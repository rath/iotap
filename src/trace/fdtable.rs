//! Per-process descriptor tables, built from traced calls, snapshots and on-demand lookups.
//!
//! Traced calls are the most reliable source: an `open` END carries the new descriptor and
//! the looked-up path. Descriptors that existed before tracing come from a snapshot, and
//! anything still unknown is looked up the first time it is used.

use std::collections::HashMap;
use std::sync::Arc;

use super::codes::{NewFd, Role};
use super::pairing::{Completed, Lookup};
use super::procs::ProcSource;
use crate::model::{Endpoint, FdType, Proto, Provenance, Target};

const F_DUPFD: i32 = 0;
const F_DUPFD_CLOEXEC: i32 = 67;

#[derive(Clone, Debug)]
struct FdEntry {
    target: Arc<Target>,
    provenance: Provenance,
    /// Trace time of the call that created the descriptor; 0 when it was not traced.
    opened_at: u64,
    /// Trace time after which an incomplete socket endpoint may be looked up again.
    refresh_at: Option<u64>,
}

#[derive(Debug, Default)]
struct ProcFds {
    fds: HashMap<i32, FdEntry>,
    cwd: Option<String>,
    /// Descriptors that could not be described, with the trace time of the attempt.
    misses: HashMap<i32, u64>,
}

/// Descriptor tables of every traced process.
#[derive(Debug)]
pub struct FdTable {
    procs: HashMap<i32, ProcFds>,
    /// Minimum trace-time gap between two lookups of the same descriptor.
    retry_ticks: u64,
    unknown: Arc<Target>,
}

impl FdTable {
    pub fn new(retry_ticks: u64) -> Self {
        Self {
            procs: HashMap::new(),
            retry_ticks,
            unknown: Arc::new(Target::Unknown),
        }
    }

    /// Loads the current descriptor table of `pid`. Entries learned from traced calls survive
    /// when the snapshot agrees or only lacks the name of a file that was since unlinked.
    /// Returns false when the process is gone.
    pub fn attach(&mut self, pid: i32, src: &mut dyn ProcSource) -> bool {
        let Some(snapshot) = src.snapshot(pid) else {
            return false;
        };
        let old = self.procs.remove(&pid).unwrap_or_default();
        let mut fds = HashMap::with_capacity(snapshot.fds.len());
        for (fd, target) in snapshot.fds {
            let kept = old.fds.get(&fd).filter(|prev| {
                prev.provenance == Provenance::Traced
                    && (*prev.target == target
                        || matches!((&*prev.target, &target), (Target::File { .. }, Target::File { path }) if path.is_empty()))
            });
            let entry = kept.cloned().unwrap_or_else(|| FdEntry {
                refresh_at: needs_refresh(&target).then_some(0),
                target: Arc::new(target),
                provenance: Provenance::Snapshot,
                opened_at: 0,
            });
            fds.insert(fd, entry);
        }
        self.procs.insert(
            pid,
            ProcFds {
                fds,
                cwd: snapshot.cwd,
                misses: HashMap::new(),
            },
        );
        true
    }

    /// Forgets `pid`.
    pub fn detach(&mut self, pid: i32) {
        self.procs.remove(&pid);
    }

    pub fn is_attached(&self, pid: i32) -> bool {
        self.procs.contains_key(&pid)
    }

    /// Target of `fd` at trace time `ts`, looking it up if the table does not know it.
    pub fn target(
        &mut self,
        pid: i32,
        fd: i32,
        ts: u64,
        src: &mut dyn ProcSource,
    ) -> (Arc<Target>, Provenance) {
        let retry = self.retry_ticks;
        let proc_fds = self.procs.entry(pid).or_default();
        if let Some(entry) = proc_fds.fds.get_mut(&fd) {
            if entry.refresh_at.is_some_and(|at| ts >= at) {
                refresh_socket(entry, src.describe(pid, fd), ts, retry);
            }
            return (entry.target.clone(), entry.provenance);
        }
        if proc_fds
            .misses
            .get(&fd)
            .is_some_and(|&at| ts < at.saturating_add(retry))
        {
            return (self.unknown.clone(), Provenance::None);
        }
        let Some(target) = src.describe(pid, fd) else {
            proc_fds.misses.insert(fd, ts);
            return (self.unknown.clone(), Provenance::None);
        };
        let entry = FdEntry {
            refresh_at: needs_refresh(&target).then(|| ts.saturating_add(retry)),
            target: Arc::new(target),
            provenance: Provenance::Lazy,
            opened_at: 0,
        };
        let found = (entry.target.clone(), entry.provenance);
        proc_fds.fds.insert(fd, entry);
        found
    }

    /// Applies a call that creates, copies or closes descriptors, or changes directory.
    pub fn apply(&mut self, done: &Completed, src: &mut dyn ProcSource) {
        let connecting = done.call.role == Role::Connect && done.errno == libc::EINPROGRESS;
        if !done.is_ok() && !connecting {
            return;
        }
        let (pid, ts) = (done.pid, done.end_ts);
        match done.call.role {
            Role::Io { .. } => {}
            Role::Open { dirfd_arg } => {
                let fd = done.ret_i32();
                match &done.lookup {
                    Some(lookup) => {
                        let dirfd = dirfd_arg.and_then(|i| done.arg_i32(i));
                        let path = self.opened_path(pid, fd, dirfd, lookup, src);
                        self.insert(pid, fd, Target::File { path }, ts);
                    }
                    None => self.forget(pid, fd),
                }
            }
            Role::Close => {
                if let (Some(fd), Some(start)) = (done.arg_i32(0), done.start_ts()) {
                    self.close(pid, fd, start);
                }
            }
            Role::Dup | Role::Dup2 => {
                if let Some(old) = done.arg_i32(0) {
                    self.copy(pid, old, done.ret_i32(), ts, src);
                }
            }
            Role::Fcntl => {
                if matches!(done.arg_i32(1), Some(F_DUPFD | F_DUPFD_CLOEXEC))
                    && let Some(old) = done.arg_i32(0)
                {
                    self.copy(pid, old, done.ret_i32(), ts, src);
                }
            }
            Role::Socket => {
                let proto = match (done.arg_i32(0), done.arg_i32(1), done.arg_i32(2)) {
                    (Some(family), Some(sock_type), Some(protocol)) => {
                        Proto::classify(family, sock_type, protocol)
                    }
                    _ => Proto::Other,
                };
                let fd = done.ret_i32();
                self.insert(pid, fd, Target::Socket(Endpoint::unresolved(proto)), ts);
                self.schedule_refresh(pid, fd, 0);
            }
            Role::Accept => {
                let fd = done.ret_i32();
                match src.describe(pid, fd) {
                    Some(target @ Target::Socket(_)) => {
                        let refresh = needs_refresh(&target);
                        self.insert(pid, fd, target, ts);
                        if refresh {
                            self.schedule_refresh(pid, fd, ts.saturating_add(self.retry_ticks));
                        }
                    }
                    _ => self.forget(pid, fd),
                }
            }
            Role::Connect => {
                if let Some(fd) = done.arg_i32(0) {
                    let path = done.lookup.as_ref().map(|lookup| self.guess(pid, None, lookup));
                    self.connect(pid, fd, path, ts, src);
                }
            }
            Role::Pipe => {
                let pipe = || Target::Other {
                    fd_type: FdType::Pipe,
                };
                self.insert(pid, done.rval[0].cast_signed(), pipe(), ts);
                self.insert(pid, done.rval[1].cast_signed(), pipe(), ts);
            }
            Role::NewFd(kind) => {
                let fd = done.ret_i32();
                let fd_type = match kind {
                    NewFd::Kqueue => FdType::Kqueue,
                    NewFd::Pshm => FdType::Pshm,
                    NewFd::Necp => FdType::Netpolicy,
                    NewFd::Unknown => return self.forget(pid, fd),
                };
                self.insert(pid, fd, Target::Other { fd_type }, ts);
            }
            Role::Chdir => {
                if let Some(lookup) = &done.lookup {
                    let cwd = self.guess(pid, None, lookup);
                    self.procs.entry(pid).or_default().cwd = Some(cwd);
                }
            }
            Role::Fchdir => {
                let dir = done.arg_i32(0).and_then(|fd| self.file_path(pid, fd));
                if let Some(dir) = dir {
                    self.procs.entry(pid).or_default().cwd = Some(dir);
                }
            }
        }
    }

    fn insert(&mut self, pid: i32, fd: i32, target: Target, ts: u64) {
        let proc_fds = self.procs.entry(pid).or_default();
        proc_fds.misses.remove(&fd);
        proc_fds.fds.insert(
            fd,
            FdEntry {
                target: Arc::new(target),
                provenance: Provenance::Traced,
                opened_at: ts,
                refresh_at: None,
            },
        );
    }

    /// Drops what is known about `fd` so its next use looks it up afresh.
    fn forget(&mut self, pid: i32, fd: i32) {
        if let Some(proc_fds) = self.procs.get_mut(&pid) {
            proc_fds.fds.remove(&fd);
            proc_fds.misses.remove(&fd);
        }
    }

    fn close(&mut self, pid: i32, fd: i32, start_ts: u64) {
        let Some(proc_fds) = self.procs.get_mut(&pid) else {
            return;
        };
        proc_fds.misses.remove(&fd);
        // Another thread may have been handed the same number after this close released it
        // but before this close returned; that newer descriptor stays.
        if proc_fds
            .fds
            .get(&fd)
            .is_some_and(|entry| entry.opened_at < start_ts)
        {
            proc_fds.fds.remove(&fd);
        }
    }

    fn copy(&mut self, pid: i32, old: i32, new: i32, ts: u64, src: &mut dyn ProcSource) {
        if old == new {
            return;
        }
        let (target, provenance) = self.target(pid, old, ts, src);
        let proc_fds = self.procs.entry(pid).or_default();
        let refresh_at = proc_fds.fds.get(&old).and_then(|entry| entry.refresh_at);
        proc_fds.misses.remove(&new);
        if *target == Target::Unknown {
            proc_fds.fds.remove(&new);
            return;
        }
        proc_fds.fds.insert(
            new,
            FdEntry {
                target,
                provenance,
                opened_at: ts,
                refresh_at,
            },
        );
    }

    fn connect(&mut self, pid: i32, fd: i32, path: Option<String>, ts: u64, src: &mut dyn ProcSource) {
        let retry = self.retry_ticks;
        let described = src.describe(pid, fd);
        let proc_fds = self.procs.entry(pid).or_default();
        let entry = proc_fds.fds.entry(fd).or_insert_with(|| FdEntry {
            target: Arc::new(Target::Socket(Endpoint::unresolved(Proto::Other))),
            provenance: Provenance::Lazy,
            opened_at: 0,
            refresh_at: None,
        });
        refresh_socket(entry, described, ts, retry);
        // Only a Unix-domain connect looks up a path: the socket file, found from the caller's
        // directory. libproc reports the address the peer was bound with instead, which can be
        // relative, and nothing once the socket is closed.
        if let (Some(path), Target::Socket(endpoint)) = (path, &*entry.target)
            && matches!(endpoint.proto, Proto::Unix | Proto::Other)
            && !endpoint.path.as_deref().is_some_and(|p| p.starts_with('/'))
        {
            let endpoint = Endpoint {
                proto: Proto::Unix,
                path: Some(path),
                ..endpoint.clone()
            };
            entry.target = Arc::new(Target::Socket(endpoint));
            entry.refresh_at = None;
        }
    }

    fn schedule_refresh(&mut self, pid: i32, fd: i32, at: u64) {
        if let Some(entry) = self.procs.get_mut(&pid).and_then(|p| p.fds.get_mut(&fd)) {
            entry.refresh_at = Some(at);
        }
    }

    fn file_path(&self, pid: i32, fd: i32) -> Option<String> {
        match &*self.procs.get(&pid)?.fds.get(&fd)?.target {
            Target::File { path } if !path.is_empty() => Some(path.clone()),
            _ => None,
        }
    }

    /// Path of the file an open call looked up. A path the kernel reported relative or cut short
    /// is replaced by libproc's name for the new descriptor when that ends in the same name; it
    /// cannot help once the process has closed the descriptor.
    fn opened_path(
        &self,
        pid: i32,
        fd: i32,
        dirfd: Option<i32>,
        lookup: &Lookup,
        src: &mut dyn ProcSource,
    ) -> String {
        if lookup.is_absolute() {
            return lookup.path.clone();
        }
        match src.describe(pid, fd) {
            Some(Target::File { path }) if same_name(&path, &lookup.path) => path,
            _ => self.guess(pid, dirfd, lookup),
        }
    }

    /// Best reading of a looked-up path without libproc. What is left of a truncated path is
    /// shown after an ellipsis. A relative path through one of the root directory's links is
    /// relative to the root. Any other relative path is joined to the directory it is relative
    /// to when no link was followed, which is wrong after a link with a relative target.
    fn guess(&self, pid: i32, dirfd: Option<i32>, lookup: &Lookup) -> String {
        if lookup.truncated {
            format!("…{}", lookup.path)
        } else if through_root_link(&lookup.path) {
            format!("/{}", lookup.path)
        } else {
            self.absolute(pid, dirfd, &lookup.path)
        }
    }

    /// Makes a looked-up path absolute: relative paths are joined to the directory
    /// descriptor of `*at` calls or to the working directory, when those are known.
    fn absolute(&self, pid: i32, dirfd: Option<i32>, path: &str) -> String {
        if path.starts_with('/') {
            return path.to_owned();
        }
        let base = match dirfd {
            Some(fd) if fd != libc::AT_FDCWD => self.file_path(pid, fd),
            _ => self.procs.get(&pid).and_then(|p| p.cwd.clone()),
        };
        match base {
            Some(base) => join(&base, path),
            None => path.to_owned(),
        }
    }
}

/// `/etc`, `/tmp` and `/var` link to `private/etc`, `private/tmp` and `private/var`, so the
/// kernel reports a lookup through them relative to the root directory.
fn through_root_link(path: &str) -> bool {
    ["private/etc", "private/tmp", "private/var"].iter().any(|dir| {
        path.strip_prefix(dir)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Whether two paths end in the same name, ignoring case as the default APFS format does.
fn same_name(a: &str, b: &str) -> bool {
    let (a, b) = (file_name(a), file_name(b));
    !a.is_empty() && a.eq_ignore_ascii_case(b)
}

fn file_name(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or_default()
}

fn needs_refresh(target: &Target) -> bool {
    matches!(target, Target::Socket(endpoint) if endpoint.is_incomplete())
}

/// Replaces a socket entry's endpoint with a fresh lookup and schedules the next one while the
/// endpoint stays incomplete.
fn refresh_socket(entry: &mut FdEntry, described: Option<Target>, ts: u64, retry: u64) {
    match described {
        Some(target @ Target::Socket(_)) => {
            entry.refresh_at = needs_refresh(&target).then(|| ts.saturating_add(retry));
            entry.target = Arc::new(target);
        }
        _ => entry.refresh_at = Some(ts.saturating_add(retry)),
    }
}

fn join(base: &str, relative: &str) -> String {
    let mut relative = relative;
    while let Some(rest) = relative.strip_prefix("./") {
        relative = rest.trim_start_matches('/');
    }
    if relative.is_empty() || relative == "." {
        return base.to_owned();
    }
    format!("{}/{relative}", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::trace::codes::syscall;
    use crate::trace::procs::Snapshot;

    #[derive(Debug, Default)]
    struct Fake {
        snapshots: HashMap<i32, Snapshot>,
        live: HashMap<(i32, i32), Target>,
        describes: usize,
    }

    impl ProcSource for Fake {
        fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
            self.snapshots.get(&pid).cloned()
        }

        fn describe(&mut self, pid: i32, fd: i32) -> Option<Target> {
            self.describes += 1;
            self.live.get(&(pid, fd)).cloned()
        }
    }

    const PID: i32 = 42;

    fn done(number: u16, start: u64, end: u64, args: [i64; 4], ret: i64, paths: &[&str]) -> Completed {
        Completed {
            call: syscall(number).unwrap(),
            tid: 1,
            pid: PID,
            start: Some((start, args.map(i64::cast_unsigned))),
            end_ts: end,
            errno: 0,
            rval: [ret.cast_unsigned() as u32, 0],
            lookup: paths.first().map(|path| Lookup {
                path: (*path).to_owned(),
                truncated: false,
            }),
        }
    }

    fn file(path: &str) -> Target {
        Target::File { path: path.into() }
    }

    fn target_of(table: &mut FdTable, fd: i32, ts: u64, src: &mut Fake) -> (Target, Provenance) {
        let (target, provenance) = table.target(PID, fd, ts, src);
        ((*target).clone(), provenance)
    }

    #[test]
    fn open_read_close() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        table.apply(&done(5, 10, 20, [0; 4], 7, &["/etc/hosts"]), &mut src);
        assert_eq!(
            target_of(&mut table, 7, 30, &mut src),
            (file("/etc/hosts"), Provenance::Traced)
        );
        table.apply(&done(6, 40, 50, [7, 0, 0, 0], 0, &[]), &mut src);
        assert_eq!(
            target_of(&mut table, 7, 60, &mut src),
            (Target::Unknown, Provenance::None)
        );
        // The miss is cached for `retry_ticks`.
        target_of(&mut table, 7, 70, &mut src);
        assert_eq!(src.describes, 1);
        target_of(&mut table, 7, 1_100, &mut src);
        assert_eq!(src.describes, 2);
    }

    #[test]
    fn close_keeps_a_descriptor_reopened_by_another_thread() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        table.apply(&done(5, 1, 2, [0; 4], 5, &["/old"]), &mut src);
        // Thread A starts close(5) at 10; thread B gets 5 back from open at 15; A returns at 20.
        table.apply(&done(5, 12, 15, [0; 4], 5, &["/new"]), &mut src);
        table.apply(&done(6, 10, 20, [5, 0, 0, 0], 0, &[]), &mut src);
        assert_eq!(target_of(&mut table, 5, 30, &mut src).0, file("/new"));
    }

    #[test]
    fn duplicates_follow_the_source() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        table.apply(&done(5, 1, 2, [0; 4], 3, &["/a"]), &mut src);
        table.apply(&done(41, 3, 4, [3, 0, 0, 0], 8, &[]), &mut src);
        table.apply(&done(90, 5, 6, [3, 1, 0, 0], 1, &[]), &mut src);
        table.apply(
            &done(92, 7, 8, [3, i64::from(F_DUPFD_CLOEXEC), 10, 0], 11, &[]),
            &mut src,
        );
        table.apply(&done(92, 9, 10, [3, 3, 0, 0], 0, &[]), &mut src);
        for fd in [8, 1, 11] {
            assert_eq!(target_of(&mut table, fd, 20, &mut src).0, file("/a"), "fd {fd}");
        }
        assert_eq!(src.describes, 0, "F_GETFL must not create a descriptor");
    }

    #[test]
    fn relative_paths_use_cwd_and_dirfd() {
        let mut src = Fake::default();
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![],
                cwd: Some("/Users/me".into()),
            },
        );
        let mut table = FdTable::new(1_000);
        assert!(table.attach(PID, &mut src));
        table.apply(&done(5, 1, 2, [0; 4], 3, &["./notes.txt"]), &mut src);
        assert_eq!(
            target_of(&mut table, 3, 5, &mut src).0,
            file("/Users/me/notes.txt")
        );
        table.apply(&done(5, 3, 4, [0; 4], 4, &["/var/db"]), &mut src);
        table.apply(&done(463, 5, 6, [4, 0, 0, 0], 5, &["x/y.db"]), &mut src);
        assert_eq!(target_of(&mut table, 5, 7, &mut src).0, file("/var/db/x/y.db"));
        let at_fdcwd = i64::from(libc::AT_FDCWD);
        table.apply(&done(463, 7, 8, [at_fdcwd, 0, 0, 0], 6, &["z"]), &mut src);
        assert_eq!(target_of(&mut table, 6, 9, &mut src).0, file("/Users/me/z"));
        table.apply(&done(12, 9, 10, [0; 4], 0, &["sub"]), &mut src);
        table.apply(&done(5, 11, 12, [0; 4], 7, &["f"]), &mut src);
        assert_eq!(target_of(&mut table, 7, 13, &mut src).0, file("/Users/me/sub/f"));
        table.apply(&done(13, 13, 14, [4, 0, 0, 0], 0, &[]), &mut src);
        table.apply(&done(5, 15, 16, [0; 4], 8, &["g"]), &mut src);
        assert_eq!(target_of(&mut table, 8, 17, &mut src).0, file("/var/db/g"));
    }

    #[test]
    fn sockets_resolve_on_connect_and_on_first_use() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let (inet, stream) = (i64::from(libc::AF_INET), i64::from(libc::SOCK_STREAM));
        table.apply(&done(97, 1, 2, [inet, stream, 0, 0], 9, &[]), &mut src);
        let resolved = Endpoint {
            proto: Proto::Tcp,
            local: Some("10.0.0.2:5000".parse().unwrap()),
            remote: Some("1.2.3.4:443".parse().unwrap()),
            path: None,
        };
        src.live.insert((PID, 9), Target::Socket(resolved.clone()));
        let mut connect = done(98, 3, 4, [9, 0, 0, 0], 0, &[]);
        connect.errno = libc::EINPROGRESS;
        table.apply(&connect, &mut src);
        assert_eq!(
            target_of(&mut table, 9, 5, &mut src).0,
            Target::Socket(resolved.clone())
        );
        assert_eq!(src.describes, 1, "a complete endpoint is not looked up again");

        // An unconnected UDP socket is looked up on first use, then at most once per retry.
        let dgram = i64::from(libc::SOCK_DGRAM);
        table.apply(&done(97, 6, 7, [inet, dgram, 0, 0], 10, &[]), &mut src);
        assert_eq!(
            target_of(&mut table, 10, 8, &mut src).0,
            Target::Socket(Endpoint::unresolved(Proto::Udp))
        );
        assert_eq!(src.describes, 2);
        target_of(&mut table, 10, 9, &mut src);
        assert_eq!(src.describes, 2);
    }

    fn table_in(cwd: &str, src: &mut Fake) -> FdTable {
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![],
                cwd: Some(cwd.into()),
            },
        );
        let mut table = FdTable::new(1_000);
        assert!(table.attach(PID, src));
        table
    }

    fn unix(path: Option<&str>) -> Target {
        Target::Socket(Endpoint {
            path: path.map(Into::into),
            ..Endpoint::unresolved(Proto::Unix)
        })
    }

    #[test]
    fn relative_lookups_take_the_name_libproc_confirms() {
        let mut src = Fake::default();
        let mut table = table_in("/", &mut src);
        // Resources links to Versions/Current/Resources, and Current to A.
        let real = "/System/Library/Frameworks/Foo.framework/Versions/A/Resources/Info.plist";
        src.live.insert((PID, 3), file(real));
        table.apply(&done(5, 1, 2, [0; 4], 3, &["A/Resources/Info.plist"]), &mut src);
        assert_eq!(
            target_of(&mut table, 3, 3, &mut src),
            (file(real), Provenance::Traced)
        );
        src.live.insert((PID, 4), file("/Users/me/Notes.TXT"));
        table.apply(&done(5, 4, 5, [0; 4], 4, &["notes.txt"]), &mut src);
        assert_eq!(
            target_of(&mut table, 4, 6, &mut src).0,
            file("/Users/me/Notes.TXT")
        );
        // Descriptor 5 was closed and its number reused before libproc was asked.
        src.live.insert((PID, 5), file("/Users/me/other.txt"));
        table.apply(&done(5, 7, 8, [0; 4], 5, &["web2"]), &mut src);
        assert_eq!(target_of(&mut table, 5, 9, &mut src).0, file("/web2"));
        // Absolute paths are exact and need no lookup.
        let asked = src.describes;
        table.apply(&done(5, 10, 11, [0; 4], 6, &["/usr/share/dict/web2"]), &mut src);
        assert_eq!(src.describes, asked);
    }

    #[test]
    fn root_links_and_truncated_paths_need_no_libproc() {
        let mut src = Fake::default();
        let mut table = table_in("/Users/me", &mut src);
        table.apply(&done(5, 1, 2, [0; 4], 3, &["private/etc/hosts"]), &mut src);
        assert_eq!(
            target_of(&mut table, 3, 3, &mut src).0,
            file("/private/etc/hosts")
        );
        table.apply(&done(5, 4, 5, [0; 4], 4, &["private/tmpdir/x"]), &mut src);
        assert_eq!(
            target_of(&mut table, 4, 6, &mut src).0,
            file("/Users/me/private/tmpdir/x")
        );
        let mut cut = done(5, 7, 8, [0; 4], 5, &[]);
        cut.lookup = Some(Lookup {
            path: "ntainers/app/Data/cache.db".into(),
            truncated: true,
        });
        table.apply(&cut, &mut src);
        assert_eq!(
            target_of(&mut table, 5, 9, &mut src).0,
            file("…ntainers/app/Data/cache.db")
        );
        // While the descriptor is open, libproc knows the whole path.
        let whole = "/Users/me/Library/Containers/app/Data/cache.db";
        src.live.insert((PID, 6), file(whole));
        cut.rval = [6, 0];
        table.apply(&cut, &mut src);
        assert_eq!(target_of(&mut table, 6, 9, &mut src).0, file(whole));
        // A working directory entered through a root link.
        table.apply(&done(12, 10, 11, [0; 4], 0, &["private/var/folders"]), &mut src);
        table.apply(&done(5, 12, 13, [0; 4], 7, &["x"]), &mut src);
        assert_eq!(
            target_of(&mut table, 7, 14, &mut src).0,
            file("/private/var/folders/x")
        );
    }

    #[test]
    fn unix_connect_paths_are_made_absolute() {
        let mut src = Fake::default();
        let mut table = table_in("/w", &mut src);
        let (af_unix, stream) = (i64::from(libc::AF_UNIX), i64::from(libc::SOCK_STREAM));
        table.apply(&done(97, 1, 2, [af_unix, stream, 0, 0], 4, &[]), &mut src);
        // The peer was bound with a relative path, and libproc repeats it.
        src.live.insert((PID, 4), unix(Some("u.sock")));
        table.apply(&done(98, 3, 4, [4, 0, 0, 0], 0, &["u.sock"]), &mut src);
        assert_eq!(target_of(&mut table, 4, 5, &mut src).0, unix(Some("/w/u.sock")));
        assert_eq!(
            target_of(&mut table, 4, 5_000, &mut src).0,
            unix(Some("/w/u.sock")),
            "a later lookup must not bring the relative path back"
        );
        // An absolute bound path is kept.
        src.live.insert((PID, 5), unix(Some("/var/run/syslog")));
        table.apply(
            &done(98, 6, 7, [5, 0, 0, 0], 0, &["private/var/run/syslog"]),
            &mut src,
        );
        assert_eq!(
            target_of(&mut table, 5, 8, &mut src).0,
            unix(Some("/var/run/syslog"))
        );
        // libproc reports no path yet, or nothing at all for a socket never seen created.
        src.live.insert((PID, 6), unix(None));
        table.apply(&done(98, 9, 10, [6, 0, 0, 0], 0, &["/var/run/a"]), &mut src);
        assert_eq!(target_of(&mut table, 6, 11, &mut src).0, unix(Some("/var/run/a")));
        table.apply(
            &done(98, 12, 13, [7, 0, 0, 0], 0, &["private/var/run/b"]),
            &mut src,
        );
        assert_eq!(
            target_of(&mut table, 7, 14, &mut src).0,
            unix(Some("/private/var/run/b"))
        );
    }

    #[test]
    fn pipes_and_kqueues_are_typed_and_unknown_new_fds_are_forgotten() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let mut pipe = done(42, 1, 2, [0; 4], 0, &[]);
        pipe.rval = [5, 6];
        table.apply(&pipe, &mut src);
        let pipe_target = Target::Other {
            fd_type: FdType::Pipe,
        };
        assert_eq!(target_of(&mut table, 5, 3, &mut src).0, pipe_target);
        assert_eq!(target_of(&mut table, 6, 3, &mut src).0, pipe_target);
        table.apply(&done(362, 4, 5, [0; 4], 5, &[]), &mut src);
        assert_eq!(
            target_of(&mut table, 5, 6, &mut src).0,
            Target::Other {
                fd_type: FdType::Kqueue
            }
        );
        src.live.insert((PID, 6), file("/from/fileport"));
        table.apply(&done(431, 7, 8, [0; 4], 6, &[]), &mut src);
        assert_eq!(
            target_of(&mut table, 6, 9, &mut src),
            (file("/from/fileport"), Provenance::Lazy)
        );
    }

    #[test]
    fn snapshot_seeds_the_table_and_reattach_keeps_better_names() {
        let mut src = Fake::default();
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![(3, file("/log")), (4, file(""))],
                cwd: None,
            },
        );
        let mut table = FdTable::new(1_000);
        assert!(table.attach(PID, &mut src));
        assert_eq!(
            target_of(&mut table, 3, 1, &mut src),
            (file("/log"), Provenance::Snapshot)
        );
        table.apply(&done(5, 1, 2, [0; 4], 4, &["/tmp/scratch"]), &mut src);
        table.apply(&done(5, 3, 4, [0; 4], 5, &["/gone"]), &mut src);
        // After lost records: fd 4 is now unlinked and fd 5 was closed.
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![(3, file("/log")), (4, file(""))],
                cwd: None,
            },
        );
        assert!(table.attach(PID, &mut src));
        assert_eq!(
            target_of(&mut table, 4, 5, &mut src),
            (file("/tmp/scratch"), Provenance::Traced)
        );
        assert_eq!(target_of(&mut table, 5, 5, &mut src).0, Target::Unknown);
        assert!(!table.attach(7, &mut src));
    }

    #[test]
    fn failed_calls_change_nothing() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let mut open = done(5, 1, 2, [0; 4], 3, &["/nope"]);
        open.errno = libc::ENOENT;
        table.apply(&open, &mut src);
        assert_eq!(target_of(&mut table, 3, 3, &mut src).0, Target::Unknown);
    }

    #[test]
    fn joins_relative_paths() {
        assert_eq!(join("/a/", "./b"), "/a/b");
        assert_eq!(join("/a", "."), "/a");
        assert_eq!(join("/", "b/c"), "/b/c");
        assert_eq!(join("/a", "../b"), "/a/../b");
    }
}
