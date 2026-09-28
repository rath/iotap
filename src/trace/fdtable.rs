//! Per-process descriptor tables, built from traced calls, snapshots and on-demand lookups.
//!
//! Traced calls are the most reliable source: an `open` END carries the new descriptor and
//! the looked-up path. Descriptors that existed before tracing come from a snapshot, and
//! anything still unknown is looked up the first time it is used.
//!
//! libproc describes a descriptor as it is when asked, and so does `/proc` on Linux, which
//! this module calls libproc too. That is after the traced call that made the table ask. If
//! the process closed the descriptor in between and got its number back for a new one, the
//! answer describes the new one. So an answer stays unconfirmed until the trace has been read
//! past the moment it was given. If the descriptor was closed before that moment the answer is
//! stale, and every entry that took its target from it falls back to what the trace alone says.
//! [`Verdict`]s report how each answer turned out, so that events whose target rests on one can
//! wait for it.
//!
//! An answer given after its descriptor began to close describes whatever held the number at
//! that moment. That can still be the same file: the descriptor on its way out, or a later one
//! opened on the same file, which the vnode in their lookups tells. Such an answer stands when
//! everything that may have held the number then refers to that file.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use super::call::{Completed, Lookup, NewFd, PathForm, Role};
use super::procs::{Described, ProcSource};
use crate::model::{Endpoint, FdType, Proto, Provenance, Target};

/// The `close_range` flag that only marks the descriptors close-on-exec, on Linux.
const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
/// The longest working directory kept: `PATH_MAX` on Linux, the larger of the two systems. The
/// trace joins each `chdir` to the directory before it without following `..`, so a program
/// that enters a directory and leaves it again, once for each of many, would make it grow
/// without bound.
const CWD_MAX: usize = 4096;

#[derive(Clone, Debug)]
struct FdEntry {
    target: Arc<Target>,
    provenance: Provenance,
    /// Trace time of the call that created the descriptor; 0 when it was not traced.
    opened_at: u64,
    /// Trace time after which an incomplete socket endpoint may be looked up again.
    refresh_at: Option<u64>,
    /// The unconfirmed answer the target rests on.
    answer: Option<u64>,
    /// Vnode of the file the descriptor was opened on, from the open's lookup; 0 when unknown.
    vnode: u64,
}

impl FdEntry {
    fn new(target: Target, provenance: Provenance, opened_at: u64) -> Self {
        Self {
            target: Arc::new(target),
            provenance,
            opened_at,
            refresh_at: None,
            answer: None,
            vnode: 0,
        }
    }
}

#[derive(Debug, Default)]
struct ProcFds {
    fds: HashMap<i32, FdEntry>,
    cwd: Option<String>,
    /// Descriptors that could not be described, with the trace time of the attempt.
    misses: HashMap<i32, u64>,
}

/// An answer that entries rest on until the trace confirms it.
#[derive(Debug)]
struct Unconfirmed {
    /// Trace time the answer was given.
    at: u64,
    /// The descriptor libproc was asked about.
    asked: (i32, i32),
    /// Vnode of the file the asked descriptor was opened on; 0 when it is not a looked-up
    /// file.
    vnode: u64,
    /// Entries that took their target from it: the descriptor asked about and its copies.
    entries: Vec<(i32, i32)>,
    /// What the trace alone says, for when the answer turns out to be about another
    /// descriptor.
    fallback: Arc<Target>,
    fallback_provenance: Provenance,
    /// Set once the descriptor asked about began to close before the answer.
    orphan: Option<Orphan>,
}

/// What the trace shows about the number of an answer given after its descriptor began to
/// close: who may have held the number when libproc answered.
#[derive(Debug)]
struct Orphan {
    /// Something that may have held it then refers to the file the answer was taken for.
    held: bool,
    /// Whether the number's current holder, which took it before the answer, refers to that
    /// file. Settled when it leaves or when the trace passes the answer.
    current: Option<bool>,
}

/// How an answer that targets rested on turned out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The trace was read past the answer with the descriptor still open.
    Confirmed(u64),
    /// The descriptor had been closed when libproc answered; `target` is what the trace alone
    /// says instead.
    Stale {
        answer: u64,
        target: Arc<Target>,
        provenance: Provenance,
    },
}

/// What a descriptor refers to, as far as the table knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub target: Arc<Target>,
    pub provenance: Provenance,
    /// The unconfirmed answer the target rests on.
    pub answer: Option<u64>,
}

/// Descriptor tables of every traced process.
#[derive(Debug)]
pub struct FdTable {
    procs: HashMap<i32, ProcFds>,
    /// Minimum trace-time gap between two lookups of the same descriptor.
    retry_ticks: u64,
    unknown: Arc<Target>,
    unconfirmed: HashMap<u64, Unconfirmed>,
    /// Unconfirmed answers by the time they were given, oldest first.
    by_time: VecDeque<(u64, u64)>,
    /// Orphaned answers by the descriptor they were about.
    orphans: HashMap<(i32, i32), Vec<u64>>,
    next_answer: u64,
    verdicts: Vec<Verdict>,
    /// The network namespace of each process whose snapshot named one, kept after the process
    /// is detached for events that wait to be emitted.
    netns: HashMap<i32, u64>,
}

impl FdTable {
    pub fn new(retry_ticks: u64) -> Self {
        Self {
            procs: HashMap::new(),
            retry_ticks,
            unknown: Arc::new(Target::Unknown),
            unconfirmed: HashMap::new(),
            by_time: VecDeque::new(),
            orphans: HashMap::new(),
            next_answer: 1,
            verdicts: Vec::new(),
            netns: HashMap::new(),
        }
    }

    /// Loads the current descriptor table of `pid`. Entries learned from traced calls survive
    /// when the snapshot agrees or only lacks the name of a file that was since unlinked.
    /// Returns false when the process is gone.
    pub fn attach(&mut self, pid: i32, src: &mut dyn ProcSource) -> bool {
        let Some(snapshot) = src.snapshot(pid) else {
            return false;
        };
        // A new snapshot follows calls the trace did not show, such as the closes of an exec or
        // records the kernel dropped, so the trace can no longer vouch for pending answers.
        self.drop_answers(pid);
        let mut old = self.procs.remove(&pid).unwrap_or_default();
        let mut fds = HashMap::with_capacity(snapshot.fds.len());
        for (fd, target) in snapshot.fds {
            let entry = match old.fds.remove(&fd) {
                Some(prev) if keeps(&prev, &target) => prev,
                prev => {
                    if let Some(prev) = &prev {
                        self.retire(pid, fd, prev, None);
                    }
                    FdEntry {
                        refresh_at: needs_refresh(&target).then_some(0),
                        ..FdEntry::new(target, Provenance::Snapshot, 0)
                    }
                }
            };
            fds.insert(fd, entry);
        }
        for (fd, entry) in &old.fds {
            self.retire(pid, *fd, entry, None);
        }
        match snapshot.netns {
            Some(netns) => self.netns.insert(pid, netns),
            None => self.netns.remove(&pid),
        };
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
        if let Some(proc_fds) = self.procs.remove(&pid) {
            for (fd, entry) in &proc_fds.fds {
                self.retire(pid, *fd, entry, None);
            }
        }
    }

    pub fn is_attached(&self, pid: i32) -> bool {
        self.procs.contains_key(&pid)
    }

    /// The network namespace of `pid`, when its latest snapshot named one.
    pub fn netns(&self, pid: i32) -> Option<u64> {
        self.netns.get(&pid).copied()
    }

    /// Gives `child`, which `parent` has just started, a copy of its parent's descriptors and
    /// working directory. A copy refers to the same open file as the original, so the answer an
    /// original waits on settles its copy too. Descriptors of a parent the table does not know
    /// are looked up when the child uses them.
    pub fn fork(&mut self, parent: i32, child: i32) {
        // Whatever an earlier process with the child's pid left behind.
        self.detach(child);
        match self.netns.get(&parent).copied() {
            Some(netns) => self.netns.insert(child, netns),
            None => self.netns.remove(&child),
        };
        let Some(from) = self.procs.get(&parent) else {
            return;
        };
        let fds = from.fds.clone();
        let cwd = from.cwd.clone();
        for (&fd, entry) in &fds {
            if let Some(answer) = entry.answer
                && let Some(unconfirmed) = self.unconfirmed.get_mut(&answer)
            {
                unconfirmed.entries.push((child, fd));
            }
        }
        let copy = ProcFds {
            fds,
            cwd,
            misses: HashMap::new(),
        };
        self.procs.insert(child, copy);
    }

    /// Target of `fd` at trace time `ts`, looking it up if the table does not know it.
    pub fn target(&mut self, pid: i32, fd: i32, ts: u64, src: &mut dyn ProcSource) -> Found {
        let due = self
            .entry(pid, fd)
            .map(|entry| entry.answer.is_none() && entry.refresh_at.is_some_and(|at| ts >= at));
        match due {
            None => return self.look_up(pid, fd, ts, src),
            Some(true) => {
                let described = src.describe(pid, fd);
                self.refresh(pid, fd, described, ts);
            }
            Some(false) => {}
        }
        match self.entry(pid, fd) {
            Some(entry) => Found {
                target: entry.target.clone(),
                provenance: entry.provenance,
                answer: entry.answer,
            },
            None => self.unknown_found(),
        }
    }

    /// Confirms the answers given before trace time `ts`: the trace up to then has been read,
    /// and it did not close their descriptors.
    pub fn advance(&mut self, ts: u64) {
        while let Some(&(at, answer)) = self.by_time.front() {
            if at >= ts {
                break;
            }
            self.by_time.pop_front();
            let Some(unconfirmed) = self.unconfirmed.get(&answer) else {
                continue;
            };
            let stands = unconfirmed
                .orphan
                .as_ref()
                .is_none_or(|orphan| match orphan.current {
                    Some(same) => same,
                    None => orphan.held,
                });
            if stands {
                self.confirm(answer);
            } else {
                self.stale(answer);
            }
        }
    }

    /// Verdicts reached since the last call.
    pub fn take_verdicts(&mut self) -> Vec<Verdict> {
        std::mem::take(&mut self.verdicts)
    }

    /// Applies a call that creates, copies or closes descriptors, or changes directory.
    pub fn apply(&mut self, done: &Completed, src: &mut dyn ProcSource) {
        let connecting = done.call.role == Role::Connect && done.errno == libc::EINPROGRESS;
        // A close reports an error of its file's own after the descriptor is gone; only one
        // that was refused (EPERM: a guarded descriptor) or not open (EBADF) closed nothing.
        let closing = done.call.role == Role::Close && !matches!(done.errno, libc::EPERM | libc::EBADF);
        if !done.is_ok() && !connecting && !closing {
            return;
        }
        let (pid, ts) = (done.pid, done.end_ts);
        // When the call began: a descriptor it closes or replaces was gone by its end at the
        // latest, and possibly from its start.
        let since = done.start_ts().unwrap_or(ts);
        match done.call.role {
            Role::Io { .. } => {}
            Role::Open { dirfd_arg } => {
                let fd = done.ret_i32();
                match &done.lookup {
                    Some(lookup) => {
                        let dirfd = dirfd_arg.and_then(|i| done.arg_i32(i));
                        self.open(pid, fd, dirfd, lookup, (ts, since), src);
                    }
                    None => self.forget(pid, fd, (since, ts)),
                }
            }
            Role::Close => {
                if let (Some(fd), Some(start)) = (done.arg_i32(0), done.start_ts()) {
                    self.close(pid, fd, (start, ts));
                }
            }
            Role::Dup | Role::Dup2 => {
                if let Some(old) = done.arg_i32(0) {
                    self.copy(pid, old, done.ret_i32(), (ts, since), src);
                }
            }
            Role::Fcntl => {
                if matches!(done.arg_i32(1), Some(libc::F_DUPFD | libc::F_DUPFD_CLOEXEC))
                    && let Some(old) = done.arg_i32(0)
                {
                    self.copy(pid, old, done.ret_i32(), (ts, since), src);
                }
            }
            Role::Socket => {
                let proto = socket_proto(done);
                let fd = done.ret_i32();
                let entry = FdEntry {
                    refresh_at: Some(0),
                    ..FdEntry::new(
                        Target::Socket(Endpoint::unresolved(proto)),
                        Provenance::Traced,
                        ts,
                    )
                };
                self.insert(pid, fd, entry, since);
            }
            Role::SocketPair => {
                // Neither end has an address to learn later.
                let socket = Target::Socket(Endpoint::unresolved(socket_proto(done)));
                self.insert_pair(pid, done.rval, &socket, (ts, since));
            }
            Role::CloseRange => self.close_range(done),
            Role::Accept => self.accept(pid, done, src),
            Role::Connect => {
                if let Some(fd) = done.arg_i32(0) {
                    let path = done.lookup.as_ref().map(|lookup| self.guess(pid, None, lookup));
                    self.connect(pid, fd, (path.as_deref(), done.remote), ts, src);
                }
            }
            Role::Pipe => {
                let pipe = Target::Other {
                    fd_type: FdType::Pipe,
                };
                self.insert_pair(pid, done.rval, &pipe, (ts, since));
            }
            Role::NewFd(kind) => {
                let fd = done.ret_i32();
                let fd_type = match kind {
                    NewFd::Kqueue => FdType::Kqueue,
                    NewFd::Pshm => FdType::Pshm,
                    NewFd::Necp => FdType::Netpolicy,
                    NewFd::Unknown => return self.forget(pid, fd, (since, ts)),
                };
                let entry = FdEntry::new(Target::Other { fd_type }, Provenance::Traced, ts);
                self.insert(pid, fd, entry, since);
            }
            Role::Chdir => {
                if let Some(lookup) = &done.lookup {
                    // Past the limit it is not a directory anyone is in, so nothing is known.
                    let cwd = Some(self.guess(pid, None, lookup)).filter(|cwd| cwd.len() <= CWD_MAX);
                    self.procs.entry(pid).or_default().cwd = cwd;
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

    fn entry(&self, pid: i32, fd: i32) -> Option<&FdEntry> {
        self.procs.get(&pid)?.fds.get(&fd)
    }

    fn entry_mut(&mut self, pid: i32, fd: i32) -> Option<&mut FdEntry> {
        self.procs.get_mut(&pid)?.fds.get_mut(&fd)
    }

    fn unknown_found(&self) -> Found {
        Found {
            target: self.unknown.clone(),
            provenance: Provenance::None,
            answer: None,
        }
    }

    /// Asks libproc about a descriptor the table does not know.
    fn look_up(&mut self, pid: i32, fd: i32, ts: u64, src: &mut dyn ProcSource) -> Found {
        let retry = self.retry_ticks;
        let missed = self
            .procs
            .get(&pid)
            .and_then(|p| p.misses.get(&fd))
            .is_some_and(|&at| ts < at.saturating_add(retry));
        if missed {
            return self.unknown_found();
        }
        // Something the trace did not show created it, at some point before now.
        self.holder_arrives((pid, fd), (0, ts), 0);
        let described = src.describe(pid, fd);
        let Some(target) = described.target else {
            self.procs.entry(pid).or_default().misses.insert(fd, ts);
            return self.unknown_found();
        };
        let entry = FdEntry {
            refresh_at: needs_refresh(&target).then(|| ts.saturating_add(retry)),
            ..FdEntry::new(target, Provenance::Lazy, 0)
        };
        let found = Found {
            target: entry.target.clone(),
            provenance: entry.provenance,
            answer: None,
        };
        self.procs.entry(pid).or_default().fds.insert(fd, entry);
        let fallback = (self.unknown.clone(), Provenance::None);
        let answer = self.rest_on(pid, fd, described.at, ts, fallback);
        Found { answer, ..found }
    }

    /// Takes a new answer about a socket whose endpoint was incomplete.
    fn refresh(&mut self, pid: i32, fd: i32, described: Described, ts: u64) {
        let retry_at = ts.saturating_add(self.retry_ticks);
        let Some(entry) = self.entry_mut(pid, fd) else {
            return;
        };
        let endpoint = match described.target {
            Some(Target::Socket(endpoint)) if same_kind(&entry.target, &endpoint) => endpoint,
            _ => {
                entry.refresh_at = Some(retry_at);
                return;
            }
        };
        let target = Target::Socket(endpoint);
        entry.refresh_at = needs_refresh(&target).then_some(retry_at);
        if *entry.target == target {
            return;
        }
        let fallback = (
            std::mem::replace(&mut entry.target, Arc::new(target)),
            entry.provenance,
        );
        self.rest_on(pid, fd, described.at, ts, fallback);
    }

    /// Makes the entry of `pid`/`fd` rest on an answer given at `at` in place of `fallback`,
    /// unless the trace at `ts` is already past the answer. Returns the answer's number.
    fn rest_on(
        &mut self,
        pid: i32,
        fd: i32,
        at: u64,
        ts: u64,
        fallback: (Arc<Target>, Provenance),
    ) -> Option<u64> {
        if at <= ts {
            return None;
        }
        let answer = self.next_answer;
        self.next_answer += 1;
        self.unconfirmed.insert(
            answer,
            Unconfirmed {
                at,
                asked: (pid, fd),
                vnode: self.entry(pid, fd).map_or(0, |entry| entry.vnode),
                entries: vec![(pid, fd)],
                fallback: fallback.0,
                fallback_provenance: fallback.1,
                orphan: None,
            },
        );
        self.by_time.push_back((at, answer));
        if let Some(entry) = self.entry_mut(pid, fd) {
            entry.answer = Some(answer);
        }
        Some(answer)
    }

    /// Settles what the answer `entry` rested on learns from its leaving the table. `closed`
    /// spans the call that closed or replaced its descriptor, when the trace shows one. Only the
    /// descriptor libproc was asked about matters; a copy leaving just stops using the answer.
    fn retire(&mut self, pid: i32, fd: i32, entry: &FdEntry, closed: Option<(u64, u64)>) {
        let Some(answer) = entry.answer else {
            return;
        };
        let Some(unconfirmed) = self.unconfirmed.get_mut(&answer) else {
            return;
        };
        unconfirmed.entries.retain(|&e| e != (pid, fd));
        let Some((start, end)) = closed.filter(|_| unconfirmed.asked == (pid, fd)) else {
            return;
        };
        if unconfirmed.at <= start {
            return;
        }
        // It began to close before libproc answered, so the answer is about whatever held the
        // number then: this descriptor only if its close had not yet finished.
        let held = end >= unconfirmed.at;
        if held || unconfirmed.vnode != 0 {
            unconfirmed.orphan = Some(Orphan { held, current: None });
            self.orphans.entry((pid, fd)).or_default().push(answer);
        } else {
            self.stale(answer);
        }
    }

    /// Notes a descriptor taking the number `slot` in a call that ran from `start` to `end`,
    /// opened on `vnode`, or 0 when it is not a known file.
    fn holder_arrives(&mut self, slot: (i32, i32), (start, end): (u64, u64), vnode: u64) {
        // A holder the trace did not show leaving was gone by the end of this call.
        self.holder_leaves(slot, end, false);
        for answer in self.orphans.get(&slot).cloned().unwrap_or_default() {
            if let Some(unconfirmed) = self.unconfirmed.get_mut(&answer)
                && let Some(orphan) = unconfirmed.orphan.as_mut()
                && start < unconfirmed.at
            {
                orphan.current = Some(vnode != 0 && vnode == unconfirmed.vnode);
            }
        }
    }

    /// Notes the holder of the number `slot` leaving it in a call that ended at `end`.
    /// `unknown` says the table had no entry for it, so nothing is known about what it was.
    fn holder_leaves(&mut self, slot: (i32, i32), end: u64, unknown: bool) {
        let mut stale = Vec::new();
        for answer in self.orphans.get(&slot).cloned().unwrap_or_default() {
            let Some(unconfirmed) = self.unconfirmed.get_mut(&answer) else {
                continue;
            };
            let Some(orphan) = unconfirmed.orphan.as_mut() else {
                continue;
            };
            let leaving = orphan.current.take().or(unknown.then_some(false));
            match leaving {
                // Gone before libproc answered, so not what it described.
                Some(_) if end < unconfirmed.at => {}
                Some(true) => orphan.held = true,
                Some(false) => stale.push(answer),
                None => {}
            }
        }
        for answer in stale {
            self.stale(answer);
        }
    }

    /// Declares every pending answer about `pid` stale.
    fn drop_answers(&mut self, pid: i32) {
        let mut pending: Vec<u64> = self
            .unconfirmed
            .iter()
            .filter(|(_, unconfirmed)| unconfirmed.asked.0 == pid)
            .map(|(&answer, _)| answer)
            .collect();
        pending.sort_unstable();
        for answer in pending {
            self.stale(answer);
        }
    }

    /// The entries resting on `answer` keep their targets.
    fn confirm(&mut self, answer: u64) {
        let Some(unconfirmed) = self.take(answer) else {
            return;
        };
        for (pid, fd) in unconfirmed.entries {
            if let Some(entry) = self.entry_mut(pid, fd)
                && entry.answer == Some(answer)
            {
                entry.answer = None;
            }
        }
        self.verdicts.push(Verdict::Confirmed(answer));
    }

    /// The entries resting on `answer` fall back to what the trace alone says.
    fn stale(&mut self, answer: u64) {
        let Some(unconfirmed) = self.take(answer) else {
            return;
        };
        for (pid, fd) in unconfirmed.entries {
            if let Some(entry) = self.entry_mut(pid, fd)
                && entry.answer == Some(answer)
            {
                entry.target = unconfirmed.fallback.clone();
                entry.provenance = unconfirmed.fallback_provenance;
                entry.answer = None;
            }
        }
        self.verdicts.push(Verdict::Stale {
            answer,
            target: unconfirmed.fallback,
            provenance: unconfirmed.fallback_provenance,
        });
    }

    /// Removes `answer` from those still pending.
    fn take(&mut self, answer: u64) -> Option<Unconfirmed> {
        let unconfirmed = self.unconfirmed.remove(&answer)?;
        if unconfirmed.orphan.is_some()
            && let Some(waiting) = self.orphans.get_mut(&unconfirmed.asked)
        {
            waiting.retain(|&other| other != answer);
            if waiting.is_empty() {
                self.orphans.remove(&unconfirmed.asked);
            }
        }
        Some(unconfirmed)
    }

    /// Puts `entry` in the table for a descriptor created by a call that began at trace time
    /// `since` and ended at the entry's `opened_at`.
    fn insert(&mut self, pid: i32, fd: i32, entry: FdEntry, since: u64) {
        let (call, vnode) = ((since, entry.opened_at.max(since)), entry.vnode);
        let proc_fds = self.procs.entry(pid).or_default();
        proc_fds.misses.remove(&fd);
        if let Some(old) = proc_fds.fds.insert(fd, entry) {
            self.retire(pid, fd, &old, Some(call));
            self.holder_leaves((pid, fd), call.1, false);
        }
        self.holder_arrives((pid, fd), call, vnode);
    }

    /// Drops what is known about `fd`, which a call running over `call` replaced with something
    /// unknown, so its next use looks it up afresh.
    fn forget(&mut self, pid: i32, fd: i32, call: (u64, u64)) {
        if let Some(proc_fds) = self.procs.get_mut(&pid) {
            proc_fds.misses.remove(&fd);
            if let Some(old) = proc_fds.fds.remove(&fd) {
                self.retire(pid, fd, &old, Some(call));
                self.holder_leaves((pid, fd), call.1, false);
            }
        }
        self.holder_arrives((pid, fd), call, 0);
    }

    /// Applies a close that ran over `call`.
    fn close(&mut self, pid: i32, fd: i32, call: (u64, u64)) {
        let Some(proc_fds) = self.procs.get_mut(&pid) else {
            return;
        };
        proc_fds.misses.remove(&fd);
        // Another thread may have been handed the same number after this close released it
        // but before this close returned; that newer descriptor stays.
        match proc_fds.fds.get(&fd).map(|entry| entry.opened_at < call.0) {
            Some(true) => {
                if let Some(old) = proc_fds.fds.remove(&fd) {
                    self.retire(pid, fd, &old, Some(call));
                    self.holder_leaves((pid, fd), call.1, false);
                }
            }
            Some(false) => {}
            // Closing a descriptor the table did not know: something unseen held the number.
            None => self.holder_leaves((pid, fd), call.1, true),
        }
    }

    /// Puts the two ends of a pipe or socket pair, both `target`, in the table.
    fn insert_pair(&mut self, pid: i32, fds: [u32; 2], target: &Target, (ts, since): (u64, u64)) {
        // A pair never has one number twice. Zeros are what a call that succeeded decodes to
        // when the trace could not read the descriptors it stored, and taking them for the
        // pair would overwrite standard input; the ends are looked up when first used.
        if fds[0] == fds[1] {
            return;
        }
        for fd in fds {
            let entry = FdEntry::new(target.clone(), Provenance::Traced, ts);
            self.insert(pid, fd.cast_signed(), entry, since);
        }
    }

    /// Applies a `close_range`: it closes every descriptor numbered from its first argument to
    /// its second, unless its flags only mark them close-on-exec.
    fn close_range(&mut self, done: &Completed) {
        let (Some(first), Some(last), Some(flags), Some(start)) =
            (done.arg(0), done.arg(1), done.arg(2), done.start_ts())
        else {
            return;
        };
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            return;
        }
        let (pid, call) = (done.pid, (start, done.end_ts));
        // The arguments are C `unsigned int`s.
        let (first, last) = (first as u32, last as u32);
        let in_range = |fd: &i32| u32::try_from(*fd).is_ok_and(|fd| (first..=last).contains(&fd));
        let mut fds: Vec<i32> = self
            .orphans
            .keys()
            .filter(|(owner, _)| *owner == pid)
            .map(|&(_, fd)| fd)
            .collect();
        if let Some(proc_fds) = self.procs.get(&pid) {
            fds.extend(proc_fds.fds.keys().chain(proc_fds.misses.keys()));
        }
        fds.retain(in_range);
        fds.sort_unstable();
        fds.dedup();
        for fd in fds {
            self.close(pid, fd, call);
        }
    }

    fn copy(&mut self, pid: i32, old: i32, new: i32, (ts, since): (u64, u64), src: &mut dyn ProcSource) {
        if old == new {
            return;
        }
        let found = self.target(pid, old, ts, src);
        if *found.target == Target::Unknown {
            self.forget(pid, new, (since, ts));
            return;
        }
        // Two descriptors resting on one answer already refer to the same open file, so copying
        // one onto the other changes nothing. Replacing the entry would drop it from the
        // answer's entries, and could settle the answer on the spot, with the new entry
        // resting on it.
        if found.answer.is_some()
            && let Some(entry) = self.entry_mut(pid, new)
            && entry.answer == found.answer
        {
            entry.opened_at = ts;
            return;
        }
        let original = self.entry(pid, old);
        let entry = FdEntry {
            target: found.target,
            provenance: found.provenance,
            opened_at: ts,
            refresh_at: original.and_then(|entry| entry.refresh_at),
            answer: found.answer,
            vnode: original.map_or(0, |entry| entry.vnode),
        };
        // The copy refers to the same open file, so the answer's verdict holds for it too. It
        // joins the answer's entries before it takes its number: replacing what held the
        // number can settle the answer, and the copy must hear of it.
        if let Some(answer) = found.answer
            && let Some(unconfirmed) = self.unconfirmed.get_mut(&answer)
        {
            unconfirmed.entries.push((pid, new));
        }
        self.insert(pid, new, entry, since);
    }

    fn open(
        &mut self,
        pid: i32,
        fd: i32,
        dirfd: Option<i32>,
        lookup: &Lookup,
        (ts, since): (u64, u64),
        src: &mut dyn ProcSource,
    ) {
        let file = |path| FdEntry {
            vnode: lookup.vnode,
            ..FdEntry::new(Target::File { path }, Provenance::Traced, ts)
        };
        if lookup.is_absolute() {
            self.insert(pid, fd, file(lookup.path.clone()), since);
            return;
        }
        // A path the kernel reported relative or cut short is replaced by libproc's name for
        // the new descriptor when that ends in the same name; it cannot help once the process
        // has closed the descriptor.
        let guess = self.guess(pid, dirfd, lookup);
        let described = src.describe(pid, fd);
        match described.target {
            Some(Target::File { path }) if same_name(&path, lookup) => {
                self.insert(pid, fd, file(path), since);
                let fallback = (Arc::new(Target::File { path: guess }), Provenance::Traced);
                self.rest_on(pid, fd, described.at, ts, fallback);
            }
            _ => self.insert(pid, fd, file(guess), since),
        }
    }

    fn accept(&mut self, pid: i32, done: &Completed, src: &mut dyn ProcSource) {
        let (fd, ts) = (done.ret_i32(), done.end_ts);
        let since = done.start_ts().unwrap_or(ts);
        let retry_at = ts.saturating_add(self.retry_ticks);
        // What the trace tells: a socket like the one it was accepted on.
        let listening = match done.arg_i32(0) {
            Some(listener) => self.accepted_from(pid, listener, ts, src),
            None => Endpoint::unresolved(Proto::Other),
        };
        let traced = Target::Socket(listening);
        let described = src.describe(pid, fd);
        match described.target {
            Some(Target::Socket(endpoint)) if same_kind(&traced, &endpoint) => {
                let answered = Target::Socket(endpoint);
                let entry = FdEntry {
                    refresh_at: needs_refresh(&answered).then_some(retry_at),
                    ..FdEntry::new(answered, Provenance::Traced, ts)
                };
                self.insert(pid, fd, entry, since);
                self.rest_on(pid, fd, described.at, ts, (Arc::new(traced), Provenance::Traced));
            }
            _ => {
                let entry = FdEntry {
                    refresh_at: Some(retry_at),
                    ..FdEntry::new(traced, Provenance::Traced, ts)
                };
                self.insert(pid, fd, entry, since);
            }
        }
    }

    /// What an accepted connection is known to share with the socket it was accepted on.
    fn accepted_from(&mut self, pid: i32, listener: i32, ts: u64, src: &mut dyn ProcSource) -> Endpoint {
        match &*self.target(pid, listener, ts, src).target {
            Target::Socket(listening) => Endpoint {
                remote: None,
                ..listening.clone()
            },
            _ => Endpoint::unresolved(Proto::Other),
        }
    }

    /// Notes a connect of `fd` to the path a Unix-domain connect looked up, or to the Internet
    /// address the trace carries.
    fn connect(
        &mut self,
        pid: i32,
        fd: i32,
        (path, remote): (Option<&str>, Option<SocketAddr>),
        ts: u64,
        src: &mut dyn ProcSource,
    ) {
        let retry_at = ts.saturating_add(self.retry_ticks);
        if self.entry(pid, fd).is_none() {
            self.holder_arrives((pid, fd), (0, ts), 0);
        }
        let described = src.describe(pid, fd);
        let (known, provenance, opened_at) = match self.entry(pid, fd) {
            Some(entry) => (entry.target.clone(), entry.provenance, entry.opened_at),
            None => (
                Arc::new(Target::Socket(Endpoint::unresolved(Proto::Other))),
                Provenance::Lazy,
                0,
            ),
        };
        // Only a Unix-domain connect looks up a path: the socket file, found from the caller's
        // directory. libproc reports the address the peer was bound with instead, which can be
        // relative, and nothing once the socket is closed. The address an Internet connect
        // named outlasts the socket too, but libproc knows the local end as well.
        let traced = Arc::new(with_remote(with_unix_path(&known, path), remote));
        let answered = match described.target {
            Some(Target::Socket(endpoint)) if same_kind(&known, &endpoint) => {
                Some(with_unix_path(&Target::Socket(endpoint), path))
            }
            _ => None,
        };
        let target = answered.clone().map_or_else(|| traced.clone(), Arc::new);
        let entry = FdEntry {
            refresh_at: needs_refresh(&target).then_some(retry_at),
            target,
            provenance,
            opened_at,
            answer: None,
            vnode: 0,
        };
        let replaced = self.procs.entry(pid).or_default().fds.insert(fd, entry);
        if let Some(old) = replaced {
            self.retire(pid, fd, &old, None);
        }
        if answered.is_some_and(|answered| answered != *traced) {
            self.rest_on(pid, fd, described.at, ts, (traced, provenance));
        }
    }

    fn file_path(&self, pid: i32, fd: i32) -> Option<String> {
        match &*self.entry(pid, fd)?.target {
            Target::File { path } if !path.is_empty() => Some(path.clone()),
            _ => None,
        }
    }

    /// Best reading of a looked-up path without libproc. What is left of a truncated path is
    /// shown after an ellipsis. A path the kernel reported relative through one of the root
    /// directory's links is relative to the root. Any other relative path is joined to the
    /// directory it is relative to; for a kernel's report, that is right only when no link was
    /// followed.
    fn guess(&self, pid: i32, dirfd: Option<i32>, lookup: &Lookup) -> String {
        if lookup.truncated {
            format!("…{}", lookup.path)
        } else if lookup.form == PathForm::Kernel && through_root_link(&lookup.path) {
            format!("/{}", lookup.path)
        } else if lookup.is_absolute() {
            lookup.path.clone()
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

/// The protocol of a socket from the arguments of the call that created it.
fn socket_proto(done: &Completed) -> Proto {
    match (done.arg_i32(0), done.arg_i32(1), done.arg_i32(2)) {
        (Some(family), Some(sock_type), Some(protocol)) => Proto::classify(family, sock_type, protocol),
        _ => Proto::Other,
    }
}

/// Whether an entry from traced calls survives a new snapshot: the snapshot agrees, or only
/// lacks the name of a file that was unlinked since.
fn keeps(prev: &FdEntry, target: &Target) -> bool {
    prev.provenance == Provenance::Traced
        && (*prev.target == *target
            || matches!((&*prev.target, target), (Target::File { .. }, Target::File { path }) if path.is_empty()))
}

/// A socket target with the path a Unix-domain connect looked up, unless it already names an
/// absolute one. Other targets are returned as they are.
fn with_unix_path(target: &Target, path: Option<&str>) -> Target {
    match (target, path) {
        (Target::Socket(endpoint), Some(path))
            if matches!(endpoint.proto, Proto::Unix | Proto::Other)
                && !endpoint.path.as_deref().is_some_and(|p| p.starts_with('/')) =>
        {
            Target::Socket(Endpoint {
                proto: Proto::Unix,
                path: Some(path.to_owned()),
                ..endpoint.clone()
            })
        }
        _ => target.clone(),
    }
}

/// A socket target with `remote`, the Internet address a connect named, as its remote end.
/// Other targets, and any target when the trace carries no address, are returned as they are.
fn with_remote(target: Target, remote: Option<SocketAddr>) -> Target {
    match (target, remote) {
        (Target::Socket(endpoint), Some(remote))
            if endpoint.proto.has_addresses() || endpoint.proto == Proto::Other =>
        {
            Target::Socket(Endpoint {
                remote: Some(remote),
                ..endpoint
            })
        }
        (target, _) => target,
    }
}

/// Whether libproc's `endpoint` can describe the socket the trace knows as `known`: a socket
/// created as one protocol never turns into another, so a different protocol means the number
/// was reused.
fn same_kind(known: &Target, endpoint: &Endpoint) -> bool {
    match known {
        Target::Socket(traced) => traced.proto == Proto::Other || traced.proto == endpoint.proto,
        _ => true,
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

/// Whether `path` ends in the name `lookup` found. Names the macOS kernel reports compare
/// ignoring case, as its default APFS format does.
fn same_name(path: &str, lookup: &Lookup) -> bool {
    let (a, b) = (file_name(path), file_name(&lookup.path));
    !a.is_empty()
        && match lookup.form {
            PathForm::Kernel => a.eq_ignore_ascii_case(b),
            PathForm::Passed | PathForm::Abstract => a == b,
        }
}

fn file_name(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or_default()
}

fn needs_refresh(target: &Target) -> bool {
    matches!(target, Target::Socket(endpoint) if endpoint.is_incomplete())
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
    use crate::interfaces::Listing;
    use crate::trace::call::Syscall;
    use crate::trace::kdebug::codes::syscall;
    use crate::trace::procs::Snapshot;

    #[derive(Debug, Default)]
    struct Fake {
        snapshots: HashMap<i32, Snapshot>,
        live: HashMap<(i32, i32), Target>,
        describes: usize,
        /// Trace time the answers are given at; 0 trusts them at once.
        answered_at: u64,
    }

    impl ProcSource for Fake {
        fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
            self.snapshots.get(&pid).cloned()
        }

        fn describe(&mut self, pid: i32, fd: i32) -> Described {
            self.describes += 1;
            Described {
                target: self.live.get(&(pid, fd)).cloned(),
                at: self.answered_at,
            }
        }

        fn interfaces(&mut self) -> Listing {
            Listing::default()
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
                vnode: 0,
                form: PathForm::Kernel,
            }),
            remote: None,
        }
    }

    fn file(path: &str) -> Target {
        Target::File { path: path.into() }
    }

    /// An `open` of `path` returning `fd`, whose lookup found `vnode`.
    fn open_of(start: u64, end: u64, path: &str, vnode: u64, fd: i64) -> Completed {
        let mut open = done(5, start, end, [0; 4], fd, &[path]);
        if let Some(lookup) = open.lookup.as_mut() {
            lookup.vnode = vnode;
        }
        open
    }

    fn close_of(start: u64, end: u64, fd: i64) -> Completed {
        done(6, start, end, [fd, 0, 0, 0], 0, &[])
    }

    /// Opens `web2` on fd 3 through a link, as `/usr/share/dict/words` is, and returns the
    /// answer its name rests on. libproc answers at trace time 100.
    fn open_web2(table: &mut FdTable, src: &mut Fake) -> u64 {
        src.answered_at = 100;
        src.live.insert((PID, 3), file("/usr/share/dict/web2"));
        table.apply(&open_of(1, 2, "web2", 0xa0, 3), src);
        let found = table.target(PID, 3, 3, src);
        assert_eq!(*found.target, file("/usr/share/dict/web2"));
        found.answer.expect("unconfirmed")
    }

    fn target_of(table: &mut FdTable, fd: i32, ts: u64, src: &mut Fake) -> (Target, Provenance) {
        let found = table.target(PID, fd, ts, src);
        ((*found.target).clone(), found.provenance)
    }

    fn tcp(remote: Option<&str>) -> Target {
        Target::Socket(Endpoint {
            remote: remote.map(|r| r.parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        })
    }

    #[test]
    fn a_child_gets_a_copy_of_its_parents_descriptors() {
        const CHILD: i32 = 43;
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let tty = Snapshot {
            fds: vec![(1, file("/dev/ttys001"))],
            cwd: Some("/work".into()),
            netns: Some(7),
        };
        src.snapshots.insert(PID, tty);
        assert!(table.attach(PID, &mut src));
        // What an earlier process with the child's pid left behind goes.
        let earlier = Snapshot {
            fds: vec![(9, file("/earlier"))],
            cwd: None,
            netns: None,
        };
        src.snapshots.insert(CHILD, earlier);
        assert!(table.attach(CHILD, &mut src));
        assert_eq!((table.netns(PID), table.netns(CHILD)), (Some(7), None));
        // The name of fd 3 rests on an answer libproc gives at 100.
        let answer = open_web2(&mut table, &mut src);
        table.fork(PID, CHILD);
        assert_eq!(table.netns(CHILD), Some(7));
        let copied = table.target(CHILD, 1, 4, &mut src);
        assert_eq!(
            (&*copied.target, copied.provenance, copied.answer),
            (&file("/dev/ttys001"), Provenance::Snapshot, None)
        );
        let web2 = table.target(CHILD, 3, 4, &mut src);
        assert_eq!(
            (&*web2.target, web2.answer),
            (&file("/usr/share/dict/web2"), Some(answer))
        );
        assert_eq!(*table.target(CHILD, 9, 4, &mut src).target, Target::Unknown);
        // The child opens a file in the directory it inherited, and closes its copy of fd 1,
        // which leaves the parent's alone.
        let child = |call: Completed| Completed { pid: CHILD, ..call };
        table.apply(&child(open_of(5, 6, "notes.txt", 0xb0, 4)), &mut src);
        table.apply(&child(close_of(7, 8, 1)), &mut src);
        assert_eq!(
            *table.target(CHILD, 4, 9, &mut src).target,
            file("/work/notes.txt")
        );
        assert_eq!(*table.target(CHILD, 1, 9, &mut src).target, Target::Unknown);
        assert_eq!(target_of(&mut table, 1, 9, &mut src).0, file("/dev/ttys001"));
        // Once the trace passes the answer, it holds for the copy too.
        table.advance(101);
        assert_eq!(table.take_verdicts(), [Verdict::Confirmed(answer)]);
        assert_eq!(table.target(CHILD, 3, 102, &mut src).answer, None);
        // A child of a process the table does not know has its descriptors looked up.
        table.fork(7, 70);
        assert!(!table.is_attached(70));
        assert_eq!(table.netns(70), None);
        // Events of a process that has exited may still wait to be emitted.
        table.detach(CHILD);
        assert_eq!(table.netns(CHILD), Some(7));
    }

    #[test]
    fn answers_given_after_a_close_are_stale() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        let (inet, stream) = (i64::from(libc::AF_INET), i64::from(libc::SOCK_STREAM));
        // By the time libproc is asked about fd 4, it names a later connection.
        src.live.insert((PID, 4), tcp(Some("10.0.0.2:443")));
        table.apply(&done(97, 1, 2, [inet, stream, 0, 0], 4, &[]), &mut src);
        table.apply(&done(98, 3, 4, [4, 0, 0, 0], 0, &[]), &mut src);
        let first = table.target(PID, 4, 5, &mut src);
        assert_eq!(*first.target, tcp(Some("10.0.0.2:443")));
        let answer = first.answer.expect("unconfirmed");
        table.apply(&done(6, 6, 7, [4, 0, 0, 0], 0, &[]), &mut src);
        assert_eq!(
            table.take_verdicts(),
            [Verdict::Stale {
                answer,
                target: Arc::new(tcp(None)),
                provenance: Provenance::Traced,
            }]
        );
        // The later connection itself: the same answer holds once the trace passes it.
        table.apply(&done(97, 8, 9, [inet, stream, 0, 0], 4, &[]), &mut src);
        table.apply(&done(98, 10, 11, [4, 0, 0, 0], 0, &[]), &mut src);
        let second = table.target(PID, 4, 12, &mut src).answer.expect("unconfirmed");
        table.advance(100);
        assert!(table.take_verdicts().is_empty(), "not yet past the answer");
        table.advance(101);
        assert_eq!(table.take_verdicts(), [Verdict::Confirmed(second)]);
        let found = table.target(PID, 4, 102, &mut src);
        assert_eq!((found.answer, &*found.target), (None, &tcp(Some("10.0.0.2:443"))));
    }

    #[test]
    fn answers_about_the_same_file_on_a_reused_number_stand() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let answer = open_web2(&mut table, &mut src);
        table.apply(&close_of(4, 5, 3), &mut src);
        // getcwd opens "." on the number and closes it again, long before libproc answers.
        table.apply(&open_of(6, 7, ".", 0xd0, 3), &mut src);
        table.apply(&close_of(8, 9, 3), &mut src);
        // Then the same file again: this is what libproc describes at 100.
        table.apply(&open_of(10, 11, "web2", 0xa0, 3), &mut src);
        assert!(
            table.take_verdicts().is_empty(),
            "undecided until the trace passes the answer"
        );
        table.advance(101);
        assert_eq!(table.take_verdicts()[0], Verdict::Confirmed(answer));
    }

    #[test]
    fn answers_about_another_file_on_a_reused_number_are_stale() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let answer = open_web2(&mut table, &mut src);
        table.apply(&close_of(4, 5, 3), &mut src);
        // Another file with the same name, still open when libproc answers.
        table.apply(&open_of(6, 7, "web2", 0xb0, 3), &mut src);
        table.advance(101);
        assert_eq!(
            table.take_verdicts()[0],
            Verdict::Stale {
                answer,
                target: Arc::new(file("web2")),
                provenance: Provenance::Traced,
            }
        );
    }

    #[test]
    fn numbers_taken_by_unknown_descriptors_make_answers_stale() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let answer = open_web2(&mut table, &mut src);
        table.apply(&close_of(4, 5, 3), &mut src);
        // An open whose lookup was not seen: the number holds something unknown.
        table.apply(&done(5, 6, 7, [0; 4], 3, &[]), &mut src);
        table.advance(101);
        assert!(matches!(table.take_verdicts()[..], [Verdict::Stale { answer: a, .. }] if a == answer));

        // One that is gone again before the answer does not matter.
        let answer = open_web2(&mut table, &mut src);
        table.apply(&close_of(4, 5, 3), &mut src);
        table.apply(&done(5, 6, 7, [0; 4], 3, &[]), &mut src);
        table.apply(&close_of(8, 9, 3), &mut src);
        table.apply(&open_of(10, 11, "web2", 0xa0, 3), &mut src);
        table.advance(101);
        assert_eq!(table.take_verdicts()[0], Verdict::Confirmed(answer));
    }

    #[test]
    fn a_descriptor_still_closing_when_libproc_answered_keeps_its_answer() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        let (inet, stream) = (i64::from(libc::AF_INET), i64::from(libc::SOCK_STREAM));
        src.live.insert((PID, 4), tcp(Some("10.0.0.2:443")));
        table.apply(&done(97, 1, 2, [inet, stream, 0, 0], 4, &[]), &mut src);
        table.apply(&done(98, 3, 4, [4, 0, 0, 0], 0, &[]), &mut src);
        let answer = table.target(PID, 4, 5, &mut src).answer.expect("unconfirmed");
        // The close began before the answer and ended after it.
        table.apply(&close_of(6, 150, 4), &mut src);
        assert!(table.take_verdicts().is_empty());
        table.advance(151);
        assert_eq!(table.take_verdicts(), [Verdict::Confirmed(answer)]);
    }

    #[test]
    fn copies_closing_leave_the_answer_to_the_original() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        src.live.insert((PID, 5), file("/later"));
        let answer = table.target(PID, 5, 1, &mut src).answer.expect("unconfirmed");
        table.apply(&done(41, 2, 3, [5, 0, 0, 0], 6, &[]), &mut src);
        table.apply(&close_of(4, 5, 6), &mut src);
        table.advance(101);
        assert_eq!(table.take_verdicts(), [Verdict::Confirmed(answer)]);
    }

    #[test]
    fn a_new_snapshot_drops_pending_answers() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        src.snapshots.insert(PID, Snapshot::default());
        let mut table = FdTable::new(1_000);
        src.live.insert((PID, 5), file("/later"));
        let answer = table.target(PID, 5, 1, &mut src).answer.expect("unconfirmed");
        assert!(table.attach(PID, &mut src));
        assert!(matches!(table.take_verdicts()[..], [Verdict::Stale { answer: a, .. }] if a == answer));
    }

    #[test]
    fn copies_share_the_verdict_of_their_answer() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        src.live.insert((PID, 5), file("/later"));
        assert!(table.target(PID, 5, 1, &mut src).answer.is_some());
        table.apply(&done(41, 2, 3, [5, 0, 0, 0], 6, &[]), &mut src);
        table.apply(&done(6, 4, 5, [5, 0, 0, 0], 0, &[]), &mut src);
        assert!(matches!(table.take_verdicts()[..], [Verdict::Stale { .. }]));
        assert_eq!(
            target_of(&mut table, 6, 6, &mut src),
            (Target::Unknown, Provenance::None),
            "the copy falls back too"
        );
    }

    #[test]
    fn a_copy_onto_a_descriptor_of_the_same_open_file_leaves_the_answer_pending() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        src.live.insert((PID, 5), file("/later"));
        let answer = table.target(PID, 5, 1, &mut src).answer.expect("unconfirmed");
        // fd 6 is a copy of fd 5, and dup2 puts it back on 5: the same open file again.
        table.apply(&done(41, 2, 3, [5, 0, 0, 0], 6, &[]), &mut src);
        table.apply(&done(90, 4, 5, [6, 5, 0, 0], 5, &[]), &mut src);
        assert_eq!(table.take_verdicts(), [], "nothing about the file changed");
        for fd in [5, 6] {
            let found = table.target(PID, fd, 6, &mut src);
            assert_eq!(
                (&*found.target, found.answer),
                (&file("/later"), Some(answer)),
                "fd {fd}"
            );
        }
        // Past the answer with both descriptors open, it holds for both.
        table.advance(101);
        assert_eq!(table.take_verdicts(), [Verdict::Confirmed(answer)]);
        for fd in [5, 6] {
            let found = table.target(PID, fd, 102, &mut src);
            assert_eq!((&*found.target, found.answer), (&file("/later"), None), "fd {fd}");
        }
    }

    #[test]
    fn a_copy_that_takes_the_number_of_its_answer_falls_back_with_the_others() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        src.live.insert((PID, 5), file("/dir/rel"));
        table.apply(&done(5, 1, 2, [0; 4], 5, &["rel"]), &mut src);
        // The name of fd 5 rests on libproc's answer at 100, and so does its copy on 6.
        table.apply(&done(41, 3, 4, [5, 0, 0, 0], 6, &[]), &mut src);
        // A call across that time gives the number to another file, which may be what libproc
        // described instead.
        table.apply(&done(5, 99, 101, [0; 4], 5, &["/abs"]), &mut src);
        assert_eq!(table.take_verdicts(), []);
        // Copying 6 onto it leaves the number to a file that is not the one described, so the
        // answer falls through, and the new copy with the old.
        table.apply(&done(90, 102, 103, [6, 5, 0, 0], 5, &[]), &mut src);
        assert!(matches!(table.take_verdicts()[..], [Verdict::Stale { .. }]));
        for fd in [5, 6] {
            let found = table.target(PID, fd, 104, &mut src);
            assert_eq!((&*found.target, found.answer), (&file("rel"), None), "fd {fd}");
        }
    }

    #[test]
    fn a_close_that_failed_still_released_its_descriptor_unless_it_was_refused() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        for fd in [3, 4, 5] {
            table.apply(&open_of(1, 2, &format!("/f{fd}"), 0, fd), &mut src);
        }
        // close returns what the file's own close reports, such as EINTR or EIO, after the
        // descriptor is gone. EPERM is a guarded descriptor, which stays, and EBADF a number
        // that was not open.
        for (fd, errno) in [(3, libc::EINTR), (4, libc::EPERM), (5, libc::EBADF)] {
            let mut close = close_of(3, 4, fd);
            close.errno = errno;
            table.apply(&close, &mut src);
        }
        assert_eq!(target_of(&mut table, 3, 5, &mut src).0, Target::Unknown);
        assert_eq!(target_of(&mut table, 4, 5, &mut src).0, file("/f4"));
        assert_eq!(target_of(&mut table, 5, 5, &mut src).0, file("/f5"));
    }

    #[test]
    fn a_different_protocol_means_the_number_was_reused() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let (inet, dgram) = (i64::from(libc::AF_INET), i64::from(libc::SOCK_DGRAM));
        table.apply(&done(97, 1, 2, [inet, dgram, 0, 0], 4, &[]), &mut src);
        src.live
            .insert((PID, 4), Target::Socket(Endpoint::unresolved(Proto::Unix)));
        assert_eq!(
            target_of(&mut table, 4, 3, &mut src).0,
            Target::Socket(Endpoint::unresolved(Proto::Udp))
        );
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
            &done(92, 7, 8, [3, i64::from(libc::F_DUPFD_CLOEXEC), 10, 0], 11, &[]),
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
                netns: None,
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
    fn a_working_directory_is_not_kept_past_the_longest_path() {
        let mut src = Fake::default();
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![],
                cwd: Some("/work".into()),
                netns: None,
            },
        );
        let mut table = FdTable::new(1_000);
        assert!(table.attach(PID, &mut src));
        // A program that enters a directory and leaves it again, for each of very many.
        for turn in 0..3_000 {
            let at = 10 * turn;
            table.apply(&done(12, at, at + 1, [0; 4], 0, &["sub"]), &mut src);
            table.apply(&done(12, at + 2, at + 3, [0; 4], 0, &[".."]), &mut src);
            let cwd = table.procs[&PID].cwd.as_ref();
            assert!(cwd.is_none_or(|cwd| cwd.len() <= CWD_MAX), "after {turn} turns");
        }
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
                netns: None,
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
            vnode: 0,
            form: PathForm::Kernel,
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

    /// `done` with its lookup in `form`.
    fn in_form(mut done: Completed, form: PathForm) -> Completed {
        if let Some(lookup) = done.lookup.as_mut() {
            lookup.form = form;
        }
        done
    }

    #[test]
    fn paths_as_passed_follow_no_macos_rules() {
        let mut src = Fake::default();
        let mut table = table_in("/home/me", &mut src);
        // With no link replacing it, `private/etc` is an ordinary relative path.
        let open = done(5, 1, 2, [0; 4], 3, &["private/etc/hosts"]);
        table.apply(&in_form(open, PathForm::Passed), &mut src);
        assert_eq!(
            target_of(&mut table, 3, 3, &mut src).0,
            file("/home/me/private/etc/hosts")
        );
        // Names that differ in case are different files.
        src.live.insert((PID, 4), file("/home/me/Notes.txt"));
        let open = done(5, 4, 5, [0; 4], 4, &["notes.txt"]);
        table.apply(&in_form(open, PathForm::Passed), &mut src);
        assert_eq!(
            target_of(&mut table, 4, 6, &mut src).0,
            file("/home/me/notes.txt")
        );
        // An abstract socket name is no path to join to a directory.
        let (af_unix, stream) = (i64::from(libc::AF_UNIX), i64::from(libc::SOCK_STREAM));
        table.apply(&done(97, 7, 8, [af_unix, stream, 0, 0], 5, &[]), &mut src);
        let connect = done(98, 9, 10, [5, 0, 0, 0], 0, &["@bus"]);
        table.apply(&in_form(connect, PathForm::Abstract), &mut src);
        assert_eq!(target_of(&mut table, 5, 11, &mut src).0, unix(Some("@bus")));
    }

    #[test]
    fn the_address_a_connect_named_outlasts_its_socket() {
        let mut src = Fake {
            answered_at: 100,
            ..Fake::default()
        };
        let mut table = FdTable::new(1_000);
        let (inet, dgram) = (i64::from(libc::AF_INET), i64::from(libc::SOCK_DGRAM));
        let dns: SocketAddr = "127.0.0.53:53".parse().unwrap();
        let udp = |local: Option<&str>| {
            Target::Socket(Endpoint {
                local: local.map(|addr| addr.parse().unwrap()),
                remote: Some(dns),
                ..Endpoint::unresolved(Proto::Udp)
            })
        };
        let connect = |fd: i64, (start, end): (u64, u64)| Completed {
            remote: Some(dns),
            ..done(98, start, end, [fd, 0, 16, 0], 0, &[])
        };
        // A query socket, closed before libproc could be asked about it.
        table.apply(&done(97, 1, 2, [inet, dgram, 0, 0], 4, &[]), &mut src);
        table.apply(&connect(4, (3, 4)), &mut src);
        assert_eq!(
            target_of(&mut table, 4, 5, &mut src),
            (udp(None), Provenance::Traced)
        );
        // Asked in time, libproc adds the local end. Should the socket turn out closed before
        // the answer, what the trace said stands.
        src.live.insert((PID, 5), udp(Some("127.0.0.1:40000")));
        table.apply(&done(97, 6, 7, [inet, dgram, 0, 0], 5, &[]), &mut src);
        table.apply(&connect(5, (8, 9)), &mut src);
        let found = table.target(PID, 5, 10, &mut src);
        assert_eq!(*found.target, udp(Some("127.0.0.1:40000")));
        let answer = found.answer.expect("unconfirmed");
        table.apply(&close_of(11, 12, 5), &mut src);
        assert_eq!(
            table.take_verdicts(),
            [Verdict::Stale {
                answer,
                target: Arc::new(udp(None)),
                provenance: Provenance::Traced,
            }]
        );
    }

    #[test]
    fn accepted_sockets_closed_early_keep_the_listener_kind() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let af_unix = i64::from(libc::AF_UNIX);
        table.apply(&done(97, 1, 2, [af_unix, 1, 0, 0], 3, &[]), &mut src);
        src.live.insert((PID, 3), unix(Some("srv.sock")));
        table.apply(&done(30, 3, 4, [3, 0, 0, 0], 4, &[]), &mut src);
        assert_eq!(
            target_of(&mut table, 4, 5, &mut src),
            (unix(Some("srv.sock")), Provenance::Traced)
        );
        // A TCP listener lends its bound address; the peer stays unknown.
        let listening = Target::Socket(Endpoint {
            local: Some("0.0.0.0:8765".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        });
        src.live.insert((PID, 5), listening.clone());
        table.apply(&done(404, 6, 7, [5, 0, 0, 0], 6, &[]), &mut src);
        assert_eq!(target_of(&mut table, 6, 8, &mut src).0, listening);
        // With an unknown listener it is still a socket.
        table.apply(&done(30, 9, 10, [9, 0, 0, 0], 7, &[]), &mut src);
        assert_eq!(target_of(&mut table, 7, 11, &mut src).0.to_string(), "socket");
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

    /// A call playing `role`, which only Linux's table has, over `span`.
    fn linux_call(role: Role, name: &'static str, span: (u64, u64), args: [i64; 4], ret: i64) -> Completed {
        Completed {
            call: Syscall {
                number: 0,
                name,
                role,
            },
            ..done(3, span.0, span.1, args, ret, &[])
        }
    }

    #[test]
    fn socket_pairs_are_sockets_with_nothing_to_learn() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        let (af_unix, stream) = (i64::from(libc::AF_UNIX), i64::from(libc::SOCK_STREAM));
        let mut pair = linux_call(Role::SocketPair, "socketpair", (1, 2), [af_unix, stream, 0, 0], 0);
        pair.rval = [7, 8];
        table.apply(&pair, &mut src);
        for fd in [7, 8] {
            assert_eq!(
                target_of(&mut table, fd, 3, &mut src),
                (unix(None), Provenance::Traced)
            );
        }
        // Not even a second later is either end looked up.
        target_of(&mut table, 7, 5_000, &mut src);
        assert_eq!(src.describes, 0);
    }

    #[test]
    fn a_pair_of_descriptors_the_trace_could_not_read_changes_nothing() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        table.apply(&open_of(1, 2, "/srv/input", 0, 0), &mut src);
        // The two ends of a pipe or socket pair are never one number: the same number twice
        // is what a call decodes to when the program could not read the descriptors it stored.
        let unread = done(42, 3, 4, [0; 4], 0, &[]);
        assert_eq!(unread.rval, [0, 0]);
        table.apply(&unread, &mut src);
        let (af_unix, stream) = (i64::from(libc::AF_UNIX), i64::from(libc::SOCK_STREAM));
        let socketpair = linux_call(Role::SocketPair, "socketpair", (5, 6), [af_unix, stream, 0, 0], 0);
        table.apply(&socketpair, &mut src);
        assert_eq!(
            target_of(&mut table, 0, 7, &mut src),
            (file("/srv/input"), Provenance::Traced)
        );
    }

    #[test]
    fn close_range_closes_what_it_spans_unless_it_only_marks_them() {
        let mut src = Fake::default();
        let mut table = FdTable::new(1_000);
        for (fd, path) in [(3, "/a"), (4, "/b"), (9, "/c")] {
            table.apply(&open_of(1, 2, path, 0, fd), &mut src);
        }
        let cloexec = i64::try_from(CLOSE_RANGE_CLOEXEC).unwrap();
        let mark = linux_call(Role::CloseRange, "close_range", (3, 4), [3, 8, cloexec, 0], 0);
        table.apply(&mark, &mut src);
        assert_eq!(target_of(&mut table, 4, 5, &mut src).0, file("/b"));
        // Up to the largest number there is.
        let everything = i64::from(u32::MAX);
        let close = linux_call(Role::CloseRange, "close_range", (6, 7), [4, everything, 0, 0], 0);
        table.apply(&close, &mut src);
        assert_eq!(target_of(&mut table, 3, 8, &mut src).0, file("/a"));
        for fd in [4, 9] {
            assert_eq!(target_of(&mut table, fd, 8, &mut src).0, Target::Unknown);
        }
    }

    #[test]
    fn snapshot_seeds_the_table_and_reattach_keeps_better_names() {
        let mut src = Fake::default();
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![(3, file("/log")), (4, file(""))],
                cwd: None,
                netns: None,
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
                netns: None,
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

    /// The sequences below come from this generator, so that a failing one can be run again.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// What is wrong with how the entries and the answers they rest on refer to each other, if
    /// anything. An entry on a settled answer would keep the events on it waiting for a verdict
    /// that has already come.
    fn answer_fault(table: &FdTable) -> Option<String> {
        for (pid, proc_fds) in &table.procs {
            for (fd, entry) in &proc_fds.fds {
                let Some(answer) = entry.answer else {
                    continue;
                };
                match table.unconfirmed.get(&answer) {
                    None => return Some(format!("fd {fd} of {pid} rests on the settled answer {answer}")),
                    Some(unconfirmed) if !unconfirmed.entries.contains(&(*pid, *fd)) => {
                        return Some(format!(
                            "answer {answer} does not list fd {fd} of {pid}, which rests on it"
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
        table.unconfirmed.iter().find_map(|(answer, unconfirmed)| {
            unconfirmed.entries.iter().find_map(|&(pid, fd)| {
                let rests = table.entry(pid, fd).and_then(|entry| entry.answer);
                (rests != Some(*answer))
                    .then(|| format!("answer {answer} lists fd {fd} of {pid}, which does not rest on it"))
            })
        })
    }

    #[test]
    fn no_sequence_of_calls_leaves_the_answers_and_their_entries_at_odds() {
        const CHILD: i32 = PID + 1;
        let inet = i64::from(libc::AF_INET);
        for seed in 1..=3_000_u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut src = Fake::default();
            let mut table = FdTable::new(50);
            let mut steps: Vec<String> = Vec::new();
            let mut now = 100_u64;
            for _ in 0..40 {
                now += 1 + rng.below(4);
                // libproc answers a little after the trace time it is asked at, or at once.
                src.answered_at = if rng.below(4) == 0 { 0 } else { now + rng.below(30) };
                let pid = if rng.below(3) == 0 { CHILD } else { PID };
                let fd = 3 + rng.below(4) as i32;
                let other = 3 + rng.below(4) as i32;
                let start = now - rng.below(3);
                for number in [fd, other] {
                    if rng.below(4) != 0 {
                        src.live
                            .insert((pid, number), file(&format!("/live/{pid}/{number}")));
                    }
                }
                let fd_arg = i64::from(fd);
                let mut call = match rng.below(12) {
                    0 => {
                        src.live.insert((pid, fd), file("/dir/rel"));
                        done(5, start, now, [0; 4], fd_arg, &["rel"])
                    }
                    1 => done(5, start, now, [0; 4], fd_arg, &["/abs"]),
                    2 => close_of(start, now, fd_arg),
                    3 => done(41, start, now, [fd_arg, 0, 0, 0], i64::from(other), &[]),
                    4 | 5 => done(
                        90,
                        start,
                        now,
                        [fd_arg, i64::from(other), 0, 0],
                        i64::from(other),
                        &[],
                    ),
                    6 => {
                        let dupfd = i64::from(libc::F_DUPFD);
                        done(92, start, now, [fd_arg, dupfd, 3, 0], i64::from(other), &[])
                    }
                    7 => done(
                        97,
                        start,
                        now,
                        [inet, i64::from(libc::SOCK_STREAM), 0, 0],
                        fd_arg,
                        &[],
                    ),
                    _ => {
                        match rng.below(6) {
                            0 => table.fork(PID, CHILD),
                            1 => table.detach(CHILD),
                            2 => {
                                let fds = vec![(fd, file("/snap"))];
                                src.snapshots.insert(
                                    pid,
                                    Snapshot {
                                        fds,
                                        cwd: None,
                                        netns: None,
                                    },
                                );
                                table.attach(pid, &mut src);
                            }
                            3 => table.advance(now),
                            _ => {
                                table.target(pid, fd, now, &mut src);
                            }
                        }
                        steps.push(format!("{now}: other step on fd {fd} of {pid}"));
                        continue;
                    }
                };
                call.pid = pid;
                steps.push(format!(
                    "{now}: {} {:?} -> {} in {start}..{now} of {pid}",
                    call.call.name,
                    call.start.map(|(_, args)| args),
                    call.rval[0].cast_signed()
                ));
                table.apply(&call, &mut src);
                if let Some(problem) = answer_fault(&table) {
                    panic!("seed {seed}: {problem} after\n{}", steps.join("\n"));
                }
            }
        }
    }

    #[test]
    fn joins_relative_paths() {
        assert_eq!(join("/a/", "./b"), "/a/b");
        assert_eq!(join("/a", "."), "/a");
        assert_eq!(join("/", "b/c"), "/b/c");
        assert_eq!(join("/a", "../b"), "/a/../b");
    }
}
