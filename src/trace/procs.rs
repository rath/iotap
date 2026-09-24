//! Where the descriptor table learns what descriptors refer to: libproc when tracing live,
//! a recording when replaying.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::{FdType, Target};
use crate::sys::proc as libproc;

/// Descriptor table and working directory of a process at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub fds: Vec<(i32, Target)>,
    pub cwd: Option<String>,
}

/// Answers questions about the traced processes.
pub trait ProcSource {
    /// Descriptor table of `pid`, or `None` if the process is gone.
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot>;
    /// What `fd` of `pid` refers to now, or `None` if it is not open.
    fn describe(&mut self, pid: i32, fd: i32) -> Option<Target>;
}

/// Queries the running system through libproc.
#[derive(Debug, Default)]
pub struct Live;

impl ProcSource for Live {
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
        let fds = libproc::list_fds(pid)?
            .into_iter()
            .filter_map(|(fd, fd_type)| describe_typed(pid, fd, fd_type).map(|target| (fd, target)))
            .collect();
        Some(Snapshot {
            fds,
            cwd: libproc::cwd(pid),
        })
    }

    fn describe(&mut self, pid: i32, fd: i32) -> Option<Target> {
        // Files and sockets answer directly; anything else needs the typed listing.
        if let Ok(path) = libproc::fd_path(pid, fd) {
            return Some(Target::File { path });
        }
        if let Ok(endpoint) = libproc::fd_socket(pid, fd) {
            return Some(Target::Socket(endpoint));
        }
        let (_, fd_type) = libproc::list_fds(pid)?
            .into_iter()
            .find(|&(open, _)| open == fd)?;
        describe_typed(pid, fd, fd_type)
    }
}

/// Answers from fixed tables; for tests and synthetic fixtures.
#[derive(Clone, Debug, Default)]
pub struct Fixed {
    pub snapshots: HashMap<i32, Snapshot>,
    pub targets: HashMap<(i32, i32), Target>,
}

impl ProcSource for Fixed {
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
        self.snapshots.get(&pid).cloned()
    }

    fn describe(&mut self, pid: i32, fd: i32) -> Option<Target> {
        self.targets.get(&(pid, fd)).cloned()
    }
}

fn describe_typed(pid: i32, fd: i32, fd_type: u32) -> Option<Target> {
    match i32::try_from(fd_type) {
        Ok(libc::PROX_FDTYPE_VNODE) => libproc::fd_path(pid, fd).ok().map(|path| Target::File { path }),
        Ok(libc::PROX_FDTYPE_SOCKET) => libproc::fd_socket(pid, fd).ok().map(Target::Socket),
        _ => Some(Target::Other {
            fd_type: FdType::from_prox(fd_type),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::model::Proto;

    #[test]
    fn live_snapshot_and_describe_agree() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let file = File::open("/etc/hosts").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (read_end, write_end) = std::io::pipe().unwrap();
        let mut live = Live;
        let snap = live.snapshot(pid).unwrap();
        let find = |fd: i32| snap.fds.iter().find(|(f, _)| *f == fd).map(|(_, t)| t.clone());
        assert_eq!(
            find(file.as_raw_fd()),
            Some(Target::File {
                path: "/private/etc/hosts".into()
            })
        );
        assert!(matches!(find(udp.as_raw_fd()), Some(Target::Socket(ep)) if ep.proto == Proto::Udp));
        assert_eq!(
            find(read_end.as_raw_fd()),
            Some(Target::Other {
                fd_type: FdType::Pipe
            })
        );
        assert!(snap.cwd.is_some());
        assert_eq!(
            live.describe(pid, write_end.as_raw_fd()),
            Some(Target::Other {
                fd_type: FdType::Pipe
            })
        );
        assert_eq!(live.describe(pid, file.as_raw_fd()), find(file.as_raw_fd()));
        assert_eq!(live.describe(pid, 9_999), None);
    }
}
