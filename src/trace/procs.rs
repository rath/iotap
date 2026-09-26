//! Where the descriptor table learns what descriptors refer to: the system when tracing live,
//! a recording when replaying.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Target;
use crate::sys::{proc, time};

/// Descriptor table, working directory and network namespace of a process at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub fds: Vec<(i32, Target)>,
    pub cwd: Option<String>,
    /// Linux only; absent from recordings made before iotap told interfaces apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns: Option<u64>,
}

/// What a descriptor referred to when the system was asked, and when that was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Described {
    /// `None` when the descriptor was not open.
    pub target: Option<Target>,
    /// Trace time just after the system answered; 0 when unknown, which trusts the answer at
    /// once.
    pub at: u64,
}

impl Described {
    /// An answer that needs no checking against the trace.
    pub fn settled(target: Option<Target>) -> Self {
        Self { target, at: 0 }
    }
}

/// Answers questions about the traced processes.
pub trait ProcSource {
    /// Descriptor table of `pid`, or `None` if the process is gone.
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot>;
    /// What `fd` of `pid` refers to now.
    fn describe(&mut self, pid: i32, fd: i32) -> Described;
}

/// Queries the running system: libproc on macOS, `/proc` on Linux.
#[derive(Debug, Default)]
pub struct Live;

impl ProcSource for Live {
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
        Some(Snapshot {
            fds: proc::fds(pid)?,
            cwd: proc::cwd(pid),
            netns: proc::netns(pid),
        })
    }

    fn describe(&mut self, pid: i32, fd: i32) -> Described {
        let target = proc::fd_target(pid, fd);
        Described {
            target,
            at: time::now_ticks(),
        }
    }
}

/// Answers from fixed tables; for tests and synthetic fixtures.
#[derive(Clone, Debug, Default)]
pub struct Fixed {
    pub snapshots: HashMap<i32, Snapshot>,
    pub targets: HashMap<(i32, i32), Target>,
    /// Trace time every answer is given at, to stand for the system lagging behind the trace.
    pub answered_at: u64,
}

impl ProcSource for Fixed {
    fn snapshot(&mut self, pid: i32) -> Option<Snapshot> {
        self.snapshots.get(&pid).cloned()
    }

    fn describe(&mut self, pid: i32, fd: i32) -> Described {
        Described {
            target: self.targets.get(&(pid, fd)).cloned(),
            at: self.answered_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::model::{FdType, Proto};

    #[test]
    fn live_snapshot_and_describe_agree() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let file = File::open("/etc/hosts").unwrap();
        // What the descriptor refers to, links resolved: `/private/etc/hosts` on macOS.
        let hosts = std::fs::canonicalize("/etc/hosts").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (read_end, write_end) = std::io::pipe().unwrap();
        let mut live = Live;
        let snap = live.snapshot(pid).unwrap();
        let find = |fd: i32| snap.fds.iter().find(|(f, _)| *f == fd).map(|(_, t)| t.clone());
        assert_eq!(
            find(file.as_raw_fd()),
            Some(Target::File {
                path: hosts.to_string_lossy().into_owned()
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
            live.describe(pid, write_end.as_raw_fd()).target,
            Some(Target::Other {
                fd_type: FdType::Pipe
            })
        );
        let before = time::now_ticks();
        let described = live.describe(pid, file.as_raw_fd());
        assert_eq!(described.target, find(file.as_raw_fd()));
        assert!(described.at >= before);
        assert_eq!(live.describe(pid, 9_999).target, None);
    }
}
