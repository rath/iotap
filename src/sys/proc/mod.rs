//! Which processes run, what they run and were started as, and what their descriptors refer to:
//! through libproc and sysctl on macOS and `/proc` on Linux.
//!
//! The rest of iotap asks only [`list_pids`], [`info`], [`exe_path`], [`arg0`], [`cwd`], [`fds`]
//! and [`fd_target`].

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::{arg0, cwd, exe_path, fd_target, fds, info, list_pids};
#[cfg(target_os = "macos")]
pub use macos::{arg0, cwd, exe_path, fd_target, fds, info, list_pids};

/// Facts that identify a running process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub name: String,
    /// When it started, which tells it apart from a later process given the same pid: seconds
    /// and microseconds on macOS, clock ticks since boot and 0 on Linux.
    pub start: (u64, u64),
    /// Pid of its parent: the process that started it, or the one it was handed to when that
    /// one exited.
    pub parent: i32,
}

/// A `sleep` started for tests under a chosen first argument, killed when dropped.
#[cfg(test)]
pub(crate) struct Sleeper(std::process::Child);

#[cfg(test)]
impl Sleeper {
    /// Starts `sleep 10` with `command` for its first argument, and returns once that can be
    /// read: on Linux, exec lets `spawn` return a moment before the new program's arguments are
    /// in place.
    pub(crate) fn start(command: &str) -> Self {
        use std::os::unix::process::CommandExt;
        use std::time::{Duration, Instant};

        let child = std::process::Command::new("sleep")
            .arg0(command)
            .arg("10")
            .spawn()
            .expect("sleep starts");
        let sleeper = Self(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while arg0(sleeper.pid()).as_deref() != Some(command) {
            assert!(Instant::now() < deadline, "the arguments of sleep never showed");
            std::thread::sleep(Duration::from_millis(1));
        }
        sleeper
    }

    pub(crate) fn pid(&self) -> i32 {
        i32::try_from(self.0.id()).expect("a pid fits in i32")
    }
}

#[cfg(test)]
impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
