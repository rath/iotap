//! Which processes run, what they run, and what their descriptors refer to: through libproc on
//! macOS and `/proc` on Linux.
//!
//! The rest of iotap asks only [`list_pids`], [`info`], [`exe_path`], [`cwd`], [`fds`] and
//! [`fd_target`].

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::{cwd, exe_path, fd_target, fds, info, list_pids};
#[cfg(target_os = "macos")]
pub use macos::{cwd, exe_path, fd_target, fds, info, list_pids};

/// Facts that identify a running process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub name: String,
    /// When it started, which tells it apart from a later process given the same pid: seconds
    /// and microseconds on macOS, clock ticks since boot and 0 on Linux.
    pub start: (u64, u64),
}
