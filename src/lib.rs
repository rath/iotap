//! `iotap` traces the file and network I/O of processes: on macOS through the kernel trace
//! facility (kdebug), the same source `fs_usage` reads, and on Linux through an eBPF program of
//! its own.

#[cfg(not(any(
    target_os = "macos",
    all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64"))
)))]
compile_error!("iotap supports macOS, and Linux on aarch64 and x86-64");

pub mod app;
pub mod cli;
pub mod hosts;
pub mod model;
pub mod output;
pub mod reader;
pub mod record;
pub mod session;
pub mod stats;
pub mod sys;
pub mod target;
pub mod trace;
pub mod tui;
