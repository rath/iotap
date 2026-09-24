//! `iotap` traces the file and network I/O of macOS processes through the kernel trace
//! facility (kdebug), the same source `fs_usage` reads.

#[cfg(not(target_os = "macos"))]
compile_error!("iotap only supports macOS");

pub mod model;
pub mod sys;
pub mod trace;
