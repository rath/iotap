//! `iotap` traces the file and network I/O of macOS processes through the kernel trace
//! facility (kdebug), the same source `fs_usage` reads.

#[cfg(not(target_os = "macos"))]
compile_error!("iotap only supports macOS");

pub mod app;
pub mod cli;
pub mod model;
pub mod output;
pub mod reader;
pub mod record;
pub mod session;
pub mod stats;
pub mod sys;
pub mod target;
pub mod trace;
