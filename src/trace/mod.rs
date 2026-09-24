//! Kernel record decoding and the state that turns records into I/O events.
//!
//! Each record format has a decoder that puts its records together into what they tell: calls
//! that returned, processes that exited, records the kernel lost. Everything after that is the
//! same whatever the format.

pub mod call;
pub mod fdtable;
pub mod kdebug;
pub mod linux;
pub mod procs;

use serde::{Deserialize, Serialize};

use self::call::Completed;

/// The system a trace comes from. It fixes the record format and the syscall numbers, and the
/// numbers the calls use for errors, address families and flags, which iotap reads as those of
/// the system it runs on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum System {
    /// macOS, through kdebug. Recordings made before iotap traced anything else say nothing
    /// and are all of this kind.
    #[default]
    Macos,
    /// Linux on 64-bit Arm, through iotap's eBPF program.
    LinuxAarch64,
    /// Linux on x86-64, through iotap's eBPF program.
    LinuxX86_64,
}

impl System {
    /// The system iotap runs on.
    #[cfg(target_os = "macos")]
    pub const HOST: Self = Self::Macos;
    /// The system iotap runs on.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub const HOST: Self = Self::LinuxAarch64;
    /// The system iotap runs on.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub const HOST: Self = Self::LinuxX86_64;

    /// Name of the operating system.
    pub fn os_name(self) -> &'static str {
        match self {
            Self::Macos => "macOS",
            Self::LinuxAarch64 | Self::LinuxX86_64 => "Linux",
        }
    }

    /// Whether the numbers in calls traced on `other` mean the same here: the operating system
    /// is the same, whatever the processor.
    pub fn same_os(self, other: Self) -> bool {
        self.os_name() == other.os_name()
    }
}

/// Records as a kernel trace facility delivers them, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Records {
    Kdebug(Vec<kdebug::KdBuf>),
    /// Records of iotap's Linux eBPF program, in time order.
    Linux(Vec<linux::Record>),
}

/// What the trace shows once records are put together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Traced {
    /// A syscall returned.
    Call(Completed),
    /// A process began to exit.
    ProcExit { pid: i32 },
    /// The kernel dropped records before this point because its buffer overflowed.
    LostEvents,
}

/// What one record adds to the trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// Trace time of the record: the trace has been read up to here.
    pub ts: u64,
    /// What the record completes, if anything.
    pub traced: Option<Traced>,
}

/// Puts the records of one format together. What it makes of a record depends only on the
/// records before it, never on the clock or the system.
pub trait Decode {
    type Record;

    /// Reads the next record; `None` for a record iotap does not use.
    fn decode(&mut self, record: &Self::Record) -> Option<Step>;

    /// Calls whose end was not seen, including those still in progress.
    fn unfinished_calls(&self) -> u64;

    /// Calls whose start was not seen, mostly calls already under way when tracing began.
    fn calls_started_before_trace(&self) -> u64;
}
