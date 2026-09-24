//! Kernel record decoding and the state that turns records into I/O events.
//!
//! Each record format has a decoder that puts its records together into what they tell: calls
//! that returned, processes that exited, records the kernel lost. Everything after that is the
//! same whatever the format.

pub mod call;
pub mod fdtable;
pub mod kdebug;
pub mod procs;

use self::call::Completed;

/// Records as a kernel trace facility delivers them, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Records {
    Kdebug(Vec<kdebug::KdBuf>),
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
