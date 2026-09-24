//! Classifies raw kernel records into the few kinds of events iotap acts on.

use super::codes::{self, Syscall};
use crate::sys::kdebug::KdBuf;

/// Position of a record within an interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Start,
    End,
    /// Both bits set: a one-record interval, such as a short path lookup.
    StartEnd,
    /// Neither bit set: a point event or a continuation record.
    Point,
}

impl Phase {
    fn from_debugid(debugid: u32) -> Self {
        match codes::func(debugid) {
            codes::FUNC_START => Self::Start,
            codes::FUNC_END => Self::End,
            3 => Self::StartEnd,
            _ => Self::Point,
        }
    }

    pub fn is_start(self) -> bool {
        matches!(self, Self::Start | Self::StartEnd)
    }

    pub fn is_end(self) -> bool {
        matches!(self, Self::End | Self::StartEnd)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Syscall(Syscall),
    /// A chunk of a looked-up path.
    Lookup,
    ProcExit {
        pid: i32,
    },
    /// Records before this point were dropped.
    LostEvents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    /// Mach ticks.
    pub ts: u64,
    pub tid: u64,
    pub phase: Phase,
    pub kind: Kind,
    pub args: [u64; 4],
}

/// Returns the event a record describes, or `None` for records iotap does not use.
pub fn decode(rec: &KdBuf) -> Option<Event> {
    let phase = Phase::from_debugid(rec.debugid);
    let id = codes::event_id(rec.debugid);
    let kind = if let Some(number) = codes::syscall_number(id) {
        Kind::Syscall(codes::syscall(number)?)
    } else if id == codes::VFS_LOOKUP {
        Kind::Lookup
    } else if id == codes::BSD_PROC_EXIT {
        // The start record is emitted by the exiting process itself.
        if !phase.is_start() {
            return None;
        }
        Kind::ProcExit {
            pid: low_i32(rec.arg1),
        }
    } else if id == codes::TRACE_LOST_EVENTS {
        Kind::LostEvents
    } else {
        return None;
    };
    Some(Event {
        ts: rec.timestamp,
        tid: rec.arg5,
        phase,
        kind,
        args: [rec.arg1, rec.arg2, rec.arg3, rec.arg4],
    })
}

/// Reads a C `int` the kernel stored in a 64-bit record slot.
pub fn low_i32(value: u64) -> i32 {
    (value as u32).cast_signed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Op;
    use crate::trace::codes::{Role, syscall_debugid};

    fn rec(debugid: u32, args: [u64; 4]) -> KdBuf {
        KdBuf {
            timestamp: 100,
            arg1: args[0],
            arg2: args[1],
            arg3: args[2],
            arg4: args[3],
            arg5: 42,
            debugid,
            ..KdBuf::default()
        }
    }

    #[test]
    fn decodes_syscall_start_and_end() {
        let start = decode(&rec(syscall_debugid(3, codes::FUNC_START), [7, 0, 4096, 0])).unwrap();
        assert_eq!(start.phase, Phase::Start);
        assert_eq!(start.tid, 42);
        let Kind::Syscall(call) = start.kind else {
            panic!("{start:?}")
        };
        assert_eq!(
            call.role,
            Role::Io {
                op: Op::Read,
                fd_arg: 0,
                len_arg: Some(2)
            }
        );
        let end = decode(&rec(syscall_debugid(3, codes::FUNC_END), [0, 4096, 0, 501])).unwrap();
        assert_eq!(end.phase, Phase::End);
    }

    #[test]
    fn decodes_lookup_exit_and_loss() {
        let lookup = decode(&rec(codes::VFS_LOOKUP | 3, [1, 2, 3, 4])).unwrap();
        assert_eq!((lookup.kind, lookup.phase), (Kind::Lookup, Phase::StartEnd));
        let exit = decode(&rec(
            codes::BSD_PROC_EXIT | codes::FUNC_START,
            [u64::MAX - 1, 0, 0, 0],
        ));
        assert_eq!(exit.map(|e| e.kind), Some(Kind::ProcExit { pid: -2 }));
        assert_eq!(
            decode(&rec(codes::BSD_PROC_EXIT | codes::FUNC_END, [5, 0, 0, 0])),
            None
        );
        let lost = decode(&rec(codes::TRACE_LOST_EVENTS, [1, 0, 0, 0])).unwrap();
        assert_eq!(lost.kind, Kind::LostEvents);
    }

    #[test]
    fn ignores_other_records() {
        assert_eq!(decode(&rec(syscall_debugid(59, codes::FUNC_START), [0; 4])), None);
        assert_eq!(decode(&rec(0x0140_0004, [0; 4])), None);
        assert_eq!(low_i32(0xffff_ffff_ffff_fffe), -2);
        assert_eq!(low_i32(0x1_0000_0005), 5);
    }
}
