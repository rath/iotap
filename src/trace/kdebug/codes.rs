//! Kernel trace event IDs and the table of syscalls iotap understands.
//!
//! A debugid is `class << 24 | subclass << 16 | code << 2 | func`, where `func` marks the
//! start (1) and end (2) of an interval. BSD syscalls use class 4, subclass 0x0C, and the
//! syscall number as the code (`sys/syscall.h`).

use crate::model::Op;
use crate::trace::call::{NewFd, Role, Syscall};

pub const CLASS_FSYSTEM: u8 = 3;
pub const CLASS_BSD: u8 = 4;
pub const SUBCLASS_FSRW: u8 = 0x01;
pub const SUBCLASS_BSD_PROC: u8 = 0x01;
pub const SUBCLASS_BSD_SYSCALL: u8 = 0x0c;

/// The (class, subclass) pairs whose records the decoder reads: BSD syscalls, file-system path
/// lookups and process exits.
pub const TRACED_CLASSES: [(u8, u8); 3] = [
    (CLASS_BSD, SUBCLASS_BSD_SYSCALL),
    (CLASS_FSYSTEM, SUBCLASS_FSRW),
    (CLASS_BSD, SUBCLASS_BSD_PROC),
];

/// Path of a name lookup, spread over one or more records (`VFS_LOOKUP`).
pub const VFS_LOOKUP: u32 = 0x0301_0090;
/// A process begins to exit; arg1 is its pid (`BSD_PROC_EXIT`).
pub const BSD_PROC_EXIT: u32 = 0x0401_0004;
/// Inserted by the kernel where records were dropped because the buffer overflowed.
pub const TRACE_LOST_EVENTS: u32 = 0x0702_0008;
/// A thread was created: arg1 is its id, arg2 the pid of its process, arg3 1 for the thread of
/// the new image that exec creates. The creating thread emits it, whatever the pid filter says.
pub const TRACE_DATA_NEWTHREAD: u32 = 0x0700_0004;
/// A process ran exec; arg1 is its pid. Emitted whatever the pid filter says.
pub const TRACE_DATA_EXEC: u32 = 0x0700_0008;
/// A thread ended; arg1 is its id.
pub const TRACE_DATA_THREAD_TERMINATE: u32 = 0x0700_000c;
/// The syscalls that start processes: `fork`, `vfork` and `posix_spawn`.
pub const STARTS_PROCESSES: [u16; 3] = [2, 66, 244];
/// Prefix shared by every BSD syscall record.
pub const BSD_SYSCALL_PREFIX: u32 = 0x040c_0000;

pub const FUNC_START: u32 = 1;
pub const FUNC_END: u32 = 2;
const FUNC_MASK: u32 = 3;

/// Debugid without its start/end bits.
pub fn event_id(debugid: u32) -> u32 {
    debugid & !FUNC_MASK
}

pub fn func(debugid: u32) -> u32 {
    debugid & FUNC_MASK
}

/// Debugid of a BSD syscall record.
pub fn syscall_debugid(number: u16, func: u32) -> u32 {
    BSD_SYSCALL_PREFIX | (u32::from(number) << 2) | (func & FUNC_MASK)
}

/// Syscall number of a BSD syscall record, if it is one.
pub fn syscall_number(debugid: u32) -> Option<u16> {
    (debugid & 0xffff_0000 == BSD_SYSCALL_PREFIX).then_some(((debugid >> 2) & 0x3fff) as u16)
}

const fn io(op: Op, fd_arg: usize, len_arg: Option<usize>) -> Role {
    Role::Io { op, fd_arg, len_arg }
}

const fn open(dirfd_arg: Option<usize>) -> Role {
    Role::Open {
        dirfd_arg,
        flags_arg: None,
    }
}

/// Looks up a BSD syscall number. Returns `None` for calls iotap ignores.
pub fn syscall(number: u16) -> Option<Syscall> {
    use Op::{
        Getdirentries, Pread, Preadv, Pwrite, Pwritev, Read, Readv, Recvfrom, Recvmsg, RecvmsgX, Sendfile,
        Sendmsg, SendmsgX, Sendto, Write, Writev,
    };
    let (name, role) = match number {
        3 => ("read", io(Read, 0, Some(2))),
        4 => ("write", io(Write, 0, Some(2))),
        5 => ("open", open(None)),
        6 => ("close", Role::Close),
        12 => ("chdir", Role::Chdir),
        13 => ("fchdir", Role::Fchdir),
        27 => ("recvmsg", io(Recvmsg, 0, None)),
        28 => ("sendmsg", io(Sendmsg, 0, None)),
        29 => ("recvfrom", io(Recvfrom, 0, Some(2))),
        30 => ("accept", Role::Accept),
        41 => ("dup", Role::Dup),
        42 => ("pipe", Role::Pipe),
        90 => ("dup2", Role::Dup2),
        92 => ("fcntl", Role::Fcntl),
        97 => ("socket", Role::Socket),
        98 => ("connect", Role::Connect),
        120 => ("readv", io(Readv, 0, None)),
        121 => ("writev", io(Writev, 0, None)),
        133 => ("sendto", io(Sendto, 0, Some(2))),
        153 => ("pread", io(Pread, 0, Some(2))),
        154 => ("pwrite", io(Pwrite, 0, Some(2))),
        216 => ("open_dprotected_np", open(None)),
        218 => ("openat_dprotected_np", open(Some(0))),
        248 => ("fhopen", Role::NewFd(NewFd::Unknown)),
        266 => ("shm_open", Role::NewFd(NewFd::Pshm)),
        277 => ("open_extended", open(None)),
        337 => ("sendfile", io(Sendfile, 1, None)),
        344 => ("getdirentries64", io(Getdirentries, 0, Some(2))),
        362 => ("kqueue", Role::NewFd(NewFd::Kqueue)),
        396 => ("read_nocancel", io(Read, 0, Some(2))),
        397 => ("write_nocancel", io(Write, 0, Some(2))),
        398 => ("open_nocancel", open(None)),
        399 => ("close_nocancel", Role::Close),
        401 => ("recvmsg_nocancel", io(Recvmsg, 0, None)),
        402 => ("sendmsg_nocancel", io(Sendmsg, 0, None)),
        403 => ("recvfrom_nocancel", io(Recvfrom, 0, Some(2))),
        404 => ("accept_nocancel", Role::Accept),
        406 => ("fcntl_nocancel", Role::Fcntl),
        409 => ("connect_nocancel", Role::Connect),
        411 => ("readv_nocancel", io(Readv, 0, None)),
        412 => ("writev_nocancel", io(Writev, 0, None)),
        413 => ("sendto_nocancel", io(Sendto, 0, Some(2))),
        414 => ("pread_nocancel", io(Pread, 0, Some(2))),
        415 => ("pwrite_nocancel", io(Pwrite, 0, Some(2))),
        431 => ("fileport_makefd", Role::NewFd(NewFd::Unknown)),
        441 => ("guarded_open_np", open(None)),
        442 => ("guarded_close_np", Role::Close),
        443 => ("guarded_kqueue_np", Role::NewFd(NewFd::Kqueue)),
        447 => ("connectx", Role::Connect),
        449 => ("peeloff", Role::NewFd(NewFd::Unknown)),
        450 => ("socket_delegate", Role::Socket),
        463 => ("openat", open(Some(0))),
        464 => ("openat_nocancel", open(Some(0))),
        479 => ("openbyid_np", Role::NewFd(NewFd::Unknown)),
        480 => ("recvmsg_x", io(RecvmsgX, 0, None)),
        481 => ("sendmsg_x", io(SendmsgX, 0, None)),
        484 => ("guarded_open_dprotected_np", open(None)),
        485 => ("guarded_write_np", io(Write, 0, Some(3))),
        486 => ("guarded_pwrite_np", io(Pwrite, 0, Some(3))),
        487 => ("guarded_writev_np", io(Writev, 0, None)),
        501 => ("necp_open", Role::NewFd(NewFd::Necp)),
        522 => ("necp_session_open", Role::NewFd(NewFd::Necp)),
        540 => ("preadv", io(Preadv, 0, None)),
        541 => ("pwritev", io(Pwritev, 0, None)),
        542 => ("preadv_nocancel", io(Preadv, 0, None)),
        543 => ("pwritev_nocancel", io(Pwritev, 0, None)),
        _ => return None,
    };
    Some(Syscall { number, name, role })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debugid_layout_matches_kernel() {
        // BSC_read = 0x040C000C, BSC_pwrite = 0x040C0268 in fs_usage.
        assert_eq!(syscall_debugid(3, 0), 0x040c_000c);
        assert_eq!(syscall_debugid(154, 0), 0x040c_0268);
        assert_eq!(syscall_debugid(486, 0), 0x040c_0798);
        assert_eq!(syscall_number(0x040c_0269), Some(154));
        assert_eq!(func(0x040c_0269), FUNC_START);
        assert_eq!(syscall_number(0x0301_0090), None);
        assert_eq!(event_id(VFS_LOOKUP | FUNC_START | FUNC_END), VFS_LOOKUP);
    }

    #[test]
    fn table_covers_io_variants() {
        for number in [3, 4, 153, 154, 396, 397, 414, 415, 485, 486, 487, 540, 541] {
            assert!(
                matches!(syscall(number).map(|s| s.role), Some(Role::Io { .. })),
                "{number}"
            );
        }
        // The guarded calls take a guard after the descriptor, so the length is the fourth argument.
        assert_eq!(syscall(485).map(|s| s.role), Some(io(Op::Write, 0, Some(3))));
        assert_eq!(syscall(486).map(|s| s.role), Some(io(Op::Pwrite, 0, Some(3))));
        assert_eq!(syscall(337).map(|s| s.role), Some(io(Op::Sendfile, 1, None)));
        assert_eq!(syscall(59), None, "execve is not tracked");
    }
}
