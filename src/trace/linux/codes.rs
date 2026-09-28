//! The syscalls iotap traces on Linux. Their numbers differ from one processor to another;
//! what each call does, and what the eBPF program reads for it, does not.

use crate::model::Op;
use crate::trace::System;
use crate::trace::call::{NewFd, Role, Syscall};

/// What the eBPF program reads from the caller's memory when a call returns. Argument indices
/// count from 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capture {
    Nothing,
    /// The NUL-terminated path in the argument.
    Path(u8),
    /// The socket address at argument `addr`, as long as argument `len` says.
    Sockaddr {
        addr: u8,
        len: u8,
    },
    /// The two descriptors the call stored at the address in the argument.
    Fds(u8),
}

impl Capture {
    /// The word the eBPF program's `calls` map holds for a traced call. Bit 0 traces it; each
    /// 4-bit field above holds an argument index plus one, or 0: the path in bits 4 to 7, the
    /// socket address in bits 8 to 11 and its length in bits 12 to 15, the descriptor pair in
    /// bits 16 to 19.
    pub fn flags(self) -> u32 {
        let field = |index: u8, shift: u32| (u32::from(index) + 1) << shift;
        1 | match self {
            Self::Nothing => 0,
            Self::Path(arg) => field(arg, 4),
            Self::Sockaddr { addr, len } => field(addr, 8) | field(len, 12),
            Self::Fds(arg) => field(arg, 16),
        }
    }
}

/// A traced call and what the eBPF program reads for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub syscall: Syscall,
    pub capture: Capture,
}

const fn entry(number: u16, name: &'static str, role: Role, capture: Capture) -> Entry {
    Entry {
        syscall: Syscall { number, name, role },
        capture,
    }
}

const fn call(number: u16, name: &'static str, role: Role) -> Entry {
    entry(number, name, role, Capture::Nothing)
}

const fn io(number: u16, name: &'static str, op: Op, len_arg: Option<usize>) -> Entry {
    call(
        number,
        name,
        Role::Io {
            op,
            fd_arg: 0,
            len_arg,
        },
    )
}

const fn new_fd(number: u16, name: &'static str) -> Entry {
    call(number, name, Role::NewFd(NewFd::Unknown))
}

const OPENAT: Role = Role::Open {
    dirfd_arg: Some(0),
    flags_arg: Some(2),
};
const OPEN: Role = Role::Open {
    dirfd_arg: None,
    flags_arg: Some(1),
};
/// `creat` has no flags to read: it always creates. `openat2` keeps its flags in a structure the
/// program does not read.
const CREAT: Role = Role::Open {
    dirfd_arg: None,
    flags_arg: None,
};
const OPENAT2: Role = Role::Open {
    dirfd_arg: Some(0),
    flags_arg: None,
};
const CONNECT: Capture = Capture::Sockaddr { addr: 1, len: 2 };

/// The flag `O_TMPFILE` of `system`, which makes an open create a file with no name in the
/// directory it is given. It is `O_DIRECTORY` and one flag more, and `O_DIRECTORY` differs from
/// one processor to another. `None` for a system that has no such flag.
pub const fn o_tmpfile(system: System) -> Option<u32> {
    match system {
        System::LinuxX86_64 => Some(0x41_0000),
        System::LinuxAarch64 => Some(0x40_4000),
        System::Macos => None,
    }
}

/// Linux on 64-bit Arm, which numbers its calls as `asm-generic/unistd.h` does. It has none of
/// the old calls that newer ones replaced, such as `open` and `pipe`.
pub const AARCH64: &[Entry] = &[
    new_fd(19, "eventfd2"),
    new_fd(20, "epoll_create1"),
    call(23, "dup", Role::Dup),
    call(24, "dup3", Role::Dup2),
    call(25, "fcntl", Role::Fcntl),
    new_fd(26, "inotify_init1"),
    entry(49, "chdir", Role::Chdir, Capture::Path(0)),
    call(50, "fchdir", Role::Fchdir),
    entry(56, "openat", OPENAT, Capture::Path(1)),
    call(57, "close", Role::Close),
    entry(59, "pipe2", Role::Pipe, Capture::Fds(0)),
    io(61, "getdents64", Op::Getdirentries, Some(2)),
    io(63, "read", Op::Read, Some(2)),
    io(64, "write", Op::Write, Some(2)),
    io(65, "readv", Op::Readv, None),
    io(66, "writev", Op::Writev, None),
    io(67, "pread64", Op::Pread, Some(2)),
    io(68, "pwrite64", Op::Pwrite, Some(2)),
    io(69, "preadv", Op::Preadv, None),
    io(70, "pwritev", Op::Pwritev, None),
    // Writes to its first descriptor what it reads from its second, and returns the count.
    io(71, "sendfile", Op::Write, Some(3)),
    new_fd(74, "signalfd4"),
    new_fd(85, "timerfd_create"),
    call(198, "socket", Role::Socket),
    entry(199, "socketpair", Role::SocketPair, Capture::Fds(3)),
    call(202, "accept", Role::Accept),
    entry(203, "connect", Role::Connect, CONNECT),
    io(206, "sendto", Op::Sendto, Some(2)),
    io(207, "recvfrom", Op::Recvfrom, Some(2)),
    io(211, "sendmsg", Op::Sendmsg, None),
    io(212, "recvmsg", Op::Recvmsg, None),
    new_fd(241, "perf_event_open"),
    call(242, "accept4", Role::Accept),
    io(243, "recvmmsg", Op::RecvmsgX, None),
    new_fd(262, "fanotify_init"),
    new_fd(265, "open_by_handle_at"),
    io(269, "sendmmsg", Op::SendmsgX, None),
    new_fd(279, "memfd_create"),
    new_fd(282, "userfaultfd"),
    io(286, "preadv2", Op::Preadv, None),
    io(287, "pwritev2", Op::Pwritev, None),
    new_fd(425, "io_uring_setup"),
    new_fd(434, "pidfd_open"),
    call(436, "close_range", Role::CloseRange),
    entry(437, "openat2", OPENAT2, Capture::Path(1)),
    new_fd(438, "pidfd_getfd"),
];

/// Linux on x86-64, with the old calls it keeps beside their replacements.
pub const X86_64: &[Entry] = &[
    io(0, "read", Op::Read, Some(2)),
    io(1, "write", Op::Write, Some(2)),
    entry(2, "open", OPEN, Capture::Path(0)),
    call(3, "close", Role::Close),
    io(17, "pread64", Op::Pread, Some(2)),
    io(18, "pwrite64", Op::Pwrite, Some(2)),
    io(19, "readv", Op::Readv, None),
    io(20, "writev", Op::Writev, None),
    entry(22, "pipe", Role::Pipe, Capture::Fds(0)),
    call(32, "dup", Role::Dup),
    call(33, "dup2", Role::Dup2),
    // Writes to its first descriptor what it reads from its second, and returns the count.
    io(40, "sendfile", Op::Write, Some(3)),
    call(41, "socket", Role::Socket),
    entry(42, "connect", Role::Connect, CONNECT),
    call(43, "accept", Role::Accept),
    io(44, "sendto", Op::Sendto, Some(2)),
    io(45, "recvfrom", Op::Recvfrom, Some(2)),
    io(46, "sendmsg", Op::Sendmsg, None),
    io(47, "recvmsg", Op::Recvmsg, None),
    entry(53, "socketpair", Role::SocketPair, Capture::Fds(3)),
    call(72, "fcntl", Role::Fcntl),
    io(78, "getdents", Op::Getdirentries, Some(2)),
    entry(80, "chdir", Role::Chdir, Capture::Path(0)),
    call(81, "fchdir", Role::Fchdir),
    entry(85, "creat", CREAT, Capture::Path(0)),
    new_fd(213, "epoll_create"),
    io(217, "getdents64", Op::Getdirentries, Some(2)),
    new_fd(253, "inotify_init"),
    entry(257, "openat", OPENAT, Capture::Path(1)),
    new_fd(282, "signalfd"),
    new_fd(283, "timerfd_create"),
    new_fd(284, "eventfd"),
    call(288, "accept4", Role::Accept),
    new_fd(289, "signalfd4"),
    new_fd(290, "eventfd2"),
    new_fd(291, "epoll_create1"),
    call(292, "dup3", Role::Dup2),
    entry(293, "pipe2", Role::Pipe, Capture::Fds(0)),
    new_fd(294, "inotify_init1"),
    io(295, "preadv", Op::Preadv, None),
    io(296, "pwritev", Op::Pwritev, None),
    new_fd(298, "perf_event_open"),
    io(299, "recvmmsg", Op::RecvmsgX, None),
    new_fd(300, "fanotify_init"),
    new_fd(304, "open_by_handle_at"),
    io(307, "sendmmsg", Op::SendmsgX, None),
    new_fd(319, "memfd_create"),
    new_fd(323, "userfaultfd"),
    io(327, "preadv2", Op::Preadv, None),
    io(328, "pwritev2", Op::Pwritev, None),
    new_fd(425, "io_uring_setup"),
    new_fd(434, "pidfd_open"),
    call(436, "close_range", Role::CloseRange),
    entry(437, "openat2", OPENAT2, Capture::Path(1)),
    new_fd(438, "pidfd_getfd"),
];

/// The calls traced on `system`; none on macOS, which kdebug traces.
pub fn table(system: System) -> &'static [Entry] {
    match system {
        System::Macos => &[],
        System::LinuxAarch64 => AARCH64,
        System::LinuxX86_64 => X86_64,
    }
}

/// The call `number` is on `system`, if iotap traces it.
pub fn syscall(system: System, number: u16) -> Option<Syscall> {
    table(system)
        .iter()
        .find(|entry| entry.syscall.number == number)
        .map(|entry| entry.syscall)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn numbers_and_names_are_unique() {
        for table in [AARCH64, X86_64] {
            let numbers: HashSet<u16> = table.iter().map(|e| e.syscall.number).collect();
            let names: HashSet<&str> = table.iter().map(|e| e.syscall.name).collect();
            assert_eq!((numbers.len(), names.len()), (table.len(), table.len()));
        }
    }

    #[test]
    fn the_flag_for_files_with_no_name_is_the_kernels() {
        #[cfg(target_os = "linux")]
        assert_eq!(o_tmpfile(System::HOST), Some(libc::O_TMPFILE.cast_unsigned()));
        assert_eq!(o_tmpfile(System::Macos), None);
        // What the opens that take flags say about where they are.
        let flags_arg = |table: &[Entry], name: &str| {
            let entry = table.iter().find(|entry| entry.syscall.name == name).unwrap();
            match entry.syscall.role {
                Role::Open { flags_arg, .. } => flags_arg,
                role => panic!("{name} plays {role:?}"),
            }
        };
        assert_eq!(flags_arg(AARCH64, "openat"), Some(2));
        assert_eq!(flags_arg(X86_64, "openat"), Some(2));
        assert_eq!(flags_arg(X86_64, "open"), Some(1));
        assert_eq!(flags_arg(X86_64, "creat"), None);
        assert_eq!(flags_arg(X86_64, "openat2"), None);
        assert_eq!(flags_arg(AARCH64, "openat2"), None);
    }

    #[test]
    fn numbers_fit_the_programs_map_of_calls() {
        // `calls` in bpf/iotap.bpf.c has 1024 entries.
        for table in [AARCH64, X86_64] {
            assert!(table.iter().all(|entry| entry.syscall.number < 1024));
        }
    }

    #[test]
    fn both_processors_trace_the_same_calls_but_the_old_ones() {
        let names = |table: &[Entry]| -> HashSet<&str> { table.iter().map(|e| e.syscall.name).collect() };
        let old: HashSet<&str> = [
            "open",
            "creat",
            "pipe",
            "dup2",
            "getdents",
            "epoll_create",
            "inotify_init",
            "signalfd",
            "eventfd",
        ]
        .into();
        assert_eq!(&names(X86_64) - &names(AARCH64), old);
        assert!(names(AARCH64).is_subset(&names(X86_64)));
        // The same name plays the same part and has the same arguments read on both.
        for entry in AARCH64 {
            let other = X86_64
                .iter()
                .find(|e| e.syscall.name == entry.syscall.name)
                .unwrap();
            assert_eq!(
                (other.syscall.role, other.capture),
                (entry.syscall.role, entry.capture)
            );
        }
    }

    #[test]
    fn flags_place_argument_indices_in_their_fields() {
        assert_eq!(Capture::Nothing.flags(), 1);
        assert_eq!(Capture::Path(1).flags(), 0x21);
        assert_eq!(Capture::Sockaddr { addr: 1, len: 2 }.flags(), 0x3201);
        assert_eq!(Capture::Fds(3).flags(), 0x4_0001);
    }

    #[test]
    fn looks_calls_up_by_number() {
        let openat = syscall(System::LinuxAarch64, 56).unwrap();
        assert_eq!((openat.name, openat.role), ("openat", OPENAT));
        assert_eq!(syscall(System::LinuxX86_64, 257).map(|s| s.name), Some("openat"));
        assert_eq!(syscall(System::LinuxAarch64, 221), None, "execve is not traced");
        assert_eq!(syscall(System::Macos, 3), None);
    }

    /// The host's numbers, as the C library knows them.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn host_number(name: &str) -> libc::c_long {
        match name {
            "eventfd2" => libc::SYS_eventfd2,
            "epoll_create1" => libc::SYS_epoll_create1,
            "dup" => libc::SYS_dup,
            "dup3" => libc::SYS_dup3,
            "fcntl" => libc::SYS_fcntl,
            "inotify_init1" => libc::SYS_inotify_init1,
            "chdir" => libc::SYS_chdir,
            "fchdir" => libc::SYS_fchdir,
            "openat" => libc::SYS_openat,
            "close" => libc::SYS_close,
            "pipe2" => libc::SYS_pipe2,
            "getdents64" => libc::SYS_getdents64,
            "read" => libc::SYS_read,
            "write" => libc::SYS_write,
            "readv" => libc::SYS_readv,
            "writev" => libc::SYS_writev,
            "pread64" => libc::SYS_pread64,
            "pwrite64" => libc::SYS_pwrite64,
            "preadv" => libc::SYS_preadv,
            "pwritev" => libc::SYS_pwritev,
            "sendfile" => libc::SYS_sendfile,
            "signalfd4" => libc::SYS_signalfd4,
            "timerfd_create" => libc::SYS_timerfd_create,
            "socket" => libc::SYS_socket,
            "socketpair" => libc::SYS_socketpair,
            "accept" => libc::SYS_accept,
            "connect" => libc::SYS_connect,
            "sendto" => libc::SYS_sendto,
            "recvfrom" => libc::SYS_recvfrom,
            "sendmsg" => libc::SYS_sendmsg,
            "recvmsg" => libc::SYS_recvmsg,
            "perf_event_open" => libc::SYS_perf_event_open,
            "accept4" => libc::SYS_accept4,
            "recvmmsg" => libc::SYS_recvmmsg,
            "fanotify_init" => libc::SYS_fanotify_init,
            "open_by_handle_at" => libc::SYS_open_by_handle_at,
            "sendmmsg" => libc::SYS_sendmmsg,
            "memfd_create" => libc::SYS_memfd_create,
            "userfaultfd" => libc::SYS_userfaultfd,
            "preadv2" => libc::SYS_preadv2,
            "pwritev2" => libc::SYS_pwritev2,
            "io_uring_setup" => libc::SYS_io_uring_setup,
            "pidfd_open" => libc::SYS_pidfd_open,
            "close_range" => libc::SYS_close_range,
            "openat2" => libc::SYS_openat2,
            "pidfd_getfd" => libc::SYS_pidfd_getfd,
            _ => panic!("no number for {name}"),
        }
    }

    /// The host's numbers, as the C library knows them.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn host_number(name: &str) -> libc::c_long {
        match name {
            "read" => libc::SYS_read,
            "write" => libc::SYS_write,
            "open" => libc::SYS_open,
            "close" => libc::SYS_close,
            "pread64" => libc::SYS_pread64,
            "pwrite64" => libc::SYS_pwrite64,
            "readv" => libc::SYS_readv,
            "writev" => libc::SYS_writev,
            "pipe" => libc::SYS_pipe,
            "dup" => libc::SYS_dup,
            "dup2" => libc::SYS_dup2,
            "sendfile" => libc::SYS_sendfile,
            "socket" => libc::SYS_socket,
            "connect" => libc::SYS_connect,
            "accept" => libc::SYS_accept,
            "sendto" => libc::SYS_sendto,
            "recvfrom" => libc::SYS_recvfrom,
            "sendmsg" => libc::SYS_sendmsg,
            "recvmsg" => libc::SYS_recvmsg,
            "socketpair" => libc::SYS_socketpair,
            "fcntl" => libc::SYS_fcntl,
            "getdents" => libc::SYS_getdents,
            "chdir" => libc::SYS_chdir,
            "fchdir" => libc::SYS_fchdir,
            "creat" => libc::SYS_creat,
            "epoll_create" => libc::SYS_epoll_create,
            "getdents64" => libc::SYS_getdents64,
            "inotify_init" => libc::SYS_inotify_init,
            "openat" => libc::SYS_openat,
            "signalfd" => libc::SYS_signalfd,
            "timerfd_create" => libc::SYS_timerfd_create,
            "eventfd" => libc::SYS_eventfd,
            "accept4" => libc::SYS_accept4,
            "signalfd4" => libc::SYS_signalfd4,
            "eventfd2" => libc::SYS_eventfd2,
            "epoll_create1" => libc::SYS_epoll_create1,
            "dup3" => libc::SYS_dup3,
            "pipe2" => libc::SYS_pipe2,
            "inotify_init1" => libc::SYS_inotify_init1,
            "preadv" => libc::SYS_preadv,
            "pwritev" => libc::SYS_pwritev,
            "perf_event_open" => libc::SYS_perf_event_open,
            "recvmmsg" => libc::SYS_recvmmsg,
            "fanotify_init" => libc::SYS_fanotify_init,
            "open_by_handle_at" => libc::SYS_open_by_handle_at,
            "sendmmsg" => libc::SYS_sendmmsg,
            "memfd_create" => libc::SYS_memfd_create,
            "userfaultfd" => libc::SYS_userfaultfd,
            "preadv2" => libc::SYS_preadv2,
            "pwritev2" => libc::SYS_pwritev2,
            "io_uring_setup" => libc::SYS_io_uring_setup,
            "pidfd_open" => libc::SYS_pidfd_open,
            "close_range" => libc::SYS_close_range,
            "openat2" => libc::SYS_openat2,
            "pidfd_getfd" => libc::SYS_pidfd_getfd,
            _ => panic!("no number for {name}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_table_matches_the_c_library() {
        for entry in table(System::HOST) {
            assert_eq!(
                libc::c_long::from(entry.syscall.number),
                host_number(entry.syscall.name),
                "{}",
                entry.syscall.name
            );
        }
    }
}
