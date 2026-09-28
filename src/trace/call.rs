//! A syscall as the trace shows it once its records are put together, whatever format they
//! came in: the part it plays, its arguments and result, and the path it looked up.

use std::net::SocketAddr;

use crate::model::Op;

/// Kind of descriptor a syscall returns when iotap cannot learn more from the trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewFd {
    Kqueue,
    Pshm,
    Necp,
    /// Resolved through libproc when first used.
    Unknown,
}

/// The part a syscall plays in tracking descriptors and I/O. Argument indices refer to the
/// four arguments recorded at syscall entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Transfers data through the descriptor in `fd_arg`; `len_arg` holds the requested size
    /// when the call takes a single buffer.
    Io {
        op: Op,
        fd_arg: usize,
        len_arg: Option<usize>,
    },
    /// Opens the looked-up path and returns a descriptor; `dirfd_arg` is set for `*at` calls.
    /// `flags_arg` holds the flags as an `int`, when the call takes them so and the decoder needs
    /// to read them. It is a `u8`, like the indices of what the eBPF program captures, so that
    /// a call stays small.
    Open {
        dirfd_arg: Option<usize>,
        flags_arg: Option<u8>,
    },
    Close,
    Dup,
    Dup2,
    Fcntl,
    Socket,
    /// Creates two connected sockets and returns their descriptors in the two return slots.
    SocketPair,
    Accept,
    Connect,
    /// Creates a pipe and returns its descriptors in the two return slots.
    Pipe,
    NewFd(NewFd),
    /// Closes every descriptor from the first argument to the second, unless the third only
    /// asks to mark them close-on-exec (Linux's `close_range`).
    CloseRange,
    Chdir,
    Fchdir,
}

impl Role {
    /// True when the paths looked up during the call matter.
    pub fn takes_path(self) -> bool {
        matches!(self, Self::Open { .. } | Self::Chdir | Self::Connect)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syscall {
    pub number: u16,
    pub name: &'static str,
    pub role: Role,
}

/// A syscall that returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    pub call: Syscall,
    pub tid: u64,
    pub pid: i32,
    /// Entry timestamp and the first four arguments; `None` when the call began before tracing
    /// did or its entry was not recorded.
    pub start: Option<(u64, [u64; 4])>,
    pub end_ts: u64,
    /// 0 on success.
    pub errno: i32,
    /// The two return-value slots, `uu_rval[0]` and `uu_rval[1]` in XNU.
    pub rval: [u32; 2],
    /// The first path looked up during the call.
    pub lookup: Option<Lookup>,
    /// The Internet address a `connect` named, when the trace carries it, as on Linux.
    pub remote: Option<SocketAddr>,
}

/// A path a call looked up, as the trace reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub path: String,
    /// Only the end of the path was reported, as kdebug did before macOS 15.4
    /// ([`PathRecords::Tail`](super::kdebug::pairing::PathRecords::Tail)). In that format a path
    /// of exactly the reported length looks the same, so it counts as truncated too.
    pub truncated: bool,
    /// The kernel's identifier for the vnode found, 0 when nothing was or the trace does not
    /// say. Lookups that find the same file report the same identifier while its vnode lives,
    /// whatever path they took.
    pub vnode: u64,
    /// How the path relates to what the process passed.
    pub form: PathForm,
}

/// How a looked-up path relates to what the process passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathForm {
    /// As the kernel reports a lookup it made, once it is complete (kdebug). Following a
    /// symbolic link replaces the path with the link's text followed by the rest of the path,
    /// so the path is what the process passed only when no link was followed. After a link with
    /// a relative target, it is relative to the directory holding that link: `/etc/hosts` is
    /// reported as `private/etc/hosts`, because `/etc` links to `private/etc`.
    Kernel,
    /// As the process passed it: relative to the working directory, or to the directory
    /// descriptor of an `*at` call.
    Passed,
    /// A name in the abstract namespace of Unix-domain sockets, written `@name`. It names no
    /// file and is relative to nothing.
    Abstract,
}

impl Lookup {
    /// Reported whole, and in need of no directory to be complete: an absolute path or an
    /// abstract socket name.
    pub fn is_absolute(&self) -> bool {
        !self.truncated && (self.path.starts_with('/') || self.form == PathForm::Abstract)
    }
}

impl Completed {
    pub fn is_ok(&self) -> bool {
        self.errno == 0
    }

    /// Return value of a call that returns a descriptor or an `int`.
    pub fn ret_i32(&self) -> i32 {
        self.rval[0].cast_signed()
    }

    /// Return value of a call that returns `ssize_t`; the kernel stores it across both slots.
    pub fn ret_u64(&self) -> u64 {
        (u64::from(self.rval[1]) << 32) | u64::from(self.rval[0])
    }

    pub fn arg(&self, index: usize) -> Option<u64> {
        self.start.map(|(_, args)| args[index])
    }

    /// Argument `index` read as a C `int`, such as a descriptor.
    pub fn arg_i32(&self, index: usize) -> Option<i32> {
        self.arg(index).map(low_i32)
    }

    pub fn start_ts(&self) -> Option<u64> {
        self.start.map(|(ts, _)| ts)
    }

    pub fn latency_ticks(&self) -> Option<u64> {
        self.start_ts().map(|ts| self.end_ts.saturating_sub(ts))
    }
}

/// Reads a C `int` the kernel stored in a 64-bit record slot.
pub fn low_i32(value: u64) -> i32 {
    (value as u32).cast_signed()
}
