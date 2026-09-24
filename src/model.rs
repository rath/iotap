//! Domain types shared by the tracer, the statistics and every output format.

use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::Serialize;

/// Direction of a data transfer, from the traced process's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dir {
    Read,
    Write,
}

/// Canonical I/O operation. `_nocancel` and guarded variants map to their base call; the exact
/// syscall name is kept separately on [`IoEvent::syscall`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Read,
    Pread,
    Readv,
    Preadv,
    Recvfrom,
    Recvmsg,
    RecvmsgX,
    Getdirentries,
    Write,
    Pwrite,
    Writev,
    Pwritev,
    Sendto,
    Sendmsg,
    SendmsgX,
    Sendfile,
}

/// What a successful call's return value counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultUnit {
    Bytes,
    /// `sendmsg_x`/`recvmsg_x` return the number of messages, not bytes.
    Messages,
    /// `sendfile` reports its byte count through a user pointer the trace cannot see.
    Unknown,
}

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Pread => "pread",
            Self::Readv => "readv",
            Self::Preadv => "preadv",
            Self::Recvfrom => "recvfrom",
            Self::Recvmsg => "recvmsg",
            Self::RecvmsgX => "recvmsg_x",
            Self::Getdirentries => "getdirentries",
            Self::Write => "write",
            Self::Pwrite => "pwrite",
            Self::Writev => "writev",
            Self::Pwritev => "pwritev",
            Self::Sendto => "sendto",
            Self::Sendmsg => "sendmsg",
            Self::SendmsgX => "sendmsg_x",
            Self::Sendfile => "sendfile",
        }
    }

    pub fn dir(self) -> Dir {
        match self {
            Self::Read
            | Self::Pread
            | Self::Readv
            | Self::Preadv
            | Self::Recvfrom
            | Self::Recvmsg
            | Self::RecvmsgX
            | Self::Getdirentries => Dir::Read,
            Self::Write
            | Self::Pwrite
            | Self::Writev
            | Self::Pwritev
            | Self::Sendto
            | Self::Sendmsg
            | Self::SendmsgX
            | Self::Sendfile => Dir::Write,
        }
    }

    pub fn result_unit(self) -> ResultUnit {
        match self {
            Self::RecvmsgX | Self::SendmsgX => ResultUnit::Messages,
            Self::Sendfile => ResultUnit::Unknown,
            _ => ResultUnit::Bytes,
        }
    }
}

/// Transport of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Raw,
    Unix,
    Route,
    System,
    Other,
}

impl Proto {
    /// Classifies a socket from its `socket(2)` arguments or its `socket_info`.
    pub fn classify(family: i32, sock_type: i32, protocol: i32) -> Self {
        match family {
            libc::AF_UNIX => Self::Unix,
            libc::AF_ROUTE => Self::Route,
            libc::AF_SYSTEM => Self::System,
            libc::AF_INET | libc::AF_INET6 => match (protocol, sock_type) {
                (libc::IPPROTO_TCP, _) | (0, libc::SOCK_STREAM) => Self::Tcp,
                (libc::IPPROTO_UDP, _) | (0, libc::SOCK_DGRAM) => Self::Udp,
                (libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6, _) => Self::Icmp,
                (_, libc::SOCK_RAW) => Self::Raw,
                _ => Self::Other,
            },
            _ => Self::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Raw => "raw",
            Self::Unix => "unix",
            Self::Route => "route",
            Self::System => "system",
            Self::Other => "socket",
        }
    }
}

/// Where a socket is connected, as far as it is known.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Endpoint {
    pub proto: Proto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<SocketAddr>,
    /// Path of a Unix-domain socket: the peer's path, or the bound path when unconnected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Endpoint {
    pub fn unresolved(proto: Proto) -> Self {
        Self {
            proto,
            local: None,
            remote: None,
            path: None,
        }
    }

    /// True when a later lookup could still add information.
    pub fn is_incomplete(&self) -> bool {
        match self.proto {
            Proto::Unix => self.path.is_none(),
            Proto::Tcp => self.remote.is_none(),
            _ => self.local.is_none_or(|addr| addr.port() == 0) || self.remote.is_none(),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.proto.name())?;
        if let Some(path) = &self.path {
            return write!(f, " {path}");
        }
        match (self.local, self.remote) {
            (Some(local), Some(remote)) => write!(f, " {local} -> {remote}"),
            (Some(local), None) => write!(f, " {local}"),
            (None, Some(remote)) => write!(f, " -> {remote}"),
            (None, None) => f.write_str(" ?"),
        }
    }
}

/// Kind of a descriptor that is neither a file nor a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FdType {
    Pipe,
    Kqueue,
    Pshm,
    Psem,
    Fsevents,
    Netpolicy,
    Channel,
    Nexus,
    Atalk,
    Other,
}

impl FdType {
    /// Maps a libproc `PROX_FDTYPE_*` value (vnodes and sockets excluded).
    pub fn from_prox(fd_type: u32) -> Self {
        match i32::try_from(fd_type).unwrap_or(-1) {
            libc::PROX_FDTYPE_PIPE => Self::Pipe,
            libc::PROX_FDTYPE_KQUEUE => Self::Kqueue,
            libc::PROX_FDTYPE_PSHM => Self::Pshm,
            libc::PROX_FDTYPE_PSEM => Self::Psem,
            libc::PROX_FDTYPE_FSEVENTS => Self::Fsevents,
            libc::PROX_FDTYPE_NETPOLICY => Self::Netpolicy,
            libc::PROX_FDTYPE_CHANNEL => Self::Channel,
            libc::PROX_FDTYPE_NEXUS => Self::Nexus,
            libc::PROX_FDTYPE_ATALK => Self::Atalk,
            _ => Self::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pipe => "pipe",
            Self::Kqueue => "kqueue",
            Self::Pshm => "shm",
            Self::Psem => "semaphore",
            Self::Fsevents => "fsevents",
            Self::Netpolicy => "necp",
            Self::Channel => "channel",
            Self::Nexus => "nexus",
            Self::Atalk => "appletalk",
            Self::Other => "other",
        }
    }
}

/// What a descriptor refers to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    File {
        path: String,
    },
    Socket(Endpoint),
    Other {
        fd_type: FdType,
    },
    /// The descriptor could not be identified, typically because it was closed before iotap
    /// could look it up, or the call began before tracing did.
    Unknown,
}

/// Coarse grouping used for filters and the summary tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    File,
    Network,
    Other,
}

impl Target {
    pub fn category(&self) -> Category {
        match self {
            Self::File { .. } => Category::File,
            Self::Socket(_) => Category::Network,
            Self::Other { .. } | Self::Unknown => Category::Other,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { path } => f.write_str(path),
            Self::Socket(endpoint) => endpoint.fmt(f),
            Self::Other { fd_type } => write!(f, "<{}>", fd_type.name()),
            Self::Unknown => f.write_str("<unknown>"),
        }
    }
}

/// How iotap learned what a descriptor refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// From the traced call that created the descriptor.
    Traced,
    /// From the descriptor table read when tracing of the process started.
    Snapshot,
    /// Looked up when the descriptor was first used; can be stale if it was reused meanwhile.
    Lazy,
    /// Not known.
    None,
}

/// One completed read or write syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoEvent {
    /// Wall-clock time the call returned, in nanoseconds since the Unix epoch.
    pub time_ns: u64,
    pub pid: i32,
    pub tid: u64,
    pub op: Op,
    /// Exact kernel syscall name, e.g. `read_nocancel`.
    pub syscall: &'static str,
    /// `None` when the call began before tracing did.
    pub fd: Option<i32>,
    /// Size the caller asked for, when the call takes a single buffer.
    pub requested: Option<u64>,
    /// Bytes transferred; `None` when the call failed or its unit is not bytes.
    pub bytes: Option<u64>,
    /// Messages transferred by `sendmsg_x`/`recvmsg_x`.
    pub messages: Option<u64>,
    /// 0 on success.
    pub errno: i32,
    /// Time spent in the call; `None` when the call began before tracing did.
    pub latency_ns: Option<u64>,
    pub target: Arc<Target>,
    pub provenance: Provenance,
}

impl IoEvent {
    pub fn dir(&self) -> Dir {
        self.op.dir()
    }

    pub fn is_ok(&self) -> bool {
        self.errno == 0
    }
}

/// Symbolic name of an errno value as reported by the kernel, e.g. `EAGAIN`.
pub fn errno_name(errno: i32) -> Cow<'static, str> {
    let name = match errno {
        -2 => "EJUSTRETURN",
        -1 => "ERESTART",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
        libc::EBADF => "EBADF",
        libc::EDEADLK => "EDEADLK",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV",
        libc::ENODEV => "ENODEV",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EINVAL => "EINVAL",
        libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE",
        libc::ENOTTY => "ENOTTY",
        libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC",
        libc::ESPIPE => "ESPIPE",
        libc::EROFS => "EROFS",
        libc::EPIPE => "EPIPE",
        libc::EAGAIN => "EAGAIN",
        libc::EINPROGRESS => "EINPROGRESS",
        libc::EALREADY => "EALREADY",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EDESTADDRREQ => "EDESTADDRREQ",
        libc::EMSGSIZE => "EMSGSIZE",
        libc::EPROTOTYPE => "EPROTOTYPE",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ENOTSUP => "ENOTSUP",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::ENETDOWN => "ENETDOWN",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ENETRESET => "ENETRESET",
        libc::ECONNABORTED => "ECONNABORTED",
        libc::ECONNRESET => "ECONNRESET",
        libc::ENOBUFS => "ENOBUFS",
        libc::EISCONN => "EISCONN",
        libc::ENOTCONN => "ENOTCONN",
        libc::ESHUTDOWN => "ESHUTDOWN",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ELOOP => "ELOOP",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::EHOSTDOWN => "EHOSTDOWN",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::EDQUOT => "EDQUOT",
        libc::ESTALE => "ESTALE",
        libc::ENOLCK => "ENOLCK",
        libc::ENOSYS => "ENOSYS",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::ECANCELED => "ECANCELED",
        libc::EILSEQ => "EILSEQ",
        libc::ENOATTR => "ENOATTR",
        libc::EBADMSG => "EBADMSG",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EQFULL => "EQFULL",
        _ => return Cow::Owned(format!("errno {errno}")),
    };
    Cow::Borrowed(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_display() {
        let tcp = Endpoint {
            proto: Proto::Tcp,
            local: Some("192.168.1.2:60868".parse().unwrap()),
            remote: Some("[2a00:1450::1]:443".parse().unwrap()),
            path: None,
        };
        assert_eq!(tcp.to_string(), "tcp 192.168.1.2:60868 -> [2a00:1450::1]:443");
        assert!(!tcp.is_incomplete());
        let unix = Endpoint {
            path: Some("/var/run/mDNSResponder".into()),
            ..Endpoint::unresolved(Proto::Unix)
        };
        assert_eq!(unix.to_string(), "unix /var/run/mDNSResponder");
        assert_eq!(Endpoint::unresolved(Proto::Udp).to_string(), "udp ?");
        assert!(Endpoint::unresolved(Proto::Udp).is_incomplete());
    }

    #[test]
    fn classifies_sockets() {
        assert_eq!(Proto::classify(libc::AF_INET, libc::SOCK_STREAM, 0), Proto::Tcp);
        assert_eq!(
            Proto::classify(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
            Proto::Udp
        );
        assert_eq!(Proto::classify(libc::AF_UNIX, libc::SOCK_STREAM, 0), Proto::Unix);
        assert_eq!(
            Proto::classify(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP),
            Proto::Icmp
        );
    }

    #[test]
    fn target_serializes_with_kind_tag() {
        let file = Target::File {
            path: "/tmp/x".into(),
        };
        assert_eq!(
            serde_json::to_string(&file).unwrap(),
            r#"{"kind":"file","path":"/tmp/x"}"#
        );
        let sock = Target::Socket(Endpoint::unresolved(Proto::Udp));
        assert_eq!(
            serde_json::to_string(&sock).unwrap(),
            r#"{"kind":"socket","proto":"udp"}"#
        );
        let pipe = Target::Other {
            fd_type: FdType::Pipe,
        };
        assert_eq!(pipe.to_string(), "<pipe>");
        assert_eq!(
            serde_json::to_string(&pipe).unwrap(),
            r#"{"kind":"other","fd_type":"pipe"}"#
        );
    }

    #[test]
    fn names_errno_values() {
        assert_eq!(errno_name(libc::EAGAIN), "EAGAIN");
        assert_eq!(errno_name(-1), "ERESTART");
        assert_eq!(errno_name(12345), "errno 12345");
    }
}
