//! Domain types shared by the tracer, the statistics and every output format.

use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

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

    /// True for calls that only work on sockets.
    pub fn needs_socket(self) -> bool {
        matches!(
            self,
            Self::Recvfrom
                | Self::Recvmsg
                | Self::RecvmsgX
                | Self::Sendto
                | Self::Sendmsg
                | Self::SendmsgX
                | Self::Sendfile
        )
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Raw,
    Unix,
    /// A macOS routing socket.
    Route,
    /// A macOS kernel control or event socket.
    System,
    /// A Linux netlink socket, which talks to the kernel.
    Netlink,
    /// A Linux packet socket, which sees whole link-layer frames.
    Packet,
    Other,
}

impl Proto {
    /// Classifies a socket from its `socket(2)` arguments or its `socket_info`.
    pub fn classify(family: i32, sock_type: i32, protocol: i32) -> Self {
        // Linux takes descriptor flags in the type.
        #[cfg(target_os = "linux")]
        let sock_type = sock_type & !(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC);
        match family {
            libc::AF_UNIX => Self::Unix,
            #[cfg(target_os = "macos")]
            libc::AF_ROUTE => Self::Route,
            #[cfg(target_os = "macos")]
            libc::AF_SYSTEM => Self::System,
            #[cfg(target_os = "linux")]
            libc::AF_NETLINK => Self::Netlink,
            #[cfg(target_os = "linux")]
            libc::AF_PACKET => Self::Packet,
            // A raw socket is one whatever protocol it speaks, except that the system lists the
            // ones that speak ICMP with the others of that protocol.
            libc::AF_INET | libc::AF_INET6 => match (protocol, sock_type) {
                (libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6, _) => Self::Icmp,
                (_, libc::SOCK_RAW) => Self::Raw,
                (libc::IPPROTO_TCP, _) | (0, libc::SOCK_STREAM) => Self::Tcp,
                (libc::IPPROTO_UDP, _) | (0, libc::SOCK_DGRAM) => Self::Udp,
                _ => Self::Other,
            },
            _ => Self::Other,
        }
    }

    /// True for protocols whose endpoints are IP addresses and ports.
    pub fn has_addresses(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp | Self::Icmp | Self::Raw)
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
            Self::Netlink => "netlink",
            Self::Packet => "packet",
            Self::Other => "socket",
        }
    }
}

/// Where a socket is connected, as far as it is known.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
            // The trace can name the peer of a connection whose local end only a lookup knows.
            Proto::Tcp => self.remote.is_none() || self.local.is_none(),
            _ => self.local.is_none_or(|addr| addr.port() == 0) || self.remote.is_none(),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, None)
    }
}

impl Endpoint {
    /// The endpoint as it displays, with `host`, when given, in place of the remote address's
    /// IP.
    pub fn named(&self, host: Option<&str>) -> impl fmt::Display {
        fmt::from_fn(move |f| self.write(f, host))
    }

    fn write(&self, f: &mut fmt::Formatter<'_>, host: Option<&str>) -> fmt::Result {
        f.write_str(self.proto.name())?;
        if let Some(path) = &self.path {
            return write!(f, " {path}");
        }
        match (self.local, self.remote.map(|remote| named_addr(remote, host))) {
            (Some(local), Some(remote)) => write!(f, " {local} -> {remote}"),
            (Some(local), None) => write!(f, " {local}"),
            (None, Some(remote)) => write!(f, " -> {remote}"),
            (None, None) if self.proto.has_addresses() => f.write_str(" ?"),
            (None, None) => Ok(()),
        }
    }
}

/// `addr`, or with `host`, when given, `host:port`: the host name in place of the IP.
pub fn named_addr(addr: SocketAddr, host: Option<&str>) -> impl fmt::Display {
    fmt::from_fn(move |f| match host {
        Some(host) => write!(f, "{host}:{}", addr.port()),
        None => fmt::Display::fmt(&addr, f),
    })
}

/// Kind of a descriptor that is neither a file nor a socket. Most kinds exist on one system
/// only: from `Kqueue` to `Atalk` on macOS, from `Eventfd` to `Userfaultfd` on Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    Eventfd,
    Epoll,
    Timerfd,
    Signalfd,
    Inotify,
    Fanotify,
    Pidfd,
    IoUring,
    /// A BPF map, program or link.
    Bpf,
    PerfEvent,
    Userfaultfd,
    Other,
}

impl FdType {
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
            Self::Eventfd => "eventfd",
            Self::Epoll => "epoll",
            Self::Timerfd => "timerfd",
            Self::Signalfd => "signalfd",
            Self::Inotify => "inotify",
            Self::Fanotify => "fanotify",
            Self::Pidfd => "pidfd",
            Self::IoUring => "io_uring",
            Self::Bpf => "bpf",
            Self::PerfEvent => "perf_event",
            Self::Userfaultfd => "userfaultfd",
            Self::Other => "other",
        }
    }
}

/// What a descriptor refers to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// The network interface that an event's I/O went over, as far as iotap can tell. Named
/// interfaces order before the others, by name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Via {
    Interface(Arc<str>),
    /// An Internet socket, or one that may be, whose interface iotap cannot tell.
    Unknown,
    /// No interface: a file or another descriptor, or a socket that stays within the host, such
    /// as a Unix-domain socket.
    NoInterface,
}

impl Via {
    /// The interface's name, when iotap knows it.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Interface(name) => Some(name),
            Self::Unknown | Self::NoInterface => None,
        }
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Interface(name) => name,
            Self::Unknown => "?",
            Self::NoInterface => "none",
        })
    }
}

/// The name, `"?"` when unknown, or null for no interface.
impl Serialize for Via {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Interface(name) => serializer.serialize_str(name),
            Self::Unknown => serializer.serialize_str("?"),
            Self::NoInterface => serializer.serialize_none(),
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
    /// Looked up through libproc or `/proc` when the descriptor was first used.
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
    /// The network interface the I/O went over, which the session tells as it emits the event.
    pub interface: Via,
}

impl IoEvent {
    pub fn dir(&self) -> Dir {
        self.op.dir()
    }

    pub fn is_ok(&self) -> bool {
        self.errno == 0
    }
}

/// Symbolic name of an errno value as reported by the kernel, e.g. `EAGAIN`. Kernels also
/// report values of their own that user space never sees, such as the ones that make a call
/// start over after a signal.
pub fn errno_name(errno: i32) -> Cow<'static, str> {
    let name = match errno {
        #[cfg(target_os = "macos")]
        -2 => "EJUSTRETURN",
        #[cfg(target_os = "macos")]
        -1 => "ERESTART",
        #[cfg(target_os = "linux")]
        512 => "ERESTARTSYS",
        #[cfg(target_os = "linux")]
        513 => "ERESTARTNOINTR",
        #[cfg(target_os = "linux")]
        514 => "ERESTARTNOHAND",
        #[cfg(target_os = "linux")]
        515 => "ENOIOCTLCMD",
        #[cfg(target_os = "linux")]
        516 => "ERESTART_RESTARTBLOCK",
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
        // Linux gives it the value of EOPNOTSUPP, which names it there.
        #[cfg(target_os = "macos")]
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
        #[cfg(target_os = "macos")]
        libc::ENOATTR => "ENOATTR",
        #[cfg(target_os = "linux")]
        libc::ENODATA => "ENODATA",
        libc::EBADMSG => "EBADMSG",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        #[cfg(target_os = "macos")]
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
        assert_eq!(
            tcp.named(Some("www.example.com")).to_string(),
            "tcp 192.168.1.2:60868 -> www.example.com:443"
        );
        assert_eq!(tcp.named(None).to_string(), tcp.to_string());
        assert!(!tcp.is_incomplete());
        let unix = Endpoint {
            path: Some("/var/run/mDNSResponder".into()),
            ..Endpoint::unresolved(Proto::Unix)
        };
        assert_eq!(unix.to_string(), "unix /var/run/mDNSResponder");
        assert_eq!(unix.named(Some("x")).to_string(), unix.to_string());
        assert_eq!(Endpoint::unresolved(Proto::Udp).to_string(), "udp ?");
        assert_eq!(Endpoint::unresolved(Proto::System).to_string(), "system");
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
        // A raw socket that speaks TCP or UDP is still a raw socket, as the system lists it,
        // and one that speaks ICMP is listed as ICMP.
        for (family, protocol, proto) in [
            (libc::AF_INET, libc::IPPROTO_TCP, Proto::Raw),
            (libc::AF_INET6, libc::IPPROTO_UDP, Proto::Raw),
            (libc::AF_INET, 255, Proto::Raw),
            (libc::AF_INET, libc::IPPROTO_ICMP, Proto::Icmp),
            (libc::AF_INET6, libc::IPPROTO_ICMPV6, Proto::Icmp),
        ] {
            assert_eq!(Proto::classify(family, libc::SOCK_RAW, protocol), proto);
        }
        #[cfg(target_os = "linux")]
        {
            let cloexec = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
            assert_eq!(Proto::classify(libc::AF_INET, cloexec, 0), Proto::Tcp);
            assert_eq!(
                Proto::classify(libc::AF_NETLINK, libc::SOCK_RAW, 0),
                Proto::Netlink
            );
        }
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
    fn interfaces_display_and_serialize() {
        let en0 = Via::Interface("en0".into());
        assert_eq!(en0.to_string(), "en0");
        assert_eq!(en0.name(), Some("en0"));
        assert_eq!(Via::Unknown.to_string(), "?");
        assert_eq!(Via::NoInterface.to_string(), "none");
        assert_eq!(Via::Unknown.name(), None);
        assert_eq!(serde_json::to_string(&en0).unwrap(), r#""en0""#);
        assert_eq!(serde_json::to_string(&Via::Unknown).unwrap(), r#""?""#);
        assert_eq!(serde_json::to_string(&Via::NoInterface).unwrap(), "null");
        let mut order = [
            Via::NoInterface,
            Via::Unknown,
            en0,
            Via::Interface("awdl0".into()),
        ];
        order.sort();
        let names: Vec<String> = order.iter().map(Via::to_string).collect();
        assert_eq!(names, ["awdl0", "en0", "?", "none"]);
    }

    #[test]
    fn names_errno_values() {
        assert_eq!(errno_name(libc::EAGAIN), "EAGAIN");
        assert_eq!(errno_name(libc::EOPNOTSUPP), "EOPNOTSUPP");
        #[cfg(target_os = "macos")]
        assert_eq!(errno_name(-1), "ERESTART");
        #[cfg(target_os = "linux")]
        assert_eq!(errno_name(512), "ERESTARTSYS");
        assert_eq!(errno_name(12345), "errno 12345");
    }
}
