//! Process facts from `/proc`: process listing, first arguments, descriptor tables and what a
//! descriptor refers to.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::ProcInfo;
use crate::model::{Endpoint, FdType, Proto, Target};

/// `PF_EXITING` in the flags `/proc/<pid>/stat` shows: the thread has begun to exit.
const PF_EXITING: u64 = 0x4;
/// What a link in `/proc` adds to the path of a file that was unlinked.
const DELETED: &str = " (deleted)";
/// The most of `/proc/<pid>/cmdline` read for `argv[0]`, `PATH_MAX`: one longer than any path
/// names no program to trace by.
const ARG0_BYTES: usize = 4096;

/// The socket tables of a network namespace, in `/proc/<pid>/net`, most used first.
const TABLES: [(&str, Layout); 11] = [
    ("tcp", Layout::Inet(Proto::Tcp)),
    ("tcp6", Layout::Inet(Proto::Tcp)),
    ("udp", Layout::Inet(Proto::Udp)),
    ("udp6", Layout::Inet(Proto::Udp)),
    ("unix", Layout::Unix),
    ("netlink", Layout::Netlink),
    ("icmp", Layout::Inet(Proto::Icmp)),
    ("icmp6", Layout::Inet(Proto::Icmp)),
    ("raw", Layout::Raw),
    ("raw6", Layout::Raw),
    ("packet", Layout::Packet),
];

/// Pids of every process on the system.
pub fn list_pids() -> Vec<i32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids: Vec<i32> = dir
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|&pid| pid > 0)
        .collect();
    pids.sort_unstable();
    pids
}

/// Name and start time of a running process; `None` once it has exited, zombies included, and
/// for the id of a thread that does not lead its process.
pub fn info(pid: i32) -> Option<ProcInfo> {
    if pid <= 0 {
        return None;
    }
    let stat = Stat::read(format!("/proc/{pid}/stat"))?;
    // `/proc` answers for every thread by its id, but only the first thread's is the process's.
    if thread_group(pid)? != pid {
        return None;
    }
    // A process lives on after its first thread exits while other threads remain.
    if !stat.running() && !any_thread_running(pid) {
        return None;
    }
    Some(ProcInfo {
        pid,
        name: stat.comm,
        start: (stat.start, 0),
        parent: stat.parent,
    })
}

/// Path of the executable a process runs.
pub fn exe_path(pid: i32) -> Option<String> {
    link(&format!("/proc/{pid}/exe"))
}

/// `argv[0]` of a process as its memory holds it now, which the process may have rewritten;
/// `None` if the process is gone or has no arguments, as kernel threads have none.
pub fn arg0(pid: i32) -> Option<String> {
    let mut head = Vec::new();
    fs::File::open(format!("/proc/{pid}/cmdline"))
        .ok()?
        .take(ARG0_BYTES as u64)
        .read_to_end(&mut head)
        .ok()?;
    let end = match head.iter().position(|&b| b == 0) {
        Some(end) => end,
        // Without its NUL, it may go on past what was read.
        None if head.len() == ARG0_BYTES => return None,
        None => head.len(),
    };
    (end > 0).then(|| String::from_utf8_lossy(&head[..end]).into_owned())
}

/// Current working directory of a process.
pub fn cwd(pid: i32) -> Option<String> {
    link(&format!("/proc/{pid}/cwd"))
}

/// The network namespace of a process, by the inode number its `/proc/<pid>/ns/net` link names;
/// `None` if the process is gone.
pub fn netns(pid: i32) -> Option<u64> {
    namespace_inode(&link(&format!("/proc/{pid}/ns/net"))?)
}

/// The inode number in a namespace link, such as `net:[4026531840]`.
fn namespace_inode(link: &str) -> Option<u64> {
    let (_, inode) = link.split_once(":[")?;
    inode.strip_suffix(']')?.parse().ok()
}

/// Open descriptors of a process and what each refers to; `None` if the process is gone.
pub fn fds(pid: i32) -> Option<Vec<(i32, Target)>> {
    let dir = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut links: Vec<(i32, Link)> = dir
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let fd = entry.file_name().to_str()?.parse().ok()?;
            // A descriptor closed since the listing is left out.
            Some((fd, fd_link(&entry.path())?))
        })
        .collect();
    links.sort_unstable_by_key(|&(fd, _)| fd);
    let wanted: Vec<Socket> = links.iter().filter_map(|(_, link)| link.socket()).collect();
    let sockets = sockets(pid, &wanted);
    Some(
        links
            .into_iter()
            .map(|(fd, link)| (fd, link.target(&sockets)))
            .collect(),
    )
}

/// What `fd` of `pid` refers to now; `None` if it is not open.
pub fn fd_target(pid: i32, fd: i32) -> Option<Target> {
    let link = fd_link(Path::new(&format!("/proc/{pid}/fd/{fd}")))?;
    let wanted: Vec<Socket> = link.socket().into_iter().collect();
    Some(link.target(&sockets(pid, &wanted)))
}

/// What the descriptor behind `path`, a link in `/proc/<pid>/fd`, refers to; `None` if it is
/// not open.
fn fd_link(path: &Path) -> Option<Link> {
    let link = Link::parse(fs::read_link(path).ok()?.as_os_str().as_bytes());
    let Link::Socket(socket) = link else {
        return Some(link);
    };
    // The kernel's name for the socket's protocol tells which table lists the socket, so that
    // only that one is read. The number may have been closed and reused meanwhile, so the name
    // counts only while the link leads to the same socket.
    let table = protocol_name(path).and_then(|name| table_of(&name));
    let again = Link::parse(fs::read_link(path).ok()?.as_os_str().as_bytes());
    Some(Link::Socket(match again {
        Link::Socket(same) if same.inode == socket.inode => Socket { table, ..socket },
        _ => socket,
    }))
}

/// The kernel's name for the protocol of the socket behind `path`, such as `TCP` or
/// `UNIX-STREAM`: the socket's `system.sockprotoname` attribute.
fn protocol_name(path: &Path) -> Option<String> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // Protocol names are shorter than 32 bytes with their NUL.
    let mut name = [0u8; 32];
    // SAFETY: both strings end in NUL, and `name` is writable for the length given.
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"system.sockprotoname".as_ptr(),
            name.as_mut_ptr().cast(),
            name.len(),
        )
    };
    let name = name.get(..usize::try_from(len).ok()?)?;
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    std::str::from_utf8(name).ok().map(str::to_owned)
}

/// Which of [`TABLES`] lists the sockets of the protocol the kernel calls `name`; `None` for a
/// protocol no table lists, or one iotap does not know.
fn table_of(name: &str) -> Option<usize> {
    let table = match name {
        "TCP" => "tcp",
        "TCPv6" => "tcp6",
        "UDP" => "udp",
        "UDPv6" => "udp6",
        "UNIX" | "UNIX-STREAM" => "unix",
        "NETLINK" => "netlink",
        "PING" => "icmp",
        "PINGv6" => "icmp6",
        "RAW" => "raw",
        "RAWv6" => "raw6",
        "PACKET" => "packet",
        _ => return None,
    };
    TABLES.iter().position(|&(listed, _)| listed == table)
}

/// The fields of `/proc/<pid>/stat` iotap reads.
#[derive(Debug, PartialEq, Eq)]
struct Stat {
    comm: String,
    state: u8,
    /// The parent's pid.
    parent: i32,
    flags: u64,
    /// Clock ticks from boot to the start.
    start: u64,
}

impl Stat {
    fn read(path: impl AsRef<Path>) -> Option<Self> {
        Self::parse(&fs::read(path).ok()?)
    }

    fn parse(text: &[u8]) -> Option<Self> {
        // The name in parentheses may hold any byte but NUL, parentheses too, so it ends at the
        // last closing one.
        let open = text.iter().position(|&b| b == b'(')?;
        let close = text.iter().rposition(|&b| b == b')')?;
        let comm = String::from_utf8_lossy(text.get(open + 1..close)?).into_owned();
        let rest = std::str::from_utf8(text.get(close + 1..)?).ok()?;
        let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
        // Fields count from 1, and the rest starts at the third, the state.
        let field = |n: usize| fields.get(n - 3).copied();
        Some(Self {
            comm,
            state: *field(3)?.as_bytes().first()?,
            parent: field(4)?.parse().ok()?,
            flags: field(9)?.parse().ok()?,
            start: field(22)?.parse().ok()?,
        })
    }

    /// Neither a zombie nor dead nor on its way out.
    fn running(&self) -> bool {
        !matches!(self.state, b'Z' | b'X' | b'x') && self.flags & PF_EXITING == 0
    }
}

/// The process a thread belongs to.
fn thread_group(tid: i32) -> Option<i32> {
    let status = fs::read(format!("/proc/{tid}/status")).ok()?;
    let status = String::from_utf8_lossy(&status);
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))?
        .trim()
        .parse()
        .ok()
}

/// Whether any thread of process `pid` is still running.
fn any_thread_running(pid: i32) -> bool {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks
        .filter_map(Result::ok)
        .any(|task| Stat::read(task.path().join("stat")).is_some_and(|stat| stat.running()))
}

/// Where a link in `/proc` points, without the mark of an unlinked file.
fn link(path: &str) -> Option<String> {
    let target = fs::read_link(path).ok()?;
    Some(undeleted(
        String::from_utf8_lossy(target.as_os_str().as_bytes()).into_owned(),
    ))
}

fn undeleted(path: String) -> String {
    match path.strip_suffix(DELETED) {
        Some(kept) => kept.to_owned(),
        None => path,
    }
}

/// What a descriptor's link in `/proc/<pid>/fd` names.
#[derive(Debug, PartialEq, Eq)]
enum Link {
    File(String),
    Socket(Socket),
    Other(FdType),
}

/// A socket, by inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Socket {
    inode: u64,
    /// Which of [`TABLES`] lists sockets of its protocol; `None` when that is not known.
    table: Option<usize>,
}

impl Link {
    /// What a link's text names. A socket's protocol is not in the text.
    fn parse(link: &[u8]) -> Self {
        if link.starts_with(b"/") {
            return Self::File(undeleted(String::from_utf8_lossy(link).into_owned()));
        }
        if let Some(inode) = bracketed(link, b"socket:") {
            return Self::Socket(Socket { inode, table: None });
        }
        if link.starts_with(b"pipe:") {
            return Self::Other(FdType::Pipe);
        }
        match link.strip_prefix(b"anon_inode:") {
            Some(name) => Self::Other(anonymous(name)),
            None => Self::Other(FdType::Other),
        }
    }

    fn socket(&self) -> Option<Socket> {
        match self {
            Self::Socket(socket) => Some(*socket),
            _ => None,
        }
    }

    /// What the descriptor refers to, given the endpoints of the sockets found.
    fn target(self, sockets: &HashMap<u64, Endpoint>) -> Target {
        match self {
            Self::File(path) => Target::File { path },
            // A socket no table lists: one of a family such as vsock, or one no table lists in
            // its state, such as a TCP socket neither bound nor connected.
            Self::Socket(socket) => {
                Target::Socket(sockets.get(&socket.inode).cloned().unwrap_or_else(|| {
                    Endpoint::unresolved(socket.table.map_or(Proto::Other, |table| TABLES[table].1.proto()))
                }))
            }
            Self::Other(fd_type) => Target::Other { fd_type },
        }
    }
}

/// The number in a link such as `socket:[123]`.
fn bracketed(link: &[u8], prefix: &[u8]) -> Option<u64> {
    let number = link
        .strip_prefix(prefix)?
        .strip_prefix(b"[")?
        .strip_suffix(b"]")?;
    std::str::from_utf8(number).ok()?.parse().ok()
}

/// The kind of an anonymous inode, by the name the kernel gives it, in brackets or not.
fn anonymous(name: &[u8]) -> FdType {
    let name = name
        .strip_prefix(b"[")
        .and_then(|name| name.strip_suffix(b"]"))
        .unwrap_or(name);
    match name {
        b"eventfd" => FdType::Eventfd,
        b"eventpoll" => FdType::Epoll,
        b"timerfd" => FdType::Timerfd,
        b"signalfd" => FdType::Signalfd,
        b"inotify" => FdType::Inotify,
        b"fanotify" => FdType::Fanotify,
        b"pidfd" => FdType::Pidfd,
        b"io_uring" => FdType::IoUring,
        b"perf_event" => FdType::PerfEvent,
        b"userfaultfd" => FdType::Userfaultfd,
        // bpf-map, bpf-prog, bpf_link and the like.
        name if name.starts_with(b"bpf") || name == b"btf" => FdType::Bpf,
        _ => FdType::Other,
    }
}

/// Endpoints of the `wanted` sockets, from the tables of the network namespace `pid` is in:
/// each looked for in the table of its protocol, or in every table when that is not known.
/// Reading a table costs up to milliseconds, however few sockets it lists.
fn sockets(pid: i32, wanted: &[Socket]) -> HashMap<u64, Endpoint> {
    let inodes: HashSet<u64> = wanted.iter().map(|socket| socket.inode).collect();
    let mut found = HashMap::new();
    for (index, (name, layout)) in TABLES.into_iter().enumerate() {
        let needed = wanted.iter().any(|socket| {
            socket.table.is_none_or(|table| table == index) && !found.contains_key(&socket.inode)
        });
        if !needed {
            continue;
        }
        let Ok(table) = fs::read(format!("/proc/{pid}/net/{name}")) else {
            continue;
        };
        // The first line names the columns.
        for line in String::from_utf8_lossy(&table).lines().skip(1) {
            if let Some((inode, endpoint)) = layout.parse(line)
                && inodes.contains(&inode)
            {
                found.insert(inode, endpoint);
            }
        }
    }
    found
}

/// How a socket table lays out its lines.
#[derive(Clone, Copy, Debug)]
enum Layout {
    /// `sl local_address rem_address st ... inode`, for the protocol given.
    Inet(Proto),
    /// As `Inet`, with the protocol number where the port would be.
    Raw,
    /// `Num RefCount Protocol Flags Type St Inode Path`.
    Unix,
    /// `sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode`.
    Netlink,
    /// `sk RefCnt Type Proto Iface R Rmem User Inode`.
    Packet,
}

impl Layout {
    /// The protocol of the sockets a table lists; a raw table's ICMP sockets aside.
    fn proto(self) -> Proto {
        match self {
            Self::Inet(proto) => proto,
            Self::Raw => Proto::Raw,
            Self::Unix => Proto::Unix,
            Self::Netlink => Proto::Netlink,
            Self::Packet => Proto::Packet,
        }
    }

    /// The inode and endpoint of the socket a line describes.
    fn parse(self, line: &str) -> Option<(u64, Endpoint)> {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let inode_at = match self {
            Self::Inet(_) | Self::Raw | Self::Netlink => 9,
            Self::Unix => 6,
            Self::Packet => 8,
        };
        let inode = fields.get(inode_at)?.parse().ok()?;
        // Addresses, where a layout has them, come before the inode.
        let endpoint = match self {
            Self::Inet(proto) => Endpoint {
                local: address(fields[1]),
                remote: address(fields[2]),
                ..Endpoint::unresolved(proto)
            },
            Self::Raw => {
                let (_, protocol) = fields.get(1)?.split_once(':')?;
                let proto = match i32::from(u16::from_str_radix(protocol, 16).ok()?) {
                    libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => Proto::Icmp,
                    _ => Proto::Raw,
                };
                // Raw sockets have no ports.
                let ip = |field: &str| {
                    let ip = hex_ip(field.split_once(':')?.0)?;
                    (!ip.is_unspecified()).then_some(SocketAddr::new(ip, 0))
                };
                Endpoint {
                    local: ip(fields[1]),
                    remote: ip(fields[2]),
                    ..Endpoint::unresolved(proto)
                }
            }
            Self::Unix => Endpoint {
                path: unix_path(line),
                ..Endpoint::unresolved(Proto::Unix)
            },
            Self::Netlink => Endpoint::unresolved(Proto::Netlink),
            Self::Packet => Endpoint::unresolved(Proto::Packet),
        };
        Some((inode, endpoint))
    }
}

/// An address as the inet tables show it: the IP in hex as the kernel holds it, a colon, and
/// the port in hex. `None` for a socket not bound or connected there, and for a field iotap
/// cannot read.
fn address(field: &str) -> Option<SocketAddr> {
    let (ip, port) = field.split_once(':')?;
    let ip = hex_ip(ip)?;
    let port = u16::from_str_radix(port, 16).ok()?;
    (port != 0 || !ip.is_unspecified()).then_some(SocketAddr::new(ip, port))
}

/// An IP address in the tables' hex: 32-bit words, each printed in the host's byte order.
fn hex_ip(hex: &str) -> Option<IpAddr> {
    if hex.len() != 8 && hex.len() != 32 {
        return None;
    }
    let mut bytes = Vec::with_capacity(16);
    for word in hex.as_bytes().chunks(8) {
        let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    Some(match <[u8; 16]>::try_from(bytes.as_slice()) {
        Ok(v6) => {
            let v6 = Ipv6Addr::from(v6);
            // A socket that takes both families shows its IPv4 peers mapped.
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        Err(_) => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
    })
}

/// The path a line of the unix table ends with: a file, or `@` and an abstract name. The path
/// follows the inode after one space and may hold spaces itself.
fn unix_path(line: &str) -> Option<String> {
    let mut rest = line;
    for _ in 0..7 {
        rest = rest.trim_start_matches(' ');
        rest = &rest[rest.find(' ').unwrap_or(rest.len())..];
    }
    rest.strip_prefix(' ')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::sys::proc::Sleeper;

    fn me() -> i32 {
        i32::try_from(std::process::id()).unwrap()
    }

    #[test]
    fn processes_share_the_network_namespace_they_start_in() {
        assert_eq!(namespace_inode("net:[4026531840]"), Some(4_026_531_840));
        assert_eq!(namespace_inode("net:[x]"), None);
        assert_eq!(namespace_inode("/dev/null"), None);
        let sleeper = Sleeper::start("iotap-netns-sleeper");
        assert_eq!(netns(sleeper.pid()), netns(me()));
        assert_eq!(netns(i32::MAX), None);
    }

    #[test]
    fn finds_own_process() {
        let own = info(me()).expect("own process info");
        assert!(!own.name.is_empty());
        assert!(own.start.0 > 0);
        assert_eq!(own.parent, std::os::unix::process::parent_id().cast_signed());
        assert!(list_pids().contains(&me()));
        assert!(exe_path(me()).is_some_and(|p| p.starts_with('/')));
        assert!(cwd(me()).is_some_and(|p| p.starts_with('/')));
        assert_eq!(arg0(me()), std::env::args().next());
        assert!(netns(me()).is_some());
        assert_eq!(info(-5), None);
        assert_eq!(info(i32::MAX), None);
        assert_eq!(arg0(i32::MAX), None);
    }

    #[test]
    fn reads_the_first_argument_another_process_was_started_with() {
        let sleeper = Sleeper::start("iotap-named-by-arg0");
        assert_eq!(arg0(sleeper.pid()).as_deref(), Some("iotap-named-by-arg0"));
        // The kernel names it after the file it runs.
        let name = info(sleeper.pid()).map(|info| info.name);
        assert_eq!(name.as_deref(), Some("sleep"));
    }

    #[test]
    fn a_thread_is_not_a_process() {
        let (started, wait) = mpsc::channel();
        let (finish, finished) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            started.send(()).unwrap();
            let _ = finished.recv();
        });
        wait.recv().unwrap();
        let other: Vec<i32> = fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|task| task.ok()?.file_name().to_str()?.parse().ok())
            .filter(|&tid| tid != me())
            .collect();
        assert!(!other.is_empty());
        for tid in other {
            assert_eq!(info(tid), None, "thread {tid}");
        }
        finish.send(()).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn a_zombie_is_gone() {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        // Until it is reaped, the child stays behind as a zombie.
        let deadline = Instant::now() + Duration::from_secs(5);
        while info(pid).is_some() {
            assert!(Instant::now() < deadline, "the child did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        let stat = Stat::read(format!("/proc/{pid}/stat")).unwrap();
        assert_eq!(stat.state, b'Z');
        child.wait().unwrap();
    }

    #[test]
    fn reads_stat_lines() {
        let line = b"42 (a (b) c) S 1 42 42 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 3 0 12345 0 0";
        let stat = Stat::parse(line).unwrap();
        assert_eq!(
            stat,
            Stat {
                comm: "a (b) c".into(),
                state: b'S',
                parent: 1,
                flags: 4_194_560,
                start: 12_345,
            }
        );
        assert!(stat.running());
        let exiting = Stat::parse(b"42 (x) R 1 42 42 0 -1 4194564 0 0 0 0 0 0 0 0 20 0 1 0 7").unwrap();
        assert!(!exiting.running(), "PF_EXITING is set");
        let zombie = Stat::parse(b"42 (x) Z 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 7").unwrap();
        assert!(!zombie.running());
        assert_eq!(Stat::parse(b"42 (x) S 1"), None);
    }

    #[test]
    fn names_what_links_point_to() {
        assert_eq!(
            Link::parse(b"/var/log/syslog (deleted)"),
            Link::File("/var/log/syslog".into())
        );
        assert_eq!(
            Link::parse(b"socket:[5848718]"),
            Link::Socket(Socket {
                inode: 5_848_718,
                table: None
            })
        );
        assert_eq!(Link::parse(b"pipe:[5848717]"), Link::Other(FdType::Pipe));
        for (link, fd_type) in [
            (&b"anon_inode:[eventfd]"[..], FdType::Eventfd),
            (b"anon_inode:[eventpoll]", FdType::Epoll),
            (b"anon_inode:inotify", FdType::Inotify),
            (b"anon_inode:[pidfd]", FdType::Pidfd),
            (b"anon_inode:bpf-map", FdType::Bpf),
            (b"anon_inode:[io_uring]", FdType::IoUring),
            (b"anon_inode:kvm-vm", FdType::Other),
            (b"net:[4026531840]", FdType::Other),
        ] {
            assert_eq!(Link::parse(link), Link::Other(fd_type), "{link:?}");
        }
    }

    #[test]
    fn protocol_names_lead_to_their_tables() {
        let table = |name| table_of(name).map(|index| TABLES[index].0);
        for (name, listed) in [
            ("TCP", "tcp"),
            ("TCPv6", "tcp6"),
            ("UDPv6", "udp6"),
            ("UNIX", "unix"),
            ("UNIX-STREAM", "unix"),
            ("NETLINK", "netlink"),
            ("PINGv6", "icmp6"),
            ("RAW", "raw"),
            ("PACKET", "packet"),
        ] {
            assert_eq!(table(name), Some(listed), "{name}");
        }
        for unlisted in ["MPTCP", "AF_VSOCK", "UDP-Lite", "tcp"] {
            assert_eq!(table(unlisted), None, "{unlisted}");
        }
    }

    #[test]
    fn reads_socket_table_lines() {
        let tcp = "   1: 0100007F:0CEA 0200007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 5497196 1 0000000000000000 100 0 0 10 0";
        let (inode, ep) = Layout::Inet(Proto::Tcp).parse(tcp).unwrap();
        assert_eq!(inode, 5_497_196);
        assert_eq!(ep.local, Some("127.0.0.1:3306".parse().unwrap()));
        assert_eq!(ep.remote, Some("127.0.0.2:443".parse().unwrap()));
        let listening = "   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5731539 1 0000000000000000 100 0 0 10 0";
        let (_, ep) = Layout::Inet(Proto::Tcp).parse(listening).unwrap();
        assert_eq!((ep.local, ep.remote), (Some("[::1]:631".parse().unwrap()), None));
        let mapped = "   0: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1 0000000000000000 100 0 0 10 0";
        let (_, ep) = Layout::Inet(Proto::Tcp).parse(mapped).unwrap();
        assert_eq!(ep.local, Some("127.0.0.1:80".parse().unwrap()));

        let unix = "0000000000000000: 00000002 00000000 00010000 0001 01   123 /run/my app.sock";
        let (inode, ep) = Layout::Unix.parse(unix).unwrap();
        assert_eq!((inode, ep.path.as_deref()), (123, Some("/run/my app.sock")));
        let unnamed = "0000000000000000: 00000002 00000000 00000000 0001 03 5621286";
        assert_eq!(Layout::Unix.parse(unnamed).unwrap().1.path, None);
        let named = "0000000000000000: 00000002 00000000 00000000 0001 03 9 @bus@x";
        assert_eq!(
            Layout::Unix.parse(named).unwrap().1.path.as_deref(),
            Some("@bus@x")
        );

        let netlink =
            "0000000000000000 0   2245268514 00000000 0        0        0     2        0        23066";
        let (inode, ep) = Layout::Netlink.parse(netlink).unwrap();
        assert_eq!((inode, ep.proto), (23_066, Proto::Netlink));
        let raw = "  112: 00000000000000000000000000000000:003A 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 40379 2 0000000000000000 0";
        let (inode, ep) = Layout::Raw.parse(raw).unwrap();
        assert_eq!((inode, ep.proto, ep.local), (40_379, Proto::Icmp, None));
        assert_eq!(Layout::Inet(Proto::Tcp).parse("  sl  local_address"), None);
    }

    #[test]
    fn resolves_file_descriptors() {
        let dir = std::env::temp_dir().join(format!("iotap-proc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        let file = File::create(&path).unwrap();
        let fd = file.as_raw_fd();
        let expected = Target::File {
            path: fs::canonicalize(&path).unwrap().to_string_lossy().into_owned(),
        };
        assert_eq!(fd_target(me(), fd), Some(expected.clone()));
        assert!(fds(me()).unwrap().contains(&(fd, expected.clone())));
        fs::remove_file(&path).unwrap();
        assert!(
            matches!(fd_target(me(), fd), Some(Target::File { path: p }) if p.ends_with("/data.bin")),
            "an unlinked file keeps its name"
        );
        drop(file);
        // A test running alongside may be given the number at once, but never for this file.
        assert_ne!(fd_target(me(), fd), Some(expected));
        fs::remove_dir_all(&dir).unwrap();

        let (read_end, _write_end) = io::pipe().unwrap();
        assert_eq!(
            fd_target(me(), read_end.as_raw_fd()),
            Some(Target::Other {
                fd_type: FdType::Pipe
            })
        );
    }

    #[test]
    fn resolves_sockets() {
        let socket = |fd| match fd_target(me(), fd) {
            Some(Target::Socket(endpoint)) => endpoint,
            other => panic!("{other:?}"),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let ep = socket(client.as_raw_fd());
        assert_eq!(ep.proto, Proto::Tcp);
        assert_eq!(ep.remote, Some(SocketAddr::from(([127, 0, 0, 1], port))));
        assert_eq!(ep.local, Some(client.local_addr().unwrap()));
        let listening = socket(listener.as_raw_fd());
        assert_eq!(
            (listening.local, listening.remote),
            (Some(listener.local_addr().unwrap()), None)
        );

        let udp = UdpSocket::bind("[::1]:0").unwrap();
        let ep = socket(udp.as_raw_fd());
        assert_eq!(
            (ep.proto, ep.local),
            (Proto::Udp, Some(udp.local_addr().unwrap()))
        );

        let sock_path = std::env::temp_dir().join(format!("iotap-{}.sock", std::process::id()));
        let _ = fs::remove_file(&sock_path);
        let unix = UnixListener::bind(&sock_path).unwrap();
        let ep = socket(unix.as_raw_fd());
        assert_eq!(ep.proto, Proto::Unix);
        assert_eq!(ep.path.as_deref(), sock_path.to_str());
        fs::remove_file(&sock_path).unwrap();

        // Both ends of a pair are unnamed; every socket shows up in one snapshot.
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(socket(a.as_raw_fd()).path, None);
        assert_eq!(socket(a.as_raw_fd()).proto, Proto::Unix);
        let all = fds(me()).unwrap();
        for fd in [client.as_raw_fd(), udp.as_raw_fd(), b.as_raw_fd()] {
            assert!(
                all.iter()
                    .any(|(open, target)| *open == fd && matches!(target, Target::Socket(_))),
                "fd {fd}"
            );
        }
    }

    #[test]
    fn sockets_are_looked_for_in_the_table_of_their_protocol() {
        let socket_of = |fd: i32| match fd_link(Path::new(&format!("/proc/self/fd/{fd}"))) {
            Some(Link::Socket(socket)) => socket.table.map(|index| TABLES[index].0),
            other => panic!("{other:?}"),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("[::1]:0").unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(socket_of(listener.as_raw_fd()), Some("tcp"));
        assert_eq!(socket_of(udp.as_raw_fd()), Some("udp6"));
        assert_eq!(socket_of(a.as_raw_fd()), Some("unix"));

        // A TCP socket neither bound nor connected is in no table, but its protocol is known.
        // SAFETY: `socket` has no preconditions, and the descriptor it returns is owned here.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(raw >= 0);
        // SAFETY: `raw` is an open descriptor that nothing else owns.
        let unbound = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(
            fd_target(me(), unbound.as_raw_fd()),
            Some(Target::Socket(Endpoint::unresolved(Proto::Tcp)))
        );
    }
}
