//! Process facts from libproc, the C shim and the `kern.procargs2` sysctl: process listing,
//! first arguments, descriptor tables and what a descriptor refers to.

use std::ffi::{c_char, c_int};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;
use std::sync::OnceLock;

use super::ProcInfo;
use crate::model::{Endpoint, FdType, Proto, Target};

const PROC_ALL_PIDS: u32 = 1;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const SOCKINFO_UN: i32 = 3;
/// `MAXPATHLEN`.
const PATH_BUF: usize = 1024;
/// `sun_path` plus a terminator; matches `IOTAP_PATH_LEN` in the shim.
const SUN_PATH_BUF: usize = 105;

/// Mirror of `struct iotap_sock` in `csrc/iotap_shim.c`.
#[repr(C)]
struct IotapSock {
    family: i32,
    sock_type: i32,
    protocol: i32,
    kind: i32,
    tcp_state: i32,
    is_v4: i32,
    lport: u16,
    rport: u16,
    laddr: [u8; 16],
    raddr: [u8; 16],
    local_path: [u8; SUN_PATH_BUF],
    peer_path: [u8; SUN_PATH_BUF],
}

impl IotapSock {
    fn zeroed() -> Self {
        Self {
            family: 0,
            sock_type: 0,
            protocol: 0,
            kind: 0,
            tcp_state: -1,
            is_v4: 0,
            lport: 0,
            rport: 0,
            laddr: [0; 16],
            raddr: [0; 16],
            local_path: [0; SUN_PATH_BUF],
            peer_path: [0; SUN_PATH_BUF],
        }
    }
}

unsafe extern "C" {
    #[cfg(test)]
    safe fn iotap_sock_size() -> usize;
    fn iotap_fd_path(pid: c_int, fd: c_int, buf: *mut c_char, len: usize) -> c_int;
    fn iotap_fd_socket(pid: c_int, fd: c_int, out: *mut IotapSock) -> c_int;
    fn iotap_proc_cwd(pid: c_int, buf: *mut c_char, len: usize) -> c_int;
}

/// Pids of every process on the system.
pub fn list_pids() -> Vec<i32> {
    // SAFETY: a null buffer asks for the size the list needs.
    let needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
    let Ok(needed) = usize::try_from(needed) else {
        return Vec::new();
    };
    // Leave room for processes started between the two calls.
    let mut pids = vec![0i32; needed / size_of::<i32>() + 256];
    let bytes = c_int::try_from(pids.len() * size_of::<i32>()).unwrap_or(c_int::MAX);
    // SAFETY: `pids` provides `bytes` writable bytes.
    let got = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), bytes) };
    let count = usize::try_from(got).unwrap_or(0) / size_of::<i32>();
    pids.truncate(count.min(pids.len()));
    pids.retain(|&pid| pid > 0);
    pids
}

/// Name and start time of a live process; `None` once it has exited, zombies included.
pub fn info(pid: i32) -> Option<ProcInfo> {
    // SAFETY: `proc_bsdinfo` is plain data for which all-zero bytes are a valid value.
    let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `bsd` is a writable buffer of `size` bytes. With arg 0 the kernel does not
    // report zombies.
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut bsd).cast(), size) };
    if n != size {
        return None;
    }
    let mut name = c_chars(&bsd.pbi_name);
    if name.is_empty() {
        name = c_chars(&bsd.pbi_comm);
    }
    Some(ProcInfo {
        pid,
        name,
        start: (bsd.pbi_start_tvsec, bsd.pbi_start_tvusec),
        parent: bsd.pbi_ppid.cast_signed(),
    })
}

/// Path of the executable a process runs.
pub fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).unwrap_or(4096)];
    let len = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` provides `len` writable bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), len) };
    let n = usize::try_from(n).ok().filter(|&n| n > 0)?;
    buf.truncate(n.min(buf.len()));
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// `argv[0]` of a process as its memory holds it now, which the process may have rewritten;
/// `None` if the process is gone, was started without arguments, or belongs to another user
/// while iotap is not root.
pub fn arg0(pid: i32) -> Option<String> {
    // Into a buffer too small for all of it the kernel copies the end of the area, so the buffer
    // takes the most a process can be started with, after the count of arguments.
    let mut area = vec![0u8; size_of::<c_int>() + args_max()?];
    let mut len = area.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `mib` holds the 3 integers passed, and `area` provides `len` writable bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            area.as_mut_ptr().cast(),
            &raw mut len,
            ptr::null_mut(),
            0,
        )
    };
    // A full buffer may hold only the end of the area.
    if rc != 0 || len >= area.len() {
        return None;
    }
    first_argument(&area[..len])
}

/// The most bytes of arguments and environment a process can be started with, `kern.argmax`.
fn args_max() -> Option<usize> {
    static MAX: OnceLock<Option<usize>> = OnceLock::new();
    *MAX.get_or_init(|| {
        let mut max: c_int = 0;
        let mut len = size_of::<c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        // SAFETY: `mib` holds the 2 integers passed, and `max` provides the `len` bytes of the
        // integer the sysctl gives.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&raw mut max).cast(),
                &raw mut len,
                ptr::null_mut(),
                0,
            )
        };
        usize::try_from(max).ok().filter(|&max| rc == 0 && max > 0)
    })
}

/// `argv[0]` in an area as `kern.procargs2` gives it: the count of arguments, the executable's
/// path, the NULs that pad it, then the arguments, each ending in a NUL. An empty `argv[0]`
/// cannot be told from the padding, so the argument after it is taken for it.
fn first_argument(area: &[u8]) -> Option<String> {
    let (argc, strings) = area.split_first_chunk::<{ size_of::<c_int>() }>()?;
    // Without arguments, what follows the path is the environment.
    if c_int::from_ne_bytes(*argc) < 1 {
        return None;
    }
    let path_end = strings.iter().position(|&b| b == 0)?;
    let padded = &strings[path_end..];
    let start = padded.iter().position(|&b| b != 0)?;
    Some(nul_terminated(&padded[start..]))
}

/// Open descriptors of a process and what each refers to; `None` if the process is gone.
pub fn fds(pid: i32) -> Option<Vec<(i32, Target)>> {
    let fds = list_fds(pid)?
        .into_iter()
        .filter_map(|(fd, fd_type)| describe_typed(pid, fd, fd_type).map(|target| (fd, target)))
        .collect();
    Some(fds)
}

/// What `fd` of `pid` refers to now; `None` if it is not open.
pub fn fd_target(pid: i32, fd: i32) -> Option<Target> {
    // Files and sockets answer directly; anything else needs the typed listing.
    if let Ok(path) = fd_path(pid, fd) {
        return Some(Target::File { path });
    }
    if let Ok(endpoint) = fd_socket(pid, fd) {
        return Some(Target::Socket(endpoint));
    }
    let (_, fd_type) = list_fds(pid)?.into_iter().find(|&(open, _)| open == fd)?;
    describe_typed(pid, fd, fd_type)
}

fn describe_typed(pid: i32, fd: i32, fd_type: u32) -> Option<Target> {
    match i32::try_from(fd_type) {
        Ok(libc::PROX_FDTYPE_VNODE) => fd_path(pid, fd).ok().map(|path| Target::File { path }),
        Ok(libc::PROX_FDTYPE_SOCKET) => fd_socket(pid, fd).ok().map(Target::Socket),
        _ => Some(Target::Other {
            fd_type: other_type(fd_type),
        }),
    }
}

/// Maps a `PROX_FDTYPE_*` value other than a vnode or a socket.
fn other_type(fd_type: u32) -> FdType {
    match i32::try_from(fd_type).unwrap_or(-1) {
        libc::PROX_FDTYPE_PIPE => FdType::Pipe,
        libc::PROX_FDTYPE_KQUEUE => FdType::Kqueue,
        libc::PROX_FDTYPE_PSHM => FdType::Pshm,
        libc::PROX_FDTYPE_PSEM => FdType::Psem,
        libc::PROX_FDTYPE_FSEVENTS => FdType::Fsevents,
        libc::PROX_FDTYPE_NETPOLICY => FdType::Netpolicy,
        libc::PROX_FDTYPE_CHANNEL => FdType::Channel,
        libc::PROX_FDTYPE_NEXUS => FdType::Nexus,
        libc::PROX_FDTYPE_ATALK => FdType::Atalk,
        _ => FdType::Other,
    }
}

/// Open descriptors of a process as (fd, `PROX_FDTYPE_*`) pairs.
fn list_fds(pid: i32) -> Option<Vec<(i32, u32)>> {
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer asks for the size the table needs.
    let needed = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
    let mut capacity = usize::try_from(needed).ok()? / entry + 32;
    loop {
        let mut fds = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            capacity
        ];
        let bytes = c_int::try_from(capacity * entry).ok()?;
        // SAFETY: `fds` provides `bytes` writable bytes.
        let got =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), bytes) };
        let count = usize::try_from(got).ok().filter(|&n| n > 0)? / entry;
        if count < capacity {
            fds.truncate(count);
            return Some(fds.iter().map(|f| (f.proc_fd, f.proc_fdtype)).collect());
        }
        // The table may have grown between the calls; retry with more room.
        capacity *= 2;
    }
}

/// Path of the vnode behind `fd`; fails with an errno if `fd` is not an open vnode.
fn fd_path(pid: i32, fd: i32) -> Result<String, i32> {
    let mut buf = vec![0u8; PATH_BUF];
    // SAFETY: `buf` provides `PATH_BUF` writable bytes; the shim always terminates it.
    let rc = unsafe { iotap_fd_path(pid, fd, buf.as_mut_ptr().cast(), buf.len()) };
    if rc == 0 {
        Ok(nul_terminated(&buf))
    } else {
        Err(rc)
    }
}

/// Endpoint of the socket behind `fd`; fails with an errno if `fd` is not an open socket.
fn fd_socket(pid: i32, fd: i32) -> Result<Endpoint, i32> {
    let mut sock = IotapSock::zeroed();
    // SAFETY: `sock` is a writable `struct iotap_sock` (layout checked by a test).
    let rc = unsafe { iotap_fd_socket(pid, fd, &raw mut sock) };
    if rc == 0 { Ok(endpoint(&sock)) } else { Err(rc) }
}

/// Current working directory of a process.
pub fn cwd(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; PATH_BUF];
    // SAFETY: `buf` provides `PATH_BUF` writable bytes; the shim always terminates it.
    let rc = unsafe { iotap_proc_cwd(pid, buf.as_mut_ptr().cast(), buf.len()) };
    let path = nul_terminated(&buf);
    (rc == 0 && !path.is_empty()).then_some(path)
}

/// The network namespace of a process: none, as macOS has none.
pub fn netns(_pid: i32) -> Option<u64> {
    None
}

fn endpoint(sock: &IotapSock) -> Endpoint {
    let mut out = Endpoint::unresolved(Proto::classify(sock.family, sock.sock_type, sock.protocol));
    match sock.kind {
        SOCKINFO_IN | SOCKINFO_TCP => {
            let addr = |bytes: &[u8; 16]| -> IpAddr {
                if sock.is_v4 != 0 {
                    IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
                } else {
                    IpAddr::V6(Ipv6Addr::from(*bytes))
                }
            };
            let known = |ip: IpAddr, port: u16| {
                (port != 0 || !ip.is_unspecified()).then_some(SocketAddr::new(ip, port))
            };
            out.local = known(addr(&sock.laddr), sock.lport);
            out.remote = known(addr(&sock.raddr), sock.rport);
        }
        SOCKINFO_UN => {
            let peer = nul_terminated(&sock.peer_path);
            let local = nul_terminated(&sock.local_path);
            out.path = [peer, local].into_iter().find(|p| !p.is_empty());
        }
        _ => {}
    }
    out
}

fn nul_terminated(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn c_chars(chars: &[c_char]) -> String {
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c.cast_unsigned())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::sys::proc::Sleeper;

    fn me() -> i32 {
        i32::try_from(std::process::id()).unwrap()
    }

    #[test]
    fn shim_struct_layout_matches() {
        assert_eq!(iotap_sock_size(), size_of::<IotapSock>());
    }

    #[test]
    fn finds_own_process() {
        let own = info(me()).expect("own process info");
        assert!(!own.name.is_empty());
        assert_eq!(own.parent, std::os::unix::process::parent_id().cast_signed());
        assert!(list_pids().contains(&me()));
        assert!(exe_path(me()).is_some_and(|p| p.starts_with('/')));
        assert!(cwd(me()).is_some_and(|p| p.starts_with('/')));
        assert_eq!(arg0(me()), std::env::args().next());
        assert_eq!(info(-5), None);
        assert_eq!(arg0(-5), None);
    }

    #[test]
    fn reads_the_first_argument_another_process_was_started_with() {
        let sleeper = Sleeper::start("iotap-named-by-arg0");
        assert_eq!(arg0(sleeper.pid()).as_deref(), Some("iotap-named-by-arg0"));
        // The kernel names it after the file it runs.
        let name = info(sleeper.pid()).map(|info| info.name);
        assert_eq!(name.as_deref(), Some("sleep"));
        assert_eq!(exe_path(sleeper.pid()).as_deref(), Some("/bin/sleep"));
    }

    #[test]
    fn finds_the_first_argument_after_the_padded_path() {
        let area = |argc: c_int, strings: &[u8]| [&argc.to_ne_bytes()[..], strings].concat();
        let args = area(2, b"/bin/sleep\0\0\0\0\0\0zz\0x\0HOME=/var/root\0");
        assert_eq!(first_argument(&args).as_deref(), Some("zz"));
        // What follows the path of a process started without arguments is its environment.
        assert_eq!(first_argument(&area(0, b"/bin/sleep\0\0HOME=/var/root\0")), None);
        assert_eq!(first_argument(&area(1, b"/bin/sleep\0\0\0")), None);
        assert_eq!(first_argument(&area(1, b"/bin/sleep")), None);
        assert_eq!(first_argument(&args[..3]), None);
        // An argument that runs to the end of the area ends there.
        assert_eq!(first_argument(&area(1, b"/bin/sleep\0zz")).as_deref(), Some("zz"));
    }

    #[test]
    fn resolves_file_descriptors() {
        let dir = std::env::temp_dir().join(format!("iotap-proc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        let file = File::create(&path).unwrap();
        let fd = file.as_raw_fd();
        let expected = std::fs::canonicalize(&path).unwrap();
        assert_eq!(fd_path(me(), fd).unwrap(), expected.to_string_lossy());
        assert!(list_fds(me()).unwrap().contains(&(fd, 1)));
        assert!(fd_socket(me(), fd).is_err());
        drop(file);
        // A test running alongside may be given the number at once, but never for this file.
        match fd_path(me(), fd) {
            Ok(path) => assert_ne!(path, expected.to_string_lossy()),
            Err(errno) => assert_ne!(errno, 0),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolves_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let ep = fd_socket(me(), client.as_raw_fd()).unwrap();
        assert_eq!(ep.proto, Proto::Tcp);
        assert_eq!(ep.remote, Some(SocketAddr::from(([127, 0, 0, 1], port))));
        assert_eq!(ep.local, Some(client.local_addr().unwrap()));
        let listening = fd_socket(me(), listener.as_raw_fd()).unwrap();
        assert_eq!(
            (listening.local, listening.remote),
            (Some(listener.local_addr().unwrap()), None)
        );

        // A socket on both IP versions, as one bound to :: is unless it asks for IPv6 alone,
        // has both flags set and an IPv6 address.
        let dual = TcpListener::bind("[::]:0").unwrap();
        let ep = fd_socket(me(), dual.as_raw_fd()).unwrap();
        assert_eq!(ep.local, Some(dual.local_addr().unwrap()));
        // A connection it accepts from an IPv4 client is on IPv4 alone, where std writes the
        // address as one mapped into IPv6.
        let dual_port = dual.local_addr().unwrap().port();
        let peer = TcpStream::connect(("127.0.0.1", dual_port)).unwrap();
        let (accepted, _) = dual.accept().unwrap();
        let ep = fd_socket(me(), accepted.as_raw_fd()).unwrap();
        assert_eq!(
            (ep.local, ep.remote),
            (
                Some(SocketAddr::from(([127, 0, 0, 1], dual_port))),
                Some(peer.local_addr().unwrap())
            )
        );

        let udp = UdpSocket::bind("[::1]:0").unwrap();
        let ep = fd_socket(me(), udp.as_raw_fd()).unwrap();
        assert_eq!(
            (ep.proto, ep.local),
            (Proto::Udp, Some(udp.local_addr().unwrap()))
        );

        let sock_path = std::env::temp_dir().join(format!("iotap-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let unix = UnixListener::bind(&sock_path).unwrap();
        let ep = fd_socket(me(), unix.as_raw_fd()).unwrap();
        assert_eq!(ep.proto, Proto::Unix);
        let bound = ep.path.expect("bound unix path");
        assert!(
            bound.ends_with(&format!("iotap-{}.sock", std::process::id())),
            "{bound}"
        );
        std::fs::remove_file(&sock_path).unwrap();
    }
}
