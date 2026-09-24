//! Safe wrappers over libproc: process listing, descriptor tables and what a descriptor
//! refers to.

use std::ffi::{c_char, c_int};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;

use crate::model::{Endpoint, Proto};

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

/// Facts that identify a running process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub name: String,
    /// Start time as (seconds, microseconds); tells a process apart from a later one that
    /// reuses its pid.
    pub start: (u64, u64),
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

/// Open descriptors of a process as (fd, `PROX_FDTYPE_*`) pairs.
pub fn list_fds(pid: i32) -> Option<Vec<(i32, u32)>> {
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
pub fn fd_path(pid: i32, fd: i32) -> Result<String, i32> {
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
pub fn fd_socket(pid: i32, fd: i32) -> Result<Endpoint, i32> {
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
        assert!(list_pids().contains(&me()));
        assert!(exe_path(me()).is_some_and(|p| p.starts_with('/')));
        assert!(cwd(me()).is_some_and(|p| p.starts_with('/')));
        assert_eq!(info(-5), None);
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
        assert!(fd_path(me(), fd).is_err_and(|e| e != 0));
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
