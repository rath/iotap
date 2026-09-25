//! Host names of IP addresses, from the system's resolver (reverse DNS).

use std::ffi::{CStr, c_int};
use std::io;
use std::net::IpAddr;

/// Room for the longest host name `getnameinfo` writes, with its NUL.
const HOST_BYTES: usize = libc::NI_MAXHOST as usize;

/// Asks the system's resolver for the name of the host at `addr`, from the hosts file, DNS or
/// multicast DNS, as the system is set up to look. Blocks for as long as the resolver takes,
/// which can be half a minute. `Ok(None)` means the resolver knows no name for the address.
///
/// Control characters in the name are replaced by `?`: the name comes from whoever runs the
/// address's DNS, and it is shown on a terminal.
pub fn host_name(addr: IpAddr) -> Result<Option<String>, String> {
    let mut host = [0_u8; HOST_BYTES];
    let rc = match addr {
        IpAddr::V4(ip) => {
            // SAFETY: `sockaddr_in` is plain data; all-zero is a valid value.
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
            }
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            name_info(&sin, &mut host)
        }
        IpAddr::V6(ip) => {
            // SAFETY: `sockaddr_in6` is plain data; all-zero is a valid value.
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            #[cfg(target_os = "macos")]
            {
                sin6.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            }
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = ip.octets();
            name_info(&sin6, &mut host)
        }
    };
    match rc {
        0 => {
            let name = CStr::from_bytes_until_nul(&host).map_err(|_| "the resolver's answer has no end")?;
            Ok(Some(printable(name.to_bytes())).filter(|name| !name.is_empty()))
        }
        libc::EAI_NONAME => Ok(None),
        libc::EAI_SYSTEM => Err(io::Error::last_os_error().to_string()),
        code => Err(error_text(code)),
    }
}

/// The socket address structures `getnameinfo` takes, which it reads whole.
trait SocketAddress {}

impl SocketAddress for libc::sockaddr_in {}
impl SocketAddress for libc::sockaddr_in6 {}

/// Asks for the host name of `addr` without a service name, writing it into `host`.
fn name_info<T: SocketAddress>(addr: &T, host: &mut [u8]) -> c_int {
    // SAFETY: `addr` is a whole socket address of `size_of::<T>()` bytes whose family matches
    // its type, and `host` has `host.len()` writable bytes. No service name is asked for, so
    // the null buffer of length 0 is never written.
    unsafe {
        libc::getnameinfo(
            (&raw const *addr).cast(),
            size_of::<T>() as libc::socklen_t,
            host.as_mut_ptr().cast(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    }
}

/// The resolver's description of its error `code`.
fn error_text(code: c_int) -> String {
    // SAFETY: `gai_strerror` has no preconditions; it returns null or a pointer to a static
    // NUL-terminated string.
    let text = unsafe { libc::gai_strerror(code) };
    if text.is_null() {
        return format!("resolver error {code}");
    }
    // SAFETY: `text` is a non-null pointer to a static NUL-terminated string.
    unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned()
}

/// `bytes` as text, with invalid UTF-8 replaced and each control character written as `?`.
fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn names_the_loopback_address() {
        // Every system's hosts file names it, so no DNS server is asked.
        assert_eq!(
            host_name(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Ok(Some("localhost".to_owned()))
        );
    }

    #[test]
    fn writes_control_characters_as_question_marks() {
        assert_eq!(printable(b"a\x1b[31mb\x7f.example"), "a?[31mb?.example");
        assert_eq!(printable(b"\xff.example"), "\u{fffd}.example");
        assert_eq!(printable(b"one.one.one.one"), "one.one.one.one");
    }
}
