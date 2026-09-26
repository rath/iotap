//! The host's network interfaces and their addresses, from `getifaddrs`.

use std::ffi::{CStr, CString, c_uint};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::interfaces::Interface;

/// Lists the host's network interfaces, in the order the system gives them, with their IPv4
/// and IPv6 addresses as it gives them. Interfaces without an address are listed too.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a live local, which the call points at a list it allocates.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let list = List(head);
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut entry = list.0;
    while !entry.is_null() {
        // SAFETY: `entry` is a non-null element of the list, which `list` frees only when it is
        // dropped, after this loop.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a non-null name is a NUL-terminated string within the list.
        let name = interface_name(unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes());
        let at = interfaces
            .iter()
            .position(|known| known.name == name)
            .unwrap_or_else(|| {
                interfaces.push(Interface {
                    index: index_of(&name),
                    name,
                    loopback: false,
                    addrs: Vec::new(),
                });
                interfaces.len() - 1
            });
        let interface = &mut interfaces[at];
        interface.loopback |= ifa.ifa_flags & libc::IFF_LOOPBACK as c_uint != 0;
        // SAFETY: a non-null address of the list is whole for its family.
        if let Some(addr) = unsafe { ip_address(ifa.ifa_addr) }
            && !interface.addrs.contains(&addr)
        {
            interface.addrs.push(addr);
        }
    }
    Ok(interfaces)
}

/// The list `getifaddrs` returned, freed when dropped.
struct List(*mut libc::ifaddrs);

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful `getifaddrs` and is freed only here.
        unsafe { libc::freeifaddrs(self.0) }
    }
}

/// The interface an entry's name belongs to. On Linux the C library names each further IPv4
/// address of an interface by its label, such as `eth0:1`, and a name cannot hold a colon.
fn interface_name(bytes: &[u8]) -> String {
    let name = String::from_utf8_lossy(bytes);
    #[cfg(target_os = "linux")]
    let name = match name.split_once(':') {
        Some((base, _)) => base.into(),
        None => name,
    };
    name.into_owned()
}

/// The kernel's index of the interface `name`; 0 when it has none by now.
fn index_of(name: &str) -> u32 {
    let Ok(name) = CString::new(name) else {
        return 0;
    };
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// The IPv4 or IPv6 address at `addr`, if it holds one.
///
/// # Safety
///
/// `addr` must be null or point to a socket address that is whole for its family.
unsafe fn ip_address(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a whole socket address, and each starts with its family.
    match i32::from(unsafe { (*addr).sa_family }) {
        libc::AF_INET => {
            // SAFETY: an AF_INET address is a whole `sockaddr_in`, perhaps not aligned for one.
            let sin = unsafe { addr.cast::<libc::sockaddr_in>().read_unaligned() };
            Some(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())))
        }
        libc::AF_INET6 => {
            // SAFETY: an AF_INET6 address is a whole `sockaddr_in6`, perhaps not aligned for one.
            let sin6 = unsafe { addr.cast::<libc::sockaddr_in6>().read_unaligned() };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_the_loopback_interface_and_its_addresses() {
        let interfaces = interfaces().unwrap();
        let loopback = interfaces
            .iter()
            .find(|interface| interface.loopback)
            .expect("a loopback interface");
        assert!(
            loopback.addrs.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{loopback:?}"
        );
        assert!(loopback.index > 0, "{loopback:?}");
        for (i, interface) in interfaces.iter().enumerate() {
            assert!(!interface.name.is_empty());
            assert!(!interface.name.contains(':'), "{interface:?}");
            assert!(
                interfaces[i + 1..]
                    .iter()
                    .all(|other| other.name != interface.name),
                "{} listed twice",
                interface.name
            );
        }
    }

    #[test]
    fn names_lose_the_label_of_an_address() {
        assert_eq!(interface_name(b"en0"), "en0");
        #[cfg(target_os = "linux")]
        assert_eq!(interface_name(b"eth0:1"), "eth0");
        assert_eq!(index_of("no-such-interface"), 0);
        assert_eq!(index_of("nul\0inside"), 0);
    }
}
