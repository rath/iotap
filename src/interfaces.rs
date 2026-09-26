//! Which network interface a socket's traffic goes over.
//!
//! The kernel's records do not say, so iotap tells from the socket's addresses and the host's
//! interfaces: traffic to an address of the host itself goes over the loopback interface, and
//! other traffic over the interface that holds the socket's local address. The host's interfaces
//! come from the process source, which records its answers, so which interface an event names
//! depends only on the trace and those answers.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::{Endpoint, Proto, Target, Via};

/// A network interface of the host and the addresses it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    /// The kernel's index of the interface, which scoped IPv6 addresses name; 0 when unknown.
    #[serde(default)]
    pub index: u32,
    pub loopback: bool,
    /// Its IPv4 and IPv6 addresses, as the system gave them.
    pub addrs: Vec<IpAddr>,
}

/// The host's interfaces at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub interfaces: Vec<Interface>,
    /// The network namespace of iotap, which the interfaces belong to; Linux only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns: Option<u64>,
}

/// `ip` as the table compares it, and the interface index it names, if any: an IPv4-mapped IPv6
/// address as IPv4, and a link-local IPv6 address without the index that macOS keeps in its
/// second group of 16 bits.
pub fn canonical(ip: IpAddr) -> (IpAddr, Option<u32>) {
    match ip.to_canonical() {
        IpAddr::V6(v6) if v6.is_unicast_link_local() => {
            let mut groups = v6.segments();
            let index = std::mem::take(&mut groups[1]);
            (
                IpAddr::V6(Ipv6Addr::from(groups)),
                (index != 0).then_some(u32::from(index)),
            )
        }
        ip => (ip, None),
    }
}

/// The host's interfaces as last listed, and when to list them again.
#[derive(Clone, Debug)]
pub struct Table {
    /// Every interface's name, in the order listed.
    names: Vec<Arc<str>>,
    /// The interface that holds each address; `None` for an address that several hold.
    by_addr: HashMap<IpAddr, Option<Arc<str>>>,
    by_index: HashMap<u32, Arc<str>>,
    loopback: Option<Arc<str>>,
    netns: Option<u64>,
    /// Trace time before which no listing is asked for.
    next_listing: u64,
    /// Local addresses that no listing held, by the trace time after which a socket using one
    /// may ask for a listing again.
    missing: HashMap<IpAddr, u64>,
    /// Least trace time between two listings.
    retry: u64,
    /// Least trace time between two listings asked for by the same missing address.
    recheck: u64,
}

impl Table {
    /// A table of `listing`, which was taken at trace time `at`. Listings follow at least `retry`
    /// ticks apart, and at least 60 times that apart for the same missing address.
    pub fn new(listing: Listing, at: u64, retry: u64) -> Self {
        let mut table = Self {
            names: Vec::new(),
            by_addr: HashMap::new(),
            by_index: HashMap::new(),
            loopback: None,
            netns: None,
            next_listing: 0,
            missing: HashMap::new(),
            retry,
            recheck: retry.saturating_mul(60),
        };
        table.update(listing, at);
        table
    }

    /// Takes in `listing`, taken at trace time `at`. An empty listing after one that was not
    /// empty, as when the system failed to answer, leaves the table as it was.
    pub fn update(&mut self, listing: Listing, at: u64) {
        self.next_listing = at.saturating_add(self.retry);
        if listing.interfaces.is_empty() && !self.names.is_empty() {
            return;
        }
        self.names.clear();
        self.by_addr.clear();
        self.by_index.clear();
        self.loopback = None;
        self.netns = listing.netns;
        for interface in listing.interfaces {
            let name: Arc<str> = interface.name.into();
            if interface.loopback && self.loopback.is_none() {
                self.loopback = Some(name.clone());
            }
            if interface.index != 0 {
                self.by_index.insert(interface.index, name.clone());
            }
            for addr in interface.addrs {
                match self.by_addr.entry(canonical(addr).0) {
                    Entry::Vacant(entry) => {
                        entry.insert(Some(name.clone()));
                    }
                    Entry::Occupied(mut entry) => {
                        if entry.get().as_ref() != Some(&name) {
                            entry.insert(None);
                        }
                    }
                }
            }
            self.names.push(name);
        }
    }

    /// Names of the interfaces, in the order listed.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|name| &**name)
    }

    /// True when the table knows no interface, as when replaying a recording made before iotap
    /// listed them.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The interface that the traffic of `target`, a descriptor of a process in the network
    /// namespace `netns`, goes over.
    pub fn via(&self, target: &Target, netns: Option<u64>) -> Via {
        let Target::Socket(endpoint) = target else {
            return Via::NoInterface;
        };
        match endpoint.proto {
            Proto::Unix | Proto::Route | Proto::System | Proto::Netlink => Via::NoInterface,
            // A packet socket is bound to an interface iotap cannot see, and an unidentified
            // socket may be an Internet one.
            Proto::Packet | Proto::Other => Via::Unknown,
            Proto::Tcp | Proto::Udp | Proto::Icmp | Proto::Raw => {
                if self.elsewhere(netns) {
                    return Via::Unknown;
                }
                self.interface_of(endpoint).map_or(Via::Unknown, Via::Interface)
            }
        }
    }

    /// True when a listing taken at trace time `ts` could name the interface of `endpoint`,
    /// which no listing so far does, and it is time for another; the caller then lists the
    /// interfaces and passes them to [`Table::update`].
    pub fn wants_listing(&mut self, endpoint: &Endpoint, netns: Option<u64>, ts: u64) -> bool {
        if !endpoint.proto.has_addresses() || self.elsewhere(netns) || ts < self.next_listing {
            return false;
        }
        let Some(local) = endpoint.local else {
            return false;
        };
        let (ip, index) = canonical(local.ip());
        if ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        let known = match index.or_else(|| scope_id(local)) {
            Some(index) => self.by_index.contains_key(&index),
            None => self.by_addr.contains_key(&ip),
        };
        if known || self.missing.get(&ip).is_some_and(|&after| ts < after) {
            return false;
        }
        self.missing.insert(ip, ts.saturating_add(self.recheck));
        self.next_listing = ts.saturating_add(self.retry);
        true
    }

    /// True when a process in the network namespace `netns` is known to have other interfaces
    /// than the listed ones.
    fn elsewhere(&self, netns: Option<u64>) -> bool {
        matches!((netns, self.netns), (Some(own), Some(listed)) if own != listed)
    }

    /// The interface of an Internet socket.
    fn interface_of(&self, endpoint: &Endpoint) -> Option<Arc<str>> {
        // The host sends traffic to its own addresses over the loopback interface, whichever
        // address it comes from.
        if let Some(remote) = endpoint.remote {
            let (ip, _) = canonical(remote.ip());
            if ip.is_loopback() || self.by_addr.contains_key(&ip) {
                return self.loopback.clone();
            }
        }
        let local = endpoint.local?;
        let (ip, index) = canonical(local.ip());
        if ip.is_loopback() {
            return self.loopback.clone();
        }
        match index.or_else(|| scope_id(local)) {
            Some(index) => self.by_index.get(&index).cloned(),
            None => self.by_addr.get(&ip).cloned().flatten(),
        }
    }
}

/// The interface index of a scoped IPv6 socket address.
fn scope_id(addr: SocketAddr) -> Option<u32> {
    match addr {
        SocketAddr::V6(addr) if addr.scope_id() != 0 => Some(addr.scope_id()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV6;

    use super::*;

    const SECOND: u64 = 1_000;

    fn listing() -> Listing {
        Listing {
            interfaces: vec![
                Interface {
                    name: "lo0".into(),
                    index: 1,
                    loopback: true,
                    addrs: vec![
                        "127.0.0.1".parse().unwrap(),
                        "::1".parse().unwrap(),
                        // As macOS lists it, with the index in the second group.
                        "fe80:1::1".parse().unwrap(),
                    ],
                },
                Interface {
                    name: "en0".into(),
                    index: 4,
                    loopback: false,
                    addrs: vec![
                        "192.168.1.20".parse().unwrap(),
                        "fe80:4::1c2d:3e4f:5a6b:7c8d".parse().unwrap(),
                        "2001:db8::20".parse().unwrap(),
                    ],
                },
                Interface {
                    name: "utun3".into(),
                    index: 9,
                    loopback: false,
                    addrs: vec!["10.8.0.2".parse().unwrap(), "fe80::a".parse().unwrap()],
                },
                Interface {
                    name: "utun4".into(),
                    index: 10,
                    loopback: false,
                    addrs: vec!["fe80::a".parse().unwrap()],
                },
                Interface {
                    name: "en5".into(),
                    index: 11,
                    loopback: false,
                    addrs: Vec::new(),
                },
            ],
            netns: Some(7),
        }
    }

    fn socket(proto: Proto, local: Option<&str>, remote: Option<&str>) -> Target {
        Target::Socket(Endpoint {
            local: local.map(|addr| addr.parse().unwrap()),
            remote: remote.map(|addr| addr.parse().unwrap()),
            ..Endpoint::unresolved(proto)
        })
    }

    fn named(name: &str) -> Via {
        Via::Interface(name.into())
    }

    #[test]
    fn canonical_addresses_drop_what_varies() {
        let mapped: IpAddr = "::ffff:192.168.1.20".parse().unwrap();
        assert_eq!(canonical(mapped), ("192.168.1.20".parse().unwrap(), None));
        let embedded: IpAddr = "fe80:4::1c2d:3e4f:5a6b:7c8d".parse().unwrap();
        assert_eq!(
            canonical(embedded),
            ("fe80::1c2d:3e4f:5a6b:7c8d".parse().unwrap(), Some(4))
        );
        let plain: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(canonical(plain), (plain, None));
        let global: IpAddr = "2001:db8:4::1".parse().unwrap();
        assert_eq!(canonical(global), (global, None));
    }

    #[test]
    fn sockets_take_the_interface_of_their_local_address() {
        let table = Table::new(listing(), 0, SECOND);
        let via = |target: &Target| table.via(target, Some(7));
        let tcp = socket(Proto::Tcp, Some("192.168.1.20:61000"), Some("93.184.216.34:443"));
        assert_eq!(via(&tcp), named("en0"));
        let mapped = socket(Proto::Tcp, Some("[::ffff:192.168.1.20]:61000"), None);
        assert_eq!(via(&mapped), named("en0"));
        let v6 = socket(Proto::Udp, Some("[2001:db8::20]:5353"), Some("[2001:db8::1]:53"));
        assert_eq!(via(&v6), named("en0"));
        let vpn = socket(Proto::Tcp, Some("10.8.0.2:50000"), Some("10.8.0.1:22"));
        assert_eq!(via(&vpn), named("utun3"));
        let icmp = socket(Proto::Icmp, Some("192.168.1.20:0"), None);
        assert_eq!(via(&icmp), named("en0"));
    }

    #[test]
    fn traffic_within_the_host_goes_over_loopback() {
        let table = Table::new(listing(), 0, SECOND);
        let via = |target: &Target| table.via(target, None);
        let local = socket(Proto::Tcp, Some("127.0.0.1:50000"), Some("127.0.0.1:8000"));
        assert_eq!(via(&local), named("lo0"));
        let v6 = socket(Proto::Udp, Some("[::1]:50000"), None);
        assert_eq!(via(&v6), named("lo0"));
        // Any 127/8 address is loopback, listed or not.
        let other = socket(Proto::Udp, None, Some("127.0.0.53:53"));
        assert_eq!(via(&other), named("lo0"));
        // To the host's own address on en0, from that same address.
        let own = socket(Proto::Tcp, Some("192.168.1.20:50000"), Some("192.168.1.20:8000"));
        assert_eq!(via(&own), named("lo0"));
        let own_v6 = socket(
            Proto::Tcp,
            Some("[2001:db8::20]:50000"),
            Some("[2001:db8::20]:80"),
        );
        assert_eq!(via(&own_v6), named("lo0"));
    }

    #[test]
    fn link_local_addresses_go_by_their_index() {
        let table = Table::new(listing(), 0, SECOND);
        let via = |target: &Target| table.via(target, None);
        let embedded = socket(Proto::Udp, Some("[fe80:4::1c2d:3e4f:5a6b:7c8d]:5353"), None);
        assert_eq!(via(&embedded), named("en0"));
        // Without its index, as Linux gives it, an address only one interface holds.
        let bare = socket(Proto::Udp, Some("[fe80::1c2d:3e4f:5a6b:7c8d]:5353"), None);
        assert_eq!(via(&bare), named("en0"));
        // Two interfaces hold fe80::a; the index tells them apart.
        let shared = socket(Proto::Udp, Some("[fe80::a]:5353"), None);
        assert_eq!(via(&shared), Via::Unknown);
        let scoped = Target::Socket(Endpoint {
            local: Some(SocketAddr::V6(SocketAddrV6::new(
                "fe80::a".parse().unwrap(),
                5353,
                0,
                10,
            ))),
            ..Endpoint::unresolved(Proto::Udp)
        });
        assert_eq!(via(&scoped), named("utun4"));
        let gone = socket(Proto::Udp, Some("[fe80:63::a]:5353"), None);
        assert_eq!(via(&gone), Via::Unknown);
    }

    #[test]
    fn some_targets_have_no_interface_or_an_unknown_one() {
        let table = Table::new(listing(), 0, SECOND);
        let via = |target: &Target| table.via(target, Some(7));
        let file = Target::File {
            path: "/tmp/x".into(),
        };
        assert_eq!(via(&file), Via::NoInterface);
        assert_eq!(via(&Target::Unknown), Via::NoInterface);
        let unix = Target::Socket(Endpoint {
            path: Some("/var/run/mDNSResponder".into()),
            ..Endpoint::unresolved(Proto::Unix)
        });
        assert_eq!(via(&unix), Via::NoInterface);
        for proto in [Proto::Route, Proto::System, Proto::Netlink] {
            assert_eq!(via(&socket(proto, None, None)), Via::NoInterface);
        }
        for proto in [Proto::Packet, Proto::Other] {
            assert_eq!(via(&socket(proto, None, None)), Via::Unknown);
        }
        // Unconnected and bound to every address: each datagram may take another interface.
        let wildcard = socket(Proto::Udp, Some("0.0.0.0:5353"), None);
        assert_eq!(via(&wildcard), Via::Unknown);
        assert_eq!(via(&socket(Proto::Tcp, None, None)), Via::Unknown);
        let remote_only = socket(Proto::Udp, None, Some("8.8.8.8:53"));
        assert_eq!(via(&remote_only), Via::Unknown);
        let foreign = socket(Proto::Tcp, Some("172.17.0.2:50000"), Some("1.1.1.1:443"));
        assert_eq!(via(&foreign), Via::Unknown);
    }

    #[test]
    fn processes_in_other_network_namespaces_have_unknown_interfaces() {
        let mut table = Table::new(listing(), 0, SECOND);
        // In a container, 192.168.1.20 is the host's address, reached over the container's
        // own interface.
        let endpoint = Endpoint {
            local: Some("172.17.0.2:50000".parse().unwrap()),
            remote: Some("192.168.1.20:8000".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        };
        let to_host = Target::Socket(endpoint.clone());
        assert_eq!(table.via(&to_host, Some(8)), Via::Unknown);
        assert_eq!(table.via(&to_host, Some(7)), named("lo0"));
        // Where either namespace is unknown, as on macOS, the process shares iotap's.
        assert_eq!(table.via(&to_host, None), named("lo0"));
        // Its local address is the container's, which no listing of iotap's would hold.
        assert!(!table.wants_listing(&endpoint, Some(8), 5 * SECOND));
        assert!(table.wants_listing(&endpoint, None, 5 * SECOND));
    }

    #[test]
    fn a_missing_local_address_asks_for_a_listing_now_and_then() {
        let mut table = Table::new(listing(), 0, SECOND);
        let endpoint = |local: &str| Endpoint {
            local: Some(local.parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        };
        let new = endpoint("10.9.0.5:40000");
        // Not within a second of the last listing.
        assert!(!table.wants_listing(&new, None, SECOND - 1));
        assert!(table.wants_listing(&new, None, SECOND));
        table.update(listing(), SECOND);
        // Still missing: another address may ask a second later, this one only a minute later.
        assert!(!table.wants_listing(&new, None, 2 * SECOND));
        let other = endpoint("10.9.0.6:40000");
        assert!(!table.wants_listing(&other, None, 2 * SECOND - 1));
        assert!(table.wants_listing(&other, None, 2 * SECOND));
        table.update(listing(), 2 * SECOND);
        assert!(!table.wants_listing(&new, None, 60 * SECOND));
        assert!(table.wants_listing(&new, None, 61 * SECOND));
        // Listed, loopback and wildcard addresses, and sockets without addresses, never ask.
        for local in ["192.168.1.20:1", "127.0.0.1:1", "0.0.0.0:1", "[fe80:4::1]:1"] {
            assert!(
                !table.wants_listing(&endpoint(local), None, 100 * SECOND),
                "{local}"
            );
        }
        let unix = Endpoint::unresolved(Proto::Unix);
        assert!(!table.wants_listing(&unix, None, 100 * SECOND));
        let unbound = Endpoint::unresolved(Proto::Udp);
        assert!(!table.wants_listing(&unbound, None, 100 * SECOND));
        // An index no interface has asks too.
        assert!(table.wants_listing(&endpoint("[fe80:63::a]:1"), None, 100 * SECOND));
    }

    #[test]
    fn a_later_listing_replaces_the_table_unless_it_is_empty() {
        let mut table = Table::new(Listing::default(), 0, SECOND);
        assert!(table.is_empty());
        let tcp = socket(Proto::Tcp, Some("192.168.1.20:61000"), Some("93.184.216.34:443"));
        assert_eq!(table.via(&tcp, None), Via::Unknown);
        table.update(listing(), SECOND);
        let names: Vec<&str> = table.names().collect();
        assert_eq!(names, ["lo0", "en0", "utun3", "utun4", "en5"]);
        assert_eq!(table.via(&tcp, None), named("en0"));
        table.update(Listing::default(), 2 * SECOND);
        assert_eq!(table.via(&tcp, None), named("en0"));
        let moved = Listing {
            interfaces: vec![Interface {
                name: "en1".into(),
                index: 5,
                loopback: false,
                addrs: vec!["192.168.1.20".parse().unwrap()],
            }],
            netns: None,
        };
        table.update(moved, 3 * SECOND);
        assert_eq!(table.via(&tcp, None), named("en1"));
        // Without a loopback interface, traffic within the host has none to name.
        let local = socket(Proto::Tcp, Some("127.0.0.1:50000"), Some("127.0.0.1:8000"));
        assert_eq!(table.via(&local, None), Via::Unknown);
    }

    #[test]
    fn listings_round_trip_through_json() {
        let listing = listing();
        let json = serde_json::to_string(&listing).unwrap();
        assert_eq!(serde_json::from_str::<Listing>(&json).unwrap(), listing);
        let bare: Listing =
            serde_json::from_str(r#"{"interfaces":[{"name":"lo","loopback":true,"addrs":[]}]}"#).unwrap();
        assert_eq!(bare.netns, None);
        assert_eq!(bare.interfaces[0].index, 0);
    }
}
