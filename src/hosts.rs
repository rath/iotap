//! Host names of remote addresses, for the terminal UI and the text summary.
//!
//! The system's resolver can take half a minute to answer, so threads of their own ask it, at
//! most [`THREADS`] at once, and whoever shows names takes the answers in as they arrive,
//! showing the address until then. Nothing is looked up before a name is asked for, and each
//! address is looked up once.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::sys::dns;

/// Most lookups under way at once.
const THREADS: usize = 16;

/// What is known of the host name of an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostName {
    /// Asked for, and not answered yet.
    Pending,
    Found(String),
    /// The resolver knows no name for the address, or the address names no single host.
    None,
    /// The lookup failed, for the reason given.
    Failed(String),
}

/// Looks up the name of one address, blocking until it has the answer.
type Lookup = dyn Fn(IpAddr) -> HostName + Send + Sync;

/// The host names asked for so far, and the threads that look them up.
#[derive(Debug)]
pub struct Hosts {
    names: HashMap<IpAddr, HostName>,
    pool: Pool,
}

impl Default for Hosts {
    fn default() -> Self {
        Self::system()
    }
}

impl Hosts {
    /// Looks names up with the system's resolver.
    pub fn system() -> Self {
        Self::with_lookup(|addr| match dns::host_name(addr) {
            Ok(Some(name)) => HostName::Found(name),
            Ok(None) => HostName::None,
            Err(err) => HostName::Failed(err),
        })
    }

    /// Looks names up with `lookup`.
    pub fn with_lookup(lookup: impl Fn(IpAddr) -> HostName + Send + Sync + 'static) -> Self {
        let (queue, queued) = mpsc::channel();
        let (answer, answers) = mpsc::channel();
        Self {
            names: HashMap::new(),
            pool: Pool {
                lookup: Arc::new(lookup),
                queue,
                queued: Arc::new(Mutex::new(queued)),
                answers,
                answer,
                threads: 0,
                pending: 0,
            },
        }
    }

    /// What is known of the host name of `addr`; the first time, asks for it.
    pub fn get(&mut self, addr: IpAddr) -> &HostName {
        let addr = addr.to_canonical();
        match self.names.entry(addr) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) if names_a_host(addr) => entry.insert(self.pool.ask(addr)),
            Entry::Vacant(entry) => entry.insert(HostName::None),
        }
    }

    /// The host name of `addr`, once found; the first time, asks for it.
    pub fn name(&mut self, addr: IpAddr) -> Option<&str> {
        match self.get(addr) {
            HostName::Found(name) => Some(name),
            _ => None,
        }
    }

    /// Addresses asked about so far.
    #[cfg(test)]
    pub(crate) fn asked(&self) -> usize {
        self.names.len()
    }

    /// Takes in the answers that have arrived; true when there were any.
    pub fn collect(&mut self) -> bool {
        let mut any = false;
        while let Ok(answer) = self.pool.answers.try_recv() {
            self.settle(answer);
            any = true;
        }
        any
    }

    /// Asks for the names of `addrs` and waits for their answers until `deadline`.
    pub fn look_up(&mut self, addrs: &[IpAddr], deadline: Instant) {
        for &addr in addrs {
            self.get(addr);
        }
        let pending = |names: &HashMap<IpAddr, HostName>| {
            addrs
                .iter()
                .any(|addr| names.get(&addr.to_canonical()) == Some(&HostName::Pending))
        };
        while pending(&self.names) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.pool.answers.recv_timeout(left) {
                Ok(answer) => self.settle(answer),
                Err(_) => return,
            }
        }
    }

    fn settle(&mut self, (addr, name): (IpAddr, HostName)) {
        self.pool.pending = self.pool.pending.saturating_sub(1);
        self.names.insert(addr, name);
    }
}

/// False for the addresses that name no single host: the unspecified address, and broadcast to
/// the local network.
fn names_a_host(addr: IpAddr) -> bool {
    !addr.is_unspecified() && addr != IpAddr::V4(Ipv4Addr::BROADCAST)
}

/// The threads that look names up, started as they are needed.
struct Pool {
    lookup: Arc<Lookup>,
    /// Addresses waiting for a thread, and the threads' end of that queue.
    queue: Sender<IpAddr>,
    queued: Arc<Mutex<Receiver<IpAddr>>>,
    /// Names found, and the threads' end of that channel.
    answers: Receiver<(IpAddr, HostName)>,
    answer: Sender<(IpAddr, HostName)>,
    threads: usize,
    /// Addresses asked for whose answers have not been taken in.
    pending: usize,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("threads", &self.threads)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// Queues `addr` for a thread, first starting another while every thread may be busy.
    fn ask(&mut self, addr: IpAddr) -> HostName {
        if self.pending >= self.threads && self.threads < THREADS {
            match self.start() {
                Ok(()) => self.threads += 1,
                Err(err) if self.threads == 0 => {
                    return HostName::Failed(format!("cannot start a thread to look it up: {err}"));
                }
                // The threads already running take the address in turn.
                Err(_) => {}
            }
        }
        // The queue stays open while `queued` holds its other end.
        let _ = self.queue.send(addr);
        self.pending += 1;
        HostName::Pending
    }

    /// Starts a thread that looks up queued addresses until the queue or the answers close,
    /// which dropping the pool does.
    fn start(&self) -> io::Result<()> {
        let queued = Arc::clone(&self.queued);
        let answer = self.answer.clone();
        let lookup = Arc::clone(&self.lookup);
        thread::Builder::new().name("host-names".into()).spawn(move || {
            loop {
                // The lock is held while waiting for an address, never during a lookup.
                let next = match queued.lock() {
                    Ok(queue) => queue.recv(),
                    Err(_) => return,
                };
                let Ok(addr) = next else { return };
                if answer.send((addr, lookup(addr))).is_err() {
                    return;
                }
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Long enough for any answer the tests wait for.
    const WAIT: Duration = Duration::from_secs(10);

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Names 192.0.2.n `host-n.example`, fails for 198.51.100.0/24 and knows no other name.
    fn fake(addr: IpAddr) -> HostName {
        match addr {
            IpAddr::V4(v4) if v4.octets()[..3] == [192, 0, 2] => {
                HostName::Found(format!("host-{}.example", v4.octets()[3]))
            }
            IpAddr::V4(v4) if v4.octets()[..3] == [198, 51, 100] => HostName::Failed("SERVFAIL".into()),
            _ => HostName::None,
        }
    }

    #[test]
    fn looks_each_address_up_once() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let mut hosts = Hosts::with_lookup(move |addr| {
            log.lock().unwrap().push(addr);
            fake(addr)
        });
        assert_eq!(hosts.get(ip("192.0.2.1")), &HostName::Pending);
        assert_eq!(hosts.name(ip("192.0.2.1")), None, "answers count once taken in");
        hosts.look_up(
            &[ip("192.0.2.1"), ip("203.0.113.9"), ip("198.51.100.7")],
            Instant::now() + WAIT,
        );
        assert_eq!(hosts.name(ip("192.0.2.1")), Some("host-1.example"));
        assert_eq!(hosts.get(ip("203.0.113.9")), &HostName::None);
        assert_eq!(
            hosts.get(ip("198.51.100.7")),
            &HostName::Failed("SERVFAIL".into())
        );
        assert_eq!(
            hosts.name(ip("::ffff:192.0.2.1")),
            Some("host-1.example"),
            "an IPv4-mapped address is its IPv4 address"
        );
        let mut asked = asked.lock().unwrap().clone();
        asked.sort();
        assert_eq!(asked, [ip("192.0.2.1"), ip("198.51.100.7"), ip("203.0.113.9")]);
    }

    #[test]
    fn starts_threads_only_while_all_may_be_busy() {
        let mut hosts = Hosts::with_lookup(fake);
        hosts.look_up(&[ip("192.0.2.1"), ip("192.0.2.2")], Instant::now() + WAIT);
        assert_eq!(hosts.pool.threads, 2);
        hosts.look_up(&[ip("192.0.2.3")], Instant::now() + WAIT);
        assert_eq!(hosts.pool.threads, 2, "an idle thread took the third");
        let many: Vec<IpAddr> = (10..40)
            .map(|n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
            .collect();
        hosts.look_up(&many, Instant::now() + WAIT);
        assert_eq!(hosts.pool.threads, THREADS);
        assert_eq!(hosts.name(ip("192.0.2.39")), Some("host-39.example"));
    }

    #[test]
    fn addresses_of_no_single_host_are_not_looked_up() {
        let mut hosts = Hosts::with_lookup(fake);
        for addr in ["0.0.0.0", "::", "255.255.255.255"] {
            assert_eq!(hosts.get(ip(addr)), &HostName::None, "{addr}");
        }
        assert_eq!(hosts.pool.threads, 0);
    }

    #[test]
    fn a_slow_lookup_holds_up_no_other() {
        // 192.0.2.1 is answered only once the test lets it be.
        let (release, gate) = mpsc::channel::<()>();
        let gate = Mutex::new(gate);
        let mut hosts = Hosts::with_lookup(move |addr| {
            if addr == ip("192.0.2.1") {
                let _ = gate.lock().unwrap().recv();
            }
            fake(addr)
        });
        assert_eq!(hosts.get(ip("192.0.2.1")), &HostName::Pending);
        hosts.look_up(&[ip("192.0.2.2")], Instant::now() + WAIT);
        assert_eq!(hosts.name(ip("192.0.2.2")), Some("host-2.example"));
        assert!(!hosts.collect(), "nothing else has arrived");

        let started = Instant::now();
        hosts.look_up(&[ip("192.0.2.1")], started + Duration::from_millis(50));
        assert_eq!(
            hosts.get(ip("192.0.2.1")),
            &HostName::Pending,
            "the wait ends at its deadline"
        );
        assert!(started.elapsed() < WAIT);
        release.send(()).unwrap();
        hosts.look_up(&[ip("192.0.2.1")], Instant::now() + WAIT);
        assert_eq!(hosts.name(ip("192.0.2.1")), Some("host-1.example"));
    }

    #[test]
    fn answers_are_taken_in_as_they_arrive() {
        let mut hosts = Hosts::with_lookup(fake);
        assert!(!hosts.collect());
        hosts.get(ip("192.0.2.5"));
        let deadline = Instant::now() + WAIT;
        while !hosts.collect() {
            assert!(Instant::now() < deadline, "no answer arrived");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(hosts.name(ip("192.0.2.5")), Some("host-5.example"));
    }
}
