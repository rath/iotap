//! Aggregates I/O events per target, per network interface and per second of trace time.

use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;

use serde::Serialize;

use crate::model::{Category, Dir, Endpoint, FdType, IoEvent, Proto, Target, Via, named_addr};

/// Seconds of throughput history kept for live views.
const HISTORY_SECONDS: usize = 120;

/// Bytes and calls in one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counter {
    pub bytes: u64,
    pub calls: u64,
}

impl Counter {
    fn add(&mut self, bytes: Option<u64>) {
        self.calls += 1;
        self.bytes = self.bytes.saturating_add(bytes.unwrap_or(0));
    }
}

/// What a socket row is keyed by: its peer when connected, else its local address or path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Peer {
    Remote(SocketAddr),
    Local(SocketAddr),
    Path(String),
    Unknown,
}

impl Peer {
    fn of(endpoint: &Endpoint) -> Self {
        if let Some(path) = &endpoint.path {
            Self::Path(path.clone())
        } else if let Some(remote) = endpoint.remote {
            Self::Remote(remote)
        } else if let Some(local) = endpoint.local {
            Self::Local(local)
        } else {
            Self::Unknown
        }
    }

    /// True when [`Peer::of`] gives this peer for `endpoint`, without building one.
    fn is_of(&self, endpoint: &Endpoint) -> bool {
        match (&endpoint.path, endpoint.remote, endpoint.local) {
            (Some(path), _, _) => matches!(self, Self::Path(own) if own == path),
            (None, Some(remote), _) => *self == Self::Remote(remote),
            (None, None, Some(local)) => *self == Self::Local(local),
            (None, None, None) => *self == Self::Unknown,
        }
    }
}

/// Aggregation key: files by path, sockets by peer, other descriptors by kind.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    File(String),
    Socket { proto: Proto, peer: Peer },
    Other(FdType),
    Unknown,
}

impl Key {
    pub fn of(target: &Target) -> Self {
        match target {
            Target::File { path } => Self::File(path.clone()),
            Target::Socket(endpoint) => Self::Socket {
                proto: endpoint.proto,
                peer: Peer::of(endpoint),
            },
            Target::Other { fd_type } => Self::Other(*fd_type),
            Target::Unknown => Self::Unknown,
        }
    }

    /// True when events on `target` count under this key; cheaper than comparing with
    /// [`Key::of`].
    pub fn matches(&self, target: &Target) -> bool {
        match (self, target) {
            (Self::File(path), Target::File { path: other }) => path == other,
            (Self::Socket { proto, peer }, Target::Socket(endpoint)) => {
                *proto == endpoint.proto && peer.is_of(endpoint)
            }
            (Self::Other(fd_type), Target::Other { fd_type: other }) => fd_type == other,
            (Self::Unknown, Target::Unknown) => true,
            _ => false,
        }
    }

    fn has_addresses(&self) -> bool {
        matches!(self, Self::Socket { proto, .. } if proto.has_addresses())
    }

    pub fn category(&self) -> Category {
        match self {
            Self::File(_) => Category::File,
            Self::Socket { .. } => Category::Network,
            Self::Other(_) | Self::Unknown => Category::Other,
        }
    }

    /// The remote address of a socket keyed by it.
    pub fn remote(&self) -> Option<SocketAddr> {
        match self {
            Self::Socket {
                peer: Peer::Remote(addr),
                ..
            } => Some(*addr),
            _ => None,
        }
    }

    /// The key as it displays, with `host`, when given, in place of its remote address's IP.
    pub fn named(&self, host: Option<&str>) -> impl fmt::Display {
        fmt::from_fn(move |f| self.write(f, host))
    }

    fn write(&self, f: &mut fmt::Formatter<'_>, host: Option<&str>) -> fmt::Result {
        match self {
            Self::File(path) if path.is_empty() => f.write_str("<unnamed file>"),
            Self::File(path) => f.write_str(path),
            Self::Socket { proto, peer } => {
                let proto = proto.name();
                match peer {
                    Peer::Remote(addr) => write!(f, "{proto} {}", named_addr(*addr, host)),
                    Peer::Local(addr) => write!(f, "{proto} {addr} (local)"),
                    Peer::Path(path) => write!(f, "{proto} {path}"),
                    Peer::Unknown if !self.has_addresses() => f.write_str(proto),
                    Peer::Unknown => write!(f, "{proto} ?"),
                }
            }
            Self::Other(fd_type) => write!(f, "<{}>", fd_type.name()),
            Self::Unknown => f.write_str("<unknown>"),
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, None)
    }
}

/// Time spent in the calls whose start was traced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Latency {
    pub calls: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

impl Latency {
    fn add(&mut self, ns: u64) {
        self.calls += 1;
        self.total_ns = self.total_ns.saturating_add(ns);
        self.max_ns = self.max_ns.max(ns);
    }

    /// Mean time per call, once a call was timed.
    pub fn mean_ns(&self) -> Option<u64> {
        self.total_ns.checked_div(self.calls)
    }
}

/// Totals for one target.
#[derive(Clone, Debug, Default)]
pub struct Row {
    pub read: Counter,
    pub write: Counter,
    /// Failed calls; they also count in `read.calls`/`write.calls`.
    pub errors: u64,
    /// Messages moved by `sendmsg_x`/`recvmsg_x`.
    pub messages: u64,
    /// Successful calls whose byte count the trace does not carry.
    pub unsized_calls: u64,
    pub latency: Latency,
    locals: BTreeSet<SocketAddr>,
    /// Interfaces the target's I/O went over, for sockets.
    interfaces: BTreeSet<Via>,
    /// Processes that used the target, in pid order.
    pids: Vec<i32>,
    /// Wall-clock time of the first and of the latest event, in Unix nanoseconds.
    pub first_ns: u64,
    pub last_ns: u64,
}

impl Row {
    pub fn bytes(&self) -> u64 {
        self.read.bytes.saturating_add(self.write.bytes)
    }

    pub fn calls(&self) -> u64 {
        self.read.calls + self.write.calls
    }

    /// Distinct local socket addresses seen for this peer.
    pub fn connections(&self) -> usize {
        self.locals.len()
    }

    /// The local socket addresses seen for this peer, in order.
    pub fn locals(&self) -> &BTreeSet<SocketAddr> {
        &self.locals
    }

    /// The interfaces a socket's I/O went over: those named, in order, then unknown if some
    /// went over an interface iotap cannot tell.
    pub fn interfaces(&self) -> &BTreeSet<Via> {
        &self.interfaces
    }

    /// Processes that used the target, in pid order.
    pub fn pids(&self) -> &[i32] {
        &self.pids
    }
}

/// Grand totals by category.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub file_read: Counter,
    pub file_write: Counter,
    pub net_read: Counter,
    pub net_write: Counter,
    pub other_read: Counter,
    pub other_write: Counter,
    pub events: u64,
    pub errors: u64,
}

/// Network I/O over one interface: in total, and in its latest seconds of trace time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub read: Counter,
    pub write: Counter,
    /// Bytes moved in the latest second that moved any, and in the one before it, oldest first.
    recent: [Moved; 2],
}

/// Bytes read and written during one second of trace time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Moved {
    unix_sec: u64,
    read: u64,
    write: u64,
}

impl Traffic {
    pub fn bytes(&self) -> u64 {
        self.read.bytes.saturating_add(self.write.bytes)
    }

    pub fn calls(&self) -> u64 {
        self.read.calls + self.write.calls
    }

    /// Bytes read and written during `unix_sec`, known for the latest two seconds that moved
    /// any; none for other seconds.
    pub fn during(&self, unix_sec: u64) -> (u64, u64) {
        self.recent
            .iter()
            .find(|moved| moved.unix_sec == unix_sec)
            .map_or((0, 0), |moved| (moved.read, moved.write))
    }

    fn add(&mut self, dir: Dir, bytes: Option<u64>, unix_sec: u64) {
        match dir {
            Dir::Read => self.read.add(bytes),
            Dir::Write => self.write.add(bytes),
        }
        let Some(bytes) = bytes else {
            return;
        };
        let [older, latest] = &mut self.recent;
        let moved = if unix_sec > latest.unix_sec {
            *older = *latest;
            *latest = Moved {
                unix_sec,
                ..Moved::default()
            };
            latest
        } else if unix_sec == latest.unix_sec {
            latest
        } else if unix_sec == older.unix_sec {
            // Events arrive in trace order, but tolerate a small step back.
            older
        } else {
            return;
        };
        match dir {
            Dir::Read => moved.read = moved.read.saturating_add(bytes),
            Dir::Write => moved.write = moved.write.saturating_add(bytes),
        }
    }
}

/// Network I/O over one interface, for the end-of-session report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceTotals {
    pub interface: Via,
    pub read_bytes: u64,
    pub read_calls: u64,
    pub write_bytes: u64,
    pub write_calls: u64,
}

/// Bytes moved during one second of trace time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Second {
    /// Unix time in seconds.
    pub unix_sec: u64,
    pub file_read: u64,
    pub file_write: u64,
    pub net_read: u64,
    pub net_write: u64,
}

/// Order of rows in tables.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortBy {
    #[default]
    Bytes,
    Read,
    Write,
    Calls,
    Recent,
}

impl SortBy {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Bytes => Self::Read,
            Self::Read => Self::Write,
            Self::Write => Self::Calls,
            Self::Calls => Self::Recent,
            Self::Recent => Self::Bytes,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Read => "read",
            Self::Write => "write",
            Self::Calls => "calls",
            Self::Recent => "recent",
        }
    }
}

/// One row of the end-of-session tables.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SummaryRow {
    pub target: String,
    /// The key of the target, which `target` writes out; not part of the JSON summary.
    #[serde(skip)]
    pub key: Key,
    pub read_bytes: u64,
    pub read_calls: u64,
    pub write_bytes: u64,
    pub write_calls: u64,
    pub errors: u64,
    pub messages: u64,
    pub unsized_calls: u64,
    /// Distinct local addresses, for sockets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    rows: HashMap<Key, Row>,
    /// Rows per category, indexed by [`category_index`].
    targets: [usize; 3],
    totals: Totals,
    /// Network I/O by the interface it went over.
    interfaces: HashMap<Via, Traffic>,
    history: VecDeque<Second>,
}

fn category_index(category: Category) -> usize {
    match category {
        Category::File => 0,
        Category::Network => 1,
        Category::Other => 2,
    }
}

/// Row order for `sort`: largest first, then most calls, then by key so the order is total.
fn compare(sort: SortBy, (ka, a): &(&Key, &Row), (kb, b): &(&Key, &Row)) -> Ordering {
    let primary = match sort {
        SortBy::Bytes => b.bytes().cmp(&a.bytes()),
        SortBy::Read => b.read.bytes.cmp(&a.read.bytes),
        SortBy::Write => b.write.bytes.cmp(&a.write.bytes),
        SortBy::Calls => b.calls().cmp(&a.calls()),
        SortBy::Recent => b.last_ns.cmp(&a.last_ns),
    };
    primary
        .then_with(|| b.calls().cmp(&a.calls()))
        .then_with(|| ka.cmp(kb))
}

impl Stats {
    pub fn record(&mut self, event: &IoEvent) {
        let key = Key::of(&event.target);
        let category = key.category();
        let row = match self.rows.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.targets[category_index(category)] += 1;
                entry.insert(Row {
                    first_ns: event.time_ns,
                    ..Row::default()
                })
            }
        };
        let dir = event.dir();
        match dir {
            Dir::Read => row.read.add(event.bytes),
            Dir::Write => row.write.add(event.bytes),
        }
        row.first_ns = row.first_ns.min(event.time_ns);
        row.last_ns = row.last_ns.max(event.time_ns);
        if let Some(ns) = event.latency_ns {
            row.latency.add(ns);
        }
        if let Err(at) = row.pids.binary_search(&event.pid) {
            row.pids.insert(at, event.pid);
        }
        row.messages = row.messages.saturating_add(event.messages.unwrap_or(0));
        if !event.is_ok() {
            row.errors += 1;
            self.totals.errors += 1;
        } else if event.bytes.is_none() && event.messages.is_none() {
            row.unsized_calls += 1;
        }
        if let Target::Socket(endpoint) = &*event.target
            && let Some(local) = endpoint.local
        {
            row.locals.insert(local);
        }
        if category == Category::Network {
            let via = &event.interface;
            if *via != Via::NoInterface && !row.interfaces.contains(via) {
                row.interfaces.insert(via.clone());
            }
            self.interfaces.entry(via.clone()).or_default().add(
                dir,
                event.bytes,
                event.time_ns / 1_000_000_000,
            );
        }

        self.totals.events += 1;
        let totals = &mut self.totals;
        let counter = match (category, dir) {
            (Category::File, Dir::Read) => &mut totals.file_read,
            (Category::File, Dir::Write) => &mut totals.file_write,
            (Category::Network, Dir::Read) => &mut totals.net_read,
            (Category::Network, Dir::Write) => &mut totals.net_write,
            (Category::Other, Dir::Read) => &mut totals.other_read,
            (Category::Other, Dir::Write) => &mut totals.other_write,
        };
        counter.add(event.bytes);

        if let Some(bytes) = event.bytes {
            let second = self.second(event.time_ns / 1_000_000_000);
            match (category, dir) {
                (Category::File, Dir::Read) => second.file_read = second.file_read.saturating_add(bytes),
                (Category::File, Dir::Write) => second.file_write = second.file_write.saturating_add(bytes),
                (Category::Network, Dir::Read) => second.net_read = second.net_read.saturating_add(bytes),
                (Category::Network, Dir::Write) => second.net_write = second.net_write.saturating_add(bytes),
                (Category::Other, _) => {}
            }
        }
    }

    pub fn totals(&self) -> &Totals {
        &self.totals
    }

    /// Number of distinct targets in a category.
    pub fn targets(&self, category: Category) -> usize {
        self.targets[category_index(category)]
    }

    /// Rows of one category, sorted.
    pub fn rows(&self, category: Category, sort: SortBy) -> Vec<(&Key, &Row)> {
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|(key, _)| key.category() == category)
            .collect();
        rows.sort_by(|a, b| compare(sort, a, b));
        rows
    }

    /// Rows `skip..skip + take` in `sort` order among the categories `wanted` accepts. Only
    /// the rows returned are fully sorted, so a live view can ask for one screen of a large
    /// table many times a second.
    pub fn page(
        &self,
        wanted: impl Fn(Category) -> bool,
        sort: SortBy,
        skip: usize,
        take: usize,
    ) -> Vec<(&Key, &Row)> {
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|(key, _)| wanted(key.category()))
            .collect();
        let end = skip.saturating_add(take).min(rows.len());
        if end == 0 {
            return Vec::new();
        }
        if end < rows.len() {
            // Afterwards the first `end` rows are the smallest, in no particular order.
            rows.select_nth_unstable_by(end - 1, |a, b| compare(sort, a, b));
            rows.truncate(end);
        }
        rows.sort_by(|a, b| compare(sort, a, b));
        rows.drain(..skip.min(end));
        rows
    }

    /// The row of `key`, if it has one.
    pub fn row(&self, key: &Key) -> Option<&Row> {
        self.rows.get(key)
    }

    /// Position of `key` in `sort` order among the rows of the categories `wanted` accepts.
    pub fn rank(&self, wanted: impl Fn(Category) -> bool, sort: SortBy, key: &Key) -> Option<usize> {
        let this = self.rows.get_key_value(key)?;
        if !wanted(key.category()) {
            return None;
        }
        let before = self
            .rows
            .iter()
            .filter(|(other, _)| wanted(other.category()))
            .filter(|other| compare(sort, other, &this) == Ordering::Less)
            .count();
        Some(before)
    }

    /// Every row of one category as summary rows, largest first.
    pub fn summary_rows(&self, category: Category) -> Vec<SummaryRow> {
        self.rows(category, SortBy::Bytes)
            .into_iter()
            .map(|(key, row)| SummaryRow {
                target: key.to_string(),
                key: key.clone(),
                read_bytes: row.read.bytes,
                read_calls: row.read.calls,
                write_bytes: row.write.bytes,
                write_calls: row.write.calls,
                errors: row.errors,
                messages: row.messages,
                unsized_calls: row.unsized_calls,
                connections: matches!(key, Key::Socket { .. }).then(|| row.connections()),
            })
            .collect()
    }

    /// Network I/O by interface: named interfaces by bytes and then calls, most first, then I/O
    /// over an interface iotap cannot tell, then I/O over none.
    pub fn interfaces(&self) -> Vec<(&Via, &Traffic)> {
        let mut interfaces: Vec<_> = self.interfaces.iter().collect();
        let rank = |via: &Via| match via {
            Via::Interface(_) => 0,
            Via::Unknown => 1,
            Via::NoInterface => 2,
        };
        interfaces.sort_by(|(via_a, a), (via_b, b)| {
            rank(via_a)
                .cmp(&rank(via_b))
                .then_with(|| b.bytes().cmp(&a.bytes()))
                .then_with(|| b.calls().cmp(&a.calls()))
                .then_with(|| via_a.cmp(via_b))
        });
        interfaces
    }

    /// Network I/O by interface as summary rows, in the order of [`Stats::interfaces`].
    pub fn interface_totals(&self) -> Vec<InterfaceTotals> {
        self.interfaces()
            .into_iter()
            .map(|(via, traffic)| InterfaceTotals {
                interface: via.clone(),
                read_bytes: traffic.read.bytes,
                read_calls: traffic.read.calls,
                write_bytes: traffic.write.bytes,
                write_calls: traffic.write.calls,
            })
            .collect()
    }

    /// Per-second byte counts, oldest first, for the last seconds of activity.
    pub fn history(&self) -> &VecDeque<Second> {
        &self.history
    }

    fn second(&mut self, unix_sec: u64) -> &mut Second {
        let index = match self.history.back() {
            Some(last) if last.unix_sec == unix_sec => self.history.len() - 1,
            Some(last) if last.unix_sec > unix_sec => {
                // Events arrive in trace order, but tolerate a small step back.
                self.history
                    .iter()
                    .rposition(|s| s.unix_sec == unix_sec)
                    .unwrap_or(self.history.len() - 1)
            }
            _ => {
                // Fill idle seconds so the history stays contiguous.
                let mut next = self.history.back().map_or(unix_sec, |last| last.unix_sec + 1);
                if unix_sec.saturating_sub(next) > HISTORY_SECONDS as u64 {
                    self.history.clear();
                    next = unix_sec;
                }
                while next <= unix_sec {
                    self.history.push_back(Second {
                        unix_sec: next,
                        ..Second::default()
                    });
                    next += 1;
                }
                while self.history.len() > HISTORY_SECONDS {
                    self.history.pop_front();
                }
                self.history.len() - 1
            }
        };
        &mut self.history[index]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::model::{Endpoint, Op, Provenance};

    fn event(op: Op, target: Target, bytes: Option<u64>, errno: i32, time_ns: u64) -> IoEvent {
        let interface = match target.category() {
            Category::Network => Via::Unknown,
            Category::File | Category::Other => Via::NoInterface,
        };
        IoEvent {
            time_ns,
            pid: 1,
            tid: 1,
            op,
            syscall: op.name(),
            fd: Some(3),
            requested: None,
            bytes,
            messages: None,
            errno,
            latency_ns: None,
            target: Arc::new(target),
            provenance: Provenance::Traced,
            interface,
        }
    }

    #[test]
    fn sums_of_bytes_stop_at_the_top_of_a_u64() {
        // A kernel cannot return this from read or write, but a recording can hold it, and a
        // debug build must not panic on it nor a release build wrap around to a small number.
        let file = || Target::File { path: "/big".into() };
        let socket = || {
            Target::Socket(Endpoint {
                proto: crate::model::Proto::Tcp,
                local: None,
                remote: Some("192.0.2.1:443".parse().unwrap()),
                path: None,
            })
        };
        let mut stats = Stats::default();
        for at in 0..3 {
            let big = 1 << 63;
            stats.record(&event(Op::Read, file(), Some(big), 0, at));
            stats.record(&event(Op::Write, file(), Some(big), 0, at));
            let mut sent = event(Op::Sendto, socket(), Some(big), 0, at);
            sent.messages = Some(u64::MAX);
            stats.record(&sent);
        }
        let totals = stats.totals();
        assert_eq!(totals.file_read.bytes, u64::MAX);
        assert_eq!(totals.file_write.bytes, u64::MAX);
        assert_eq!(totals.file_read.calls, 3);
        let rows = stats.summary_rows(Category::File);
        assert_eq!(rows[0].read_bytes, u64::MAX);
        let network = stats.summary_rows(Category::Network);
        assert_eq!(network[0].messages, u64::MAX);
        assert_eq!(stats.history()[0].file_read, u64::MAX);
        let file = stats.rows(Category::File, SortBy::Bytes);
        assert_eq!(file[0].1.bytes(), u64::MAX, "read and written together");
    }

    #[test]
    fn aggregates_per_target_and_category() {
        let mut stats = Stats::default();
        let file = Target::File { path: "/a".into() };
        let sock = |local: &str| {
            Target::Socket(Endpoint {
                proto: Proto::Tcp,
                local: Some(local.parse().unwrap()),
                remote: Some("1.1.1.1:443".parse().unwrap()),
                path: None,
            })
        };
        stats.record(&event(Op::Read, file.clone(), Some(100), 0, 1_000_000_000));
        stats.record(&event(Op::Write, file.clone(), Some(50), 0, 1_500_000_000));
        stats.record(&event(Op::Read, file, None, libc::EAGAIN, 1_600_000_000));
        stats.record(&event(
            Op::Sendto,
            sock("10.0.0.1:5000"),
            Some(10),
            0,
            2_000_000_000,
        ));
        stats.record(&event(
            Op::Recvfrom,
            sock("10.0.0.1:5001"),
            Some(30),
            0,
            2_100_000_000,
        ));
        stats.record(&event(
            Op::Sendfile,
            sock("10.0.0.1:5001"),
            None,
            0,
            2_200_000_000,
        ));

        let files = stats.rows(Category::File, SortBy::Bytes);
        assert_eq!(files.len(), 1);
        let (key, row) = files[0];
        assert_eq!(key.to_string(), "/a");
        assert_eq!(
            (row.read, row.write, row.errors),
            (
                Counter { bytes: 100, calls: 2 },
                Counter { bytes: 50, calls: 1 },
                1
            )
        );

        let net = stats.rows(Category::Network, SortBy::Bytes);
        assert_eq!(net.len(), 1);
        assert_eq!(net[0].0.to_string(), "tcp 1.1.1.1:443");
        assert_eq!((net[0].1.connections(), net[0].1.unsized_calls), (2, 1));

        let totals = stats.totals();
        assert_eq!(
            (
                totals.file_read.bytes,
                totals.net_write.bytes,
                totals.net_read.bytes
            ),
            (100, 10, 30)
        );
        assert_eq!((totals.events, totals.errors), (6, 1));

        let history: Vec<_> = stats
            .history()
            .iter()
            .map(|s| (s.unix_sec, s.file_read, s.net_read))
            .collect();
        assert_eq!(history, vec![(1, 100, 0), (2, 0, 30)]);
    }

    /// Network I/O over en0, utun4, awdl0 (without a byte count) and an unknown interface to
    /// one peer, and over none to a Unix-domain socket, and a file write.
    fn traffic() -> Stats {
        let mut stats = Stats::default();
        let peer = Target::Socket(Endpoint {
            remote: Some("1.1.1.1:443".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        });
        let unix = Target::Socket(Endpoint {
            path: Some("/tmp/s".into()),
            ..Endpoint::unresolved(Proto::Unix)
        });
        let second = |n: u64| n * 1_000_000_000;
        let over = |name: &str, op: Op, bytes: Option<u64>, sec: u64| IoEvent {
            interface: Via::Interface(name.into()),
            ..event(op, peer.clone(), bytes, 0, second(sec))
        };
        stats.record(&over("en0", Op::Recvfrom, Some(100), 10));
        stats.record(&over("en0", Op::Sendto, Some(7), 11));
        stats.record(&over("en0", Op::Recvfrom, Some(50), 12));
        // A step back into the second before still counts in it.
        stats.record(&over("en0", Op::Sendto, Some(3), 11));
        stats.record(&over("utun4", Op::Sendto, Some(900), 12));
        stats.record(&over("awdl0", Op::Sendto, None, 12));
        stats.record(&event(Op::Sendto, peer.clone(), Some(1), 0, second(12)));
        stats.record(&IoEvent {
            interface: Via::NoInterface,
            ..event(Op::Write, unix, Some(2_000), 0, second(12))
        });
        let file = Target::File { path: "/a".into() };
        stats.record(&event(Op::Write, file, Some(5), 0, second(12)));
        stats
    }

    #[test]
    fn counts_network_traffic_per_interface() {
        let stats = traffic();
        let interfaces: Vec<(String, u64, u64)> = stats
            .interfaces()
            .iter()
            .map(|(via, traffic)| (via.to_string(), traffic.bytes(), traffic.calls()))
            .collect();
        let expected = [
            ("utun4", 900, 1),
            ("en0", 160, 4),
            ("awdl0", 0, 1),
            ("?", 1, 1),
            ("none", 2_000, 1),
        ];
        let expected: Vec<(String, u64, u64)> = expected
            .iter()
            .map(|&(name, bytes, calls)| (name.to_owned(), bytes, calls))
            .collect();
        assert_eq!(interfaces, expected);
        let en0 = stats.interfaces()[1].1;
        assert_eq!(
            (en0.during(12), en0.during(11), en0.during(10)),
            ((50, 0), (0, 10), (0, 0))
        );
        assert_eq!(
            stats.interface_totals()[1].interface,
            Via::Interface("en0".into())
        );
        assert_eq!(
            serde_json::to_value(&stats.interface_totals()[4]).unwrap(),
            serde_json::json!({
                "interface": null,
                "read_bytes": 0,
                "read_calls": 0,
                "write_bytes": 2000,
                "write_calls": 1
            })
        );
    }

    #[test]
    fn rows_keep_the_interfaces_their_io_went_over() {
        let stats = traffic();
        let net = stats.rows(Category::Network, SortBy::Bytes);
        let row = |name: &str| {
            net.iter()
                .find(|(key, _)| key.to_string() == name)
                .map(|(_, row)| *row)
                .unwrap()
        };
        let names: Vec<String> = row("tcp 1.1.1.1:443")
            .interfaces()
            .iter()
            .map(Via::to_string)
            .collect();
        assert_eq!(names, ["awdl0", "en0", "utun4", "?"]);
        assert!(row("unix /tmp/s").interfaces().is_empty());
    }

    #[test]
    fn sorts_and_labels_rows() {
        let mut stats = Stats::default();
        for (path, bytes) in [("/small", 1), ("/big", 1_000), ("/mid", 10)] {
            stats.record(&event(
                Op::Write,
                Target::File { path: path.into() },
                Some(bytes),
                0,
                0,
            ));
        }
        let order: Vec<String> = stats
            .rows(Category::File, SortBy::Bytes)
            .iter()
            .map(|(k, _)| k.to_string())
            .collect();
        assert_eq!(order, ["/big", "/mid", "/small"]);
        assert_eq!(
            Key::of(&Target::Other {
                fd_type: FdType::Pipe
            })
            .to_string(),
            "<pipe>"
        );
        let udp = Target::Socket(Endpoint {
            local: Some("0.0.0.0:5353".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Udp)
        });
        assert_eq!(Key::of(&udp).to_string(), "udp 0.0.0.0:5353 (local)");
        assert_eq!(
            Key::of(&Target::Socket(Endpoint::unresolved(Proto::System))).to_string(),
            "system"
        );
        assert_eq!(
            Key::of(&Target::Socket(Endpoint::unresolved(Proto::Tcp))).to_string(),
            "tcp ?"
        );
        assert_eq!(SortBy::Recent.next(), SortBy::Bytes);
    }

    #[test]
    fn pages_match_a_full_sort() {
        let mut stats = Stats::default();
        for i in 0..40_u64 {
            let target = if i % 4 == 0 {
                Target::Other {
                    fd_type: FdType::Pipe,
                }
            } else {
                Target::File {
                    path: format!("/f{i}"),
                }
            };
            // Equal byte counts exercise the tie-breakers.
            stats.record(&event(Op::Read, target, Some(i % 7), 0, i));
        }
        stats.record(&event(
            Op::Sendto,
            Target::Socket(Endpoint::unresolved(Proto::Udp)),
            Some(9),
            0,
            50,
        ));
        assert_eq!(
            (
                stats.targets(Category::File),
                stats.targets(Category::Network),
                stats.targets(Category::Other)
            ),
            (30, 1, 1)
        );
        let local = |c: Category| c != Category::Network;
        for sort in [SortBy::Bytes, SortBy::Calls, SortBy::Recent] {
            let mut full: Vec<_> = stats.rows(Category::File, sort);
            full.extend(stats.rows(Category::Other, sort));
            full.sort_by(|a, b| compare(sort, a, b));
            for (skip, take) in [(0, 5), (3, 10), (25, 10), (31, 4), (0, 100), (0, 0)] {
                let end = (skip + take).min(full.len());
                let expected: Vec<String> = full[skip.min(end)..end]
                    .iter()
                    .map(|(k, _)| k.to_string())
                    .collect();
                let got: Vec<String> = stats
                    .page(local, sort, skip, take)
                    .iter()
                    .map(|(k, _)| k.to_string())
                    .collect();
                assert_eq!(got, expected, "{sort:?} {skip}+{take}");
            }
            for (rank, (key, _)) in full.iter().enumerate() {
                assert_eq!(stats.rank(local, sort, key), Some(rank), "{sort:?} {key}");
            }
            assert_eq!(stats.rank(|c| c == Category::Network, sort, full[0].0), None);
            assert_eq!(stats.rank(local, sort, &Key::File("/none".into())), None);
        }
    }

    #[test]
    fn rows_keep_processes_latency_and_first_use() {
        let mut stats = Stats::default();
        let file = Target::File { path: "/a".into() };
        for (pid, latency_ns, time_ns) in [(3, Some(10), 5), (1, None, 2), (3, Some(30), 9)] {
            stats.record(&IoEvent {
                pid,
                latency_ns,
                ..event(Op::Read, file.clone(), Some(1), 0, time_ns)
            });
        }
        let row = stats.row(&Key::of(&file)).unwrap();
        assert_eq!(row.pids(), [1, 3]);
        assert_eq!((row.first_ns, row.last_ns), (2, 9));
        assert_eq!(
            row.latency,
            Latency {
                calls: 2,
                total_ns: 40,
                max_ns: 30
            }
        );
        assert_eq!(row.latency.mean_ns(), Some(20));
        assert_eq!(Latency::default().mean_ns(), None);
        assert!(stats.row(&Key::File("/b".into())).is_none());
    }

    #[test]
    fn keys_match_the_targets_they_count() {
        let tcp = |remote: Option<&str>, path: Option<&str>| {
            Target::Socket(Endpoint {
                proto: Proto::Tcp,
                local: Some("10.0.0.1:5000".parse().unwrap()),
                remote: remote.map(|r| r.parse().unwrap()),
                path: path.map(Into::into),
            })
        };
        let targets = [
            Target::File { path: "/a".into() },
            Target::File { path: "/b".into() },
            tcp(Some("1.1.1.1:443"), None),
            tcp(Some("1.1.1.1:80"), None),
            tcp(None, None),
            tcp(Some("1.1.1.1:443"), Some("/tmp/s")),
            Target::Socket(Endpoint::unresolved(Proto::Unix)),
            Target::Socket(Endpoint::unresolved(Proto::Udp)),
            Target::Other {
                fd_type: FdType::Pipe,
            },
            Target::Other {
                fd_type: FdType::Kqueue,
            },
            Target::Unknown,
        ];
        for a in &targets {
            for b in &targets {
                assert_eq!(Key::of(a).matches(b), Key::of(a) == Key::of(b), "{a} and {b}");
            }
        }
    }

    #[test]
    fn keys_write_a_host_name_in_place_of_the_remote_address() {
        let key = |local: &str, remote: Option<&str>| {
            Key::of(&Target::Socket(Endpoint {
                proto: Proto::Tcp,
                local: Some(local.parse().unwrap()),
                remote: remote.map(|r| r.parse().unwrap()),
                path: None,
            }))
        };
        let connected = key("10.0.0.1:5000", Some("[2001:db8::1]:443"));
        assert_eq!(connected.remote(), Some("[2001:db8::1]:443".parse().unwrap()));
        assert_eq!(
            connected.named(Some("www.example.com")).to_string(),
            "tcp www.example.com:443"
        );
        assert_eq!(connected.named(None).to_string(), "tcp [2001:db8::1]:443");
        let bound = key("10.0.0.1:5000", None);
        assert_eq!(bound.remote(), None);
        assert_eq!(
            bound.named(Some("www.example.com")).to_string(),
            "tcp 10.0.0.1:5000 (local)"
        );
        assert_eq!(Key::File("/a".into()).remote(), None);
    }

    #[test]
    fn history_skips_long_idle_gaps() {
        let mut stats = Stats::default();
        let file = Target::File { path: "/a".into() };
        stats.record(&event(Op::Read, file.clone(), Some(1), 0, 10_000_000_000));
        stats.record(&event(Op::Read, file, Some(2), 0, 1_000_000_000_000));
        assert_eq!(stats.history().len(), 1);
        assert_eq!(stats.history()[0].unix_sec, 1_000);
    }
}
