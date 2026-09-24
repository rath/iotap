//! Aggregates I/O events per target and per second of trace time.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;

use serde::Serialize;

use crate::model::{Category, Dir, FdType, IoEvent, Proto, Target};

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
        self.bytes += bytes.unwrap_or(0);
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
            Target::Socket(endpoint) => {
                let peer = if let Some(path) = &endpoint.path {
                    Peer::Path(path.clone())
                } else if let Some(remote) = endpoint.remote {
                    Peer::Remote(remote)
                } else if let Some(local) = endpoint.local {
                    Peer::Local(local)
                } else {
                    Peer::Unknown
                };
                Self::Socket {
                    proto: endpoint.proto,
                    peer,
                }
            }
            Target::Other { fd_type } => Self::Other(*fd_type),
            Target::Unknown => Self::Unknown,
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
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) if path.is_empty() => f.write_str("<unnamed file>"),
            Self::File(path) => f.write_str(path),
            Self::Socket { proto, peer } => {
                let proto = proto.name();
                match peer {
                    Peer::Remote(addr) => write!(f, "{proto} {addr}"),
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
    locals: HashSet<SocketAddr>,
    /// Wall-clock time of the latest event, in Unix nanoseconds.
    pub last_ns: u64,
}

impl Row {
    pub fn bytes(&self) -> u64 {
        self.read.bytes + self.write.bytes
    }

    pub fn calls(&self) -> u64 {
        self.read.calls + self.write.calls
    }

    /// Distinct local socket addresses seen for this peer.
    pub fn connections(&self) -> usize {
        self.locals.len()
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

#[derive(Debug, Default)]
pub struct Stats {
    rows: HashMap<Key, Row>,
    totals: Totals,
    history: VecDeque<Second>,
}

impl Stats {
    pub fn record(&mut self, event: &IoEvent) {
        let key = Key::of(&event.target);
        let category = key.category();
        let row = self.rows.entry(key).or_default();
        let dir = event.dir();
        match dir {
            Dir::Read => row.read.add(event.bytes),
            Dir::Write => row.write.add(event.bytes),
        }
        row.last_ns = row.last_ns.max(event.time_ns);
        row.messages += event.messages.unwrap_or(0);
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
                (Category::File, Dir::Read) => second.file_read += bytes,
                (Category::File, Dir::Write) => second.file_write += bytes,
                (Category::Network, Dir::Read) => second.net_read += bytes,
                (Category::Network, Dir::Write) => second.net_write += bytes,
                (Category::Other, _) => {}
            }
        }
    }

    pub fn totals(&self) -> &Totals {
        &self.totals
    }

    /// Rows of one category, sorted.
    pub fn rows(&self, category: Category, sort: SortBy) -> Vec<(&Key, &Row)> {
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|(key, _)| key.category() == category)
            .collect();
        rows.sort_by(|(ka, a), (kb, b)| {
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
        });
        rows
    }

    /// Every row of one category as summary rows, largest first.
    pub fn summary_rows(&self, category: Category) -> Vec<SummaryRow> {
        self.rows(category, SortBy::Bytes)
            .into_iter()
            .map(|(key, row)| SummaryRow {
                target: key.to_string(),
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
        }
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
    fn history_skips_long_idle_gaps() {
        let mut stats = Stats::default();
        let file = Target::File { path: "/a".into() };
        stats.record(&event(Op::Read, file.clone(), Some(1), 0, 10_000_000_000));
        stats.record(&event(Op::Read, file, Some(2), 0, 1_000_000_000_000));
        assert_eq!(stats.history().len(), 1);
        assert_eq!(stats.history()[0].unix_sec, 1_000);
    }
}
