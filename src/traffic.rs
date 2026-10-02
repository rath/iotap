//! Network counters are measurements, not syscalls. Replay uses only these recorded inputs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::{Category, Endpoint, Via};
use crate::stats::Stats;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Active,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub time_ns: u64,
    pub state: State,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub time_ns: u64,
    /// When this process became a target. Counters from before this time are excluded.
    pub since_ns: u64,
    pub started_ns: Option<u64>,
    pub source: u64,
    pub process_id: u64,
    pub pid: i32,
    pub target: Endpoint,
    pub interface: Via,
    pub received: u64,
    pub sent: u64,
    pub closed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Input {
    Observation(Observation),
    Status(Status),
}

/// An interval's increase, with no invented syscall, descriptor, latency, or call count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub time_ns: u64,
    pub interval_start_ns: u64,
    pub source: u64,
    pub process_id: u64,
    pub pid: i32,
    pub target: Endpoint,
    pub interface: Via,
    pub received_bytes: u64,
    pub sent_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Update {
    Sample(Sample),
    Status(Status),
}

#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub target: String,
    #[serde(skip)]
    pub key: crate::stats::Key,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub connections: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Interface {
    pub interface: Via,
    pub received_bytes: u64,
    pub sent_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub source: &'static str,
    pub status: Status,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub interfaces: Vec<Interface>,
    pub targets: Vec<Row>,
}

#[derive(Debug, Default)]
pub struct Tracker {
    flows: HashMap<(u64, u64), Observation>,
    pub stats: Stats,
    pub status: Option<Status>,
}

impl Tracker {
    pub fn ingest(&mut self, input: &Input) -> Vec<Update> {
        match input {
            Input::Status(status) => {
                // A later successful poll cannot recover bytes from a lost, closed flow.
                if status.state == State::Active
                    && self.status.as_ref().is_some_and(|s| s.state == State::Partial)
                {
                    return Vec::new();
                }
                self.status = Some(status.clone());
                vec![Update::Status(status.clone())]
            }
            Input::Observation(now) => self.observe(now),
        }
    }

    fn observe(&mut self, now: &Observation) -> Vec<Update> {
        let key = (now.process_id, now.source);
        let previous = self.flows.get(&key);
        if previous.is_some_and(|old| old.closed || now.time_ns <= old.time_ns) {
            return Vec::new();
        }
        let mut updates = Vec::new();
        let (start, received, sent, interface) = if let Some(old) = previous {
            if now.received < old.received || now.sent < old.sent {
                let status = Status {
                    time_ns: now.time_ns,
                    state: State::Partial,
                    reason: Some("network counters restarted; the new values are a baseline".into()),
                };
                self.status = Some(status.clone());
                updates.push(Update::Status(status));
                (now.time_ns, 0, 0, now.interface.clone())
            } else {
                let interface = if now.interface == old.interface {
                    now.interface.clone()
                } else {
                    Via::Unknown
                };
                (
                    old.time_ns,
                    now.received - old.received,
                    now.sent - old.sent,
                    interface,
                )
            }
        } else if let Some(start) = now.started_ns.filter(|&t| t >= now.since_ns && t < now.time_ns) {
            (start, now.received, now.sent, now.interface.clone())
        } else {
            (now.time_ns, 0, 0, now.interface.clone())
        };
        self.flows.insert(key, now.clone());
        if start < now.time_ns {
            updates.push(Update::Sample(Sample {
                time_ns: now.time_ns,
                interval_start_ns: start,
                source: now.source,
                process_id: now.process_id,
                pid: now.pid,
                target: now.target.clone(),
                interface,
                received_bytes: received,
                sent_bytes: sent,
            }));
        }
        updates
    }

    pub fn report(&self) -> Option<Report> {
        Some(Report {
            source: "macos_network_statistics",
            status: self.status.clone()?,
            received_bytes: self.stats.totals().net_read.bytes,
            sent_bytes: self.stats.totals().net_write.bytes,
            interfaces: self
                .stats
                .interface_totals()
                .into_iter()
                .map(|row| Interface {
                    interface: row.interface,
                    received_bytes: row.read_bytes,
                    sent_bytes: row.write_bytes,
                })
                .collect(),
            targets: self
                .stats
                .summary_rows(Category::Network)
                .into_iter()
                .map(|row| Row {
                    target: row.target,
                    key: row.key,
                    received_bytes: row.read_bytes,
                    sent_bytes: row.write_bytes,
                    connections: row.connections.unwrap_or(0),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proto;

    fn observation(time_ns: u64, received: u64) -> Observation {
        Observation {
            time_ns,
            since_ns: 10,
            started_ns: Some(1),
            source: 1,
            process_id: 5,
            pid: 5,
            target: Endpoint::unresolved(Proto::Tcp),
            interface: Via::Interface("en0".into()),
            received,
            sent: 0,
            closed: false,
        }
    }

    #[test]
    fn excludes_existing_bytes_and_counts_final_update_once() {
        let mut tracker = Tracker::default();
        assert!(
            tracker
                .ingest(&Input::Observation(observation(20, 1000)))
                .is_empty()
        );
        let mut last = observation(30, 1100);
        last.closed = true;
        let updates = tracker.ingest(&Input::Observation(last.clone()));
        assert!(
            matches!(&updates[..], [Update::Sample(s)] if s.received_bytes == 100 && s.interval_start_ns == 20)
        );
        last.time_ns = 40;
        assert!(tracker.ingest(&Input::Observation(last)).is_empty());
    }

    #[test]
    fn new_short_lived_connections_include_their_first_and_last_counts() {
        let mut tracker = Tracker::default();
        let mut observation = observation(30, 512);
        observation.started_ns = Some(20);
        observation.closed = true;
        assert!(
            matches!(&tracker.ingest(&Input::Observation(observation))[..], [Update::Sample(s)] if s.received_bytes == 512)
        );
    }

    #[test]
    fn counter_reset_and_interface_change_do_not_invent_bytes_or_attribution() {
        let mut tracker = Tracker::default();
        tracker.ingest(&Input::Observation(observation(20, 1000)));
        let mut changed = observation(30, 1010);
        changed.interface = Via::Interface("en1".into());
        assert!(
            matches!(&tracker.ingest(&Input::Observation(changed))[..], [Update::Sample(s)] if s.interface == Via::Unknown && s.received_bytes == 10)
        );
        assert!(
            matches!(&tracker.ingest(&Input::Observation(observation(40, 5)))[..], [Update::Status(s)] if s.state == State::Partial)
        );
        assert!(
            matches!(&tracker.ingest(&Input::Observation(observation(50, 15)))[..], [Update::Sample(s)] if s.received_bytes == 10)
        );
    }

    #[test]
    fn old_samples_and_reused_pids_do_not_change_another_connections_baseline() {
        let mut tracker = Tracker::default();
        tracker.ingest(&Input::Observation(observation(20, 1000)));
        assert!(
            tracker
                .ingest(&Input::Observation(observation(19, 500)))
                .is_empty()
        );
        let mut other = observation(25, 8000);
        other.process_id = 6; // The numeric PID was reused, the process identity was not.
        assert!(tracker.ingest(&Input::Observation(other.clone())).is_empty());
        other.time_ns = 35;
        other.received = 8010;
        assert!(
            matches!(&tracker.ingest(&Input::Observation(other))[..], [Update::Sample(s)] if s.received_bytes == 10)
        );
        assert!(
            matches!(&tracker.ingest(&Input::Observation(observation(40, 1020)))[..], [Update::Sample(s)] if s.received_bytes == 20)
        );
    }
}
