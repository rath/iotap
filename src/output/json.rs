//! JSON Lines output: one object per line, each with a `type` field.
//!
//! Types: `start` (once), `event` (one per call), `lost_events`, `attached`, `untraced`, `exec`,
//! `exited`, and `summary` (last). Times are nanoseconds since the Unix epoch.

use std::borrow::Cow;
use std::io::{self, Write};

use serde::Serialize;

use crate::model::{Dir, IoEvent, Op, Provenance, Target, Via, errno_name};
use crate::session::{Notice, Process, SessionInfo, Sink, Summary, UntracedReason};

#[derive(Serialize)]
struct Start<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    time_ns: u64,
    processes: &'a [Process],
}

#[derive(Serialize)]
struct Event<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    time_ns: u64,
    pid: i32,
    tid: u64,
    op: Op,
    dir: Dir,
    syscall: &'a str,
    fd: Option<i32>,
    requested: Option<u64>,
    bytes: Option<u64>,
    messages: Option<u64>,
    errno: i32,
    error: Option<Cow<'static, str>>,
    latency_ns: Option<u64>,
    target: &'a Target,
    interface: &'a Via,
    resolved: Provenance,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum NoticeRecord<'a> {
    LostEvents {
        time_ns: u64,
    },
    Attached {
        pid: i32,
        name: &'a str,
        parent: Option<i32>,
    },
    Untraced {
        pid: i32,
        parent: Option<i32>,
        reason: UntracedReason,
    },
    Exec {
        pid: i32,
        path: &'a str,
    },
    Exited {
        pid: i32,
        name: &'a str,
    },
}

#[derive(Serialize)]
struct SummaryRecord<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(flatten)]
    summary: &'a Summary,
}

/// Writes events and notices as JSON Lines.
#[derive(Debug)]
pub struct JsonSink<W: Write> {
    out: W,
    quiet: bool,
}

impl<W: Write> JsonSink<W> {
    pub fn new(out: W, quiet: bool) -> Self {
        Self { out, quiet }
    }

    pub fn start(&mut self, info: &SessionInfo) -> io::Result<()> {
        let start = Start {
            kind: "start",
            time_ns: info.anchor.unix_nanos,
            processes: &info.processes,
        };
        self.line(&start)
    }

    pub fn summary(&mut self, summary: &Summary) -> io::Result<()> {
        self.line(&SummaryRecord {
            kind: "summary",
            summary,
        })?;
        self.out.flush()
    }

    pub fn into_inner(self) -> W {
        self.out
    }

    fn line<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        serde_json::to_writer(&mut self.out, value).map_err(io::Error::other)?;
        self.out.write_all(b"\n")
    }
}

impl<W: Write> Sink for JsonSink<W> {
    fn event(&mut self, event: &IoEvent) -> io::Result<()> {
        if self.quiet {
            return Ok(());
        }
        self.line(&Event {
            kind: "event",
            time_ns: event.time_ns,
            pid: event.pid,
            tid: event.tid,
            op: event.op,
            dir: event.dir(),
            syscall: event.syscall,
            fd: event.fd,
            requested: event.requested,
            bytes: event.bytes,
            messages: event.messages,
            errno: event.errno,
            error: (!event.is_ok()).then(|| errno_name(event.errno)),
            latency_ns: event.latency_ns,
            target: &event.target,
            interface: &event.interface,
            resolved: event.provenance,
        })
    }

    fn notice(&mut self, notice: &Notice) -> io::Result<()> {
        let record = match notice {
            Notice::LostEvents { time_ns } => NoticeRecord::LostEvents { time_ns: *time_ns },
            Notice::Attached { process, parent } => NoticeRecord::Attached {
                pid: process.pid,
                name: &process.name,
                parent: *parent,
            },
            Notice::Untraced { pid, parent, reason } => NoticeRecord::Untraced {
                pid: *pid,
                parent: *parent,
                reason: *reason,
            },
            Notice::Exec { pid, path } => NoticeRecord::Exec { pid: *pid, path },
            Notice::Exited(process) => NoticeRecord::Exited {
                pid: process.pid,
                name: &process.name,
            },
        };
        self.line(&record)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{Value, json};

    use super::*;
    use crate::model::{Endpoint, Proto, Via};

    fn lines(bytes: &[u8]) -> Vec<Value> {
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn writes_events_and_notices() {
        let mut sink = JsonSink::new(Vec::new(), false);
        let event = IoEvent {
            time_ns: 5,
            pid: 7,
            tid: 9,
            op: Op::Recvfrom,
            syscall: "recvfrom_nocancel",
            fd: Some(4),
            requested: Some(1024),
            bytes: None,
            messages: None,
            errno: libc::EAGAIN,
            latency_ns: Some(1_500),
            target: Arc::new(Target::Socket(Endpoint {
                remote: Some("1.2.3.4:53".parse().unwrap()),
                ..Endpoint::unresolved(Proto::Udp)
            })),
            provenance: Provenance::Lazy,
            interface: Via::Unknown,
        };
        sink.event(&event).unwrap();
        sink.notice(&Notice::Exited(Process {
            pid: 7,
            name: "dig".into(),
        }))
        .unwrap();
        sink.notice(&Notice::Attached {
            process: Process {
                pid: 8,
                name: "sh".into(),
            },
            parent: Some(7),
        })
        .unwrap();
        sink.notice(&Notice::Untraced {
            pid: 9,
            parent: None,
            reason: UntracedReason::Ended,
        })
        .unwrap();
        let out = lines(&sink.into_inner());
        assert_eq!(
            out[0],
            json!({
                "type": "event", "time_ns": 5, "pid": 7, "tid": 9, "op": "recvfrom", "dir": "read",
                "syscall": "recvfrom_nocancel", "fd": 4, "requested": 1024, "bytes": null,
                "messages": null, "errno": libc::EAGAIN, "error": "EAGAIN", "latency_ns": 1500,
                "target": {"kind": "socket", "proto": "udp", "remote": "1.2.3.4:53"},
                "interface": "?", "resolved": "lazy"
            })
        );
        assert_eq!(out[1], json!({"type": "exited", "pid": 7, "name": "dig"}));
        assert_eq!(
            out[2],
            json!({"type": "attached", "pid": 8, "name": "sh", "parent": 7})
        );
        assert_eq!(
            out[3],
            json!({"type": "untraced", "pid": 9, "parent": null, "reason": "ended"})
        );
    }

    #[test]
    fn events_name_their_interface_or_none() {
        let mut sink = JsonSink::new(Vec::new(), false);
        let event = IoEvent {
            time_ns: 5,
            pid: 7,
            tid: 9,
            op: Op::Write,
            syscall: "write",
            fd: Some(4),
            requested: Some(10),
            bytes: Some(10),
            messages: None,
            errno: 0,
            latency_ns: None,
            target: Arc::new(Target::Socket(Endpoint {
                local: Some("192.168.1.20:61000".parse().unwrap()),
                ..Endpoint::unresolved(Proto::Tcp)
            })),
            provenance: Provenance::Traced,
            interface: Via::Interface("wlP9s9".into()),
        };
        sink.event(&event).unwrap();
        let file = IoEvent {
            target: Arc::new(Target::File {
                path: "/tmp/x".into(),
            }),
            interface: Via::NoInterface,
            ..event
        };
        sink.event(&file).unwrap();
        let out = lines(&sink.into_inner());
        let interfaces: Vec<&Value> = out.iter().map(|line| &line["interface"]).collect();
        assert_eq!(interfaces, [&json!("wlP9s9"), &Value::Null]);
    }

    #[test]
    fn quiet_keeps_notices_only() {
        let mut sink = JsonSink::new(Vec::new(), true);
        sink.notice(&Notice::LostEvents { time_ns: 1 }).unwrap();
        assert_eq!(
            lines(&sink.into_inner()),
            [json!({"type": "lost_events", "time_ns": 1})]
        );
    }
}
