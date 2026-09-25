//! Human-readable event lines and the end-of-session summary.

use std::borrow::Cow;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::{bytes, count, duration, latency};
use crate::hosts::Hosts;
use crate::model::{IoEvent, errno_name};
use crate::session::{Filter, Notice, Sink, Summary};
use crate::stats::SummaryRow;
use crate::sys::time::LocalClock;

/// Longest wait for the host names of the summary's network rows.
const HOST_NAMES_WAIT: Duration = Duration::from_secs(2);

/// Writes one line per event; notices go to stderr so stdout stays a clean event stream.
#[derive(Debug)]
pub struct TextSink<W: Write> {
    out: W,
    clock: LocalClock,
    quiet: bool,
    header_written: bool,
}

impl<W: Write> TextSink<W> {
    pub fn new(out: W, quiet: bool) -> Self {
        Self {
            out,
            clock: LocalClock::default(),
            quiet,
            header_written: false,
        }
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

/// The columns of an event line: time, pid, op, fd, requested, result, latency and target.
pub fn event_fields(event: &IoEvent, clock: &mut LocalClock) -> [String; 8] {
    let fd = event.fd.map_or_else(|| "-".to_owned(), |fd| fd.to_string());
    let requested = event.requested.map_or_else(|| "-".to_owned(), |n| n.to_string());
    let result = if !event.is_ok() {
        errno_name(event.errno).into_owned()
    } else if let Some(n) = event.bytes {
        n.to_string()
    } else if let Some(n) = event.messages {
        count(n, "msg")
    } else {
        "?".to_owned()
    };
    let latency = event.latency_ns.map_or_else(|| "-".to_owned(), latency);
    [
        clock.format(event.time_ns),
        event.pid.to_string(),
        event.op.name().to_owned(),
        fd,
        requested,
        result,
        latency,
        event.target.to_string(),
    ]
}

/// Formats one event line (without a trailing newline).
pub fn event_line(event: &IoEvent, clock: &mut LocalClock) -> String {
    let [time, pid, op, fd, requested, result, latency, target] = event_fields(event, clock);
    format!("{time}  {pid:>6}  {op:<13} {fd:>5} {requested:>11} {result:>11} {latency:>11}  {target}")
}

/// Header matching [`event_line`].
pub fn header_line() -> String {
    format!(
        "{:<15}  {:>6}  {:<13} {:>5} {:>11} {:>11} {:>11}  TARGET",
        "TIME", "PID", "OP", "FD", "REQUESTED", "RESULT", "LATENCY"
    )
}

/// Describes a notice as a sentence.
pub fn notice_text(notice: &Notice, clock: &mut LocalClock) -> String {
    match notice {
        Notice::LostEvents { time_ns } => format!(
            "{} the kernel dropped trace records because its buffer was full; totals are incomplete (try a larger --buffer)",
            clock.format(*time_ns)
        ),
        Notice::Attached(process) => format!("now tracing {} ({})", process.pid, process.name),
        Notice::Exec { pid, path } => format!("{pid} is now running {path}"),
        Notice::Exited(process) => format!("{} ({}) exited", process.pid, process.name),
    }
}

impl<W: Write> Sink for TextSink<W> {
    fn event(&mut self, event: &IoEvent) -> io::Result<()> {
        if self.quiet {
            return Ok(());
        }
        if !self.header_written {
            writeln!(self.out, "{}", header_line())?;
            self.header_written = true;
        }
        writeln!(self.out, "{}", event_line(event, &mut self.clock))
    }

    fn notice(&mut self, notice: &Notice) -> io::Result<()> {
        // Keep stdout and stderr in order on a terminal.
        self.out.flush()?;
        let text = notice_text(notice, &mut self.clock);
        let _ = writeln!(io::stderr(), "iotap: {text}");
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Writes the end-of-session summary tables. With `hosts`, the network rows name the hosts of
/// their remote addresses, as far as the resolver answers within [`HOST_NAMES_WAIT`].
pub fn write_summary(
    out: &mut dyn Write,
    summary: &Summary,
    top: usize,
    filter: Filter,
    mut hosts: Option<&mut Hosts>,
) -> io::Result<()> {
    if let Some(hosts) = hosts.as_deref_mut()
        && filter.network
    {
        let shown: Vec<IpAddr> = summary
            .network
            .iter()
            .take(top)
            .filter_map(|row| row.key.remote())
            .map(|addr| addr.ip())
            .collect();
        hosts.look_up(&shown, Instant::now() + HOST_NAMES_WAIT);
    }
    let processes: Vec<String> = summary
        .processes
        .iter()
        .map(|p| format!("{} ({})", p.pid, p.name))
        .collect();
    writeln!(out)?;
    writeln!(
        out,
        "iotap summary: {} traced for {}",
        processes.join(", "),
        duration(summary.duration_ns)
    )?;
    if filter.files {
        table(out, "Files", ["READ", "WRITTEN"], &summary.files, top, None)?;
    }
    if filter.network {
        table(out, "Network", ["RECEIVED", "SENT"], &summary.network, top, hosts)?;
    }
    if filter.other && !summary.other.is_empty() {
        table(
            out,
            "Other descriptors",
            ["READ", "WRITTEN"],
            &summary.other,
            top,
            None,
        )?;
    }

    let t = &summary.totals;
    writeln!(out)?;
    writeln!(out, "Totals")?;
    let line = |label: &str,
                read_word: &str,
                read: crate::stats::Counter,
                write_word: &str,
                write: crate::stats::Counter| {
        format!(
            "  {label:<8} {read_word} {} ({}), {write_word} {} ({})",
            bytes(read.bytes),
            count(read.calls, "call"),
            bytes(write.bytes),
            count(write.calls, "call")
        )
    };
    if filter.files {
        writeln!(
            out,
            "{}",
            line("files", "read", t.file_read, "written", t.file_write)
        )?;
    }
    if filter.network {
        writeln!(
            out,
            "{}",
            line("network", "received", t.net_read, "sent", t.net_write)
        )?;
    }
    if filter.other && t.other_read.calls + t.other_write.calls > 0 {
        writeln!(
            out,
            "{}",
            line("other", "read", t.other_read, "written", t.other_write)
        )?;
    }
    writeln!(out, "  {}, {} failed", count(t.events, "call"), t.errors)?;

    if summary.lost_events > 0 {
        writeln!(
            out,
            "Warning: the kernel dropped trace records {}; totals are incomplete. Try a larger --buffer.",
            count(summary.lost_events, "time")
        )?;
    }
    if summary.calls_started_before_trace > 0 {
        writeln!(
            out,
            "Note: {} began before tracing started; their descriptors are unknown.",
            count(summary.calls_started_before_trace, "call")
        )?;
    }
    Ok(())
}

/// Writes one table of targets; with `hosts`, sockets show the host names found for their
/// remote addresses.
fn table(
    out: &mut dyn Write,
    title: &str,
    words: [&str; 2],
    rows: &[SummaryRow],
    top: usize,
    mut hosts: Option<&mut Hosts>,
) -> io::Result<()> {
    writeln!(out)?;
    if rows.is_empty() {
        return writeln!(out, "{title}: none");
    }
    writeln!(out, "{title} ({})", count(rows.len() as u64, "target"))?;
    writeln!(
        out,
        "  {:>10} {:>8}  {:>10} {:>8}  {:>6}  TARGET",
        words[0], "CALLS", words[1], "CALLS", "FAILED"
    )?;
    for row in rows.iter().take(top) {
        let mut notes = Vec::new();
        if let Some(n) = row.connections.filter(|&n| n > 1) {
            notes.push(count(n as u64, "connection"));
        }
        if row.messages > 0 {
            notes.push(count(row.messages, "message"));
        }
        if row.unsized_calls > 0 {
            notes.push(format!("{} of unknown size", count(row.unsized_calls, "call")));
        }
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        let target = match (row.key.remote(), hosts.as_deref_mut()) {
            (Some(addr), Some(hosts)) => Cow::Owned(row.key.named(hosts.name(addr.ip())).to_string()),
            _ => Cow::Borrowed(row.target.as_str()),
        };
        writeln!(
            out,
            "  {:>10} {:>8}  {:>10} {:>8}  {:>6}  {target}{notes}",
            bytes(row.read_bytes),
            row.read_calls,
            bytes(row.write_bytes),
            row.write_calls,
            row.errors,
        )?;
    }
    if rows.len() > top {
        writeln!(out, "  ... and {} more", rows.len() - top)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::hosts::HostName;
    use crate::model::{Category, Endpoint, Op, Proto, Provenance, Target};
    use crate::session::Process;
    use crate::stats::Stats;

    /// A summary of reads from three servers: two with names, one without.
    fn summary() -> Summary {
        let mut stats = Stats::default();
        for (remote, bytes) in [
            ("192.0.2.1:443", 3_000),
            ("[2001:db8::1]:8443", 2_000),
            ("198.51.100.7:80", 1_000),
        ] {
            stats.record(&IoEvent {
                time_ns: 1,
                pid: 7,
                tid: 1,
                op: Op::Read,
                syscall: "read",
                fd: Some(5),
                requested: Some(bytes),
                bytes: Some(bytes),
                messages: None,
                errno: 0,
                latency_ns: Some(1_000),
                target: Arc::new(Target::Socket(Endpoint {
                    proto: Proto::Tcp,
                    local: None,
                    remote: Some(remote.parse().unwrap()),
                    path: None,
                })),
                provenance: Provenance::Traced,
            });
        }
        Summary {
            duration_ns: 1_000_000_000,
            processes: vec![Process {
                pid: 7,
                name: "curl".into(),
            }],
            totals: *stats.totals(),
            lost_events: 0,
            unfinished_calls: 0,
            calls_started_before_trace: 0,
            files: Vec::new(),
            network: stats.summary_rows(Category::Network),
            other: Vec::new(),
        }
    }

    fn written(summary: &Summary, top: usize, hosts: Option<&mut Hosts>) -> String {
        let mut out = Vec::new();
        write_summary(&mut out, summary, top, Filter::ALL, hosts).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_summary_names_remote_hosts_when_asked() {
        let summary = summary();
        let plain = written(&summary, 30, None);
        assert!(
            plain.contains(" tcp 192.0.2.1:443\n") && plain.contains(" tcp [2001:db8::1]:8443\n"),
            "{plain}"
        );
        let mut hosts = Hosts::with_lookup(|addr| match addr.to_string().as_str() {
            "192.0.2.1" => HostName::Found("www.example.com".into()),
            "2001:db8::1" => HostName::Found("v6.example.com".into()),
            _ => HostName::None,
        });
        let named = written(&summary, 30, Some(&mut hosts));
        assert!(named.contains(" tcp www.example.com:443\n"), "{named}");
        assert!(named.contains(" tcp v6.example.com:8443\n"), "{named}");
        assert!(
            named.contains(" tcp 198.51.100.7:80\n"),
            "an address without a name stays: {named}"
        );
        assert_eq!(named.lines().count(), plain.lines().count());
    }

    #[test]
    fn only_the_rows_shown_are_looked_up() {
        let summary = summary();
        let mut hosts = Hosts::with_lookup(|_| HostName::Found("www.example.com".into()));
        let named = written(&summary, 1, Some(&mut hosts));
        assert!(named.contains(" tcp www.example.com:443\n"), "{named}");
        assert!(named.contains("  ... and 2 more\n"), "{named}");
        assert_eq!(hosts.asked(), 1, "the rows left out are not looked up");
    }
}
