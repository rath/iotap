//! Human-readable event lines and the end-of-session summary.

use std::io::{self, Write};

use super::{bytes, count, duration, latency};
use crate::model::{IoEvent, errno_name};
use crate::session::{Filter, Notice, Sink, Summary};
use crate::stats::SummaryRow;
use crate::sys::time::LocalClock;

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

/// Formats one event line (without a trailing newline).
pub fn event_line(event: &IoEvent, clock: &mut LocalClock) -> String {
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
    format!(
        "{}  {:>6}  {:<13} {:>5} {:>11} {:>11} {:>11}  {}",
        clock.format(event.time_ns),
        event.pid,
        event.op.name(),
        fd,
        requested,
        result,
        latency,
        event.target
    )
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

/// Writes the end-of-session summary tables.
pub fn write_summary(out: &mut dyn Write, summary: &Summary, top: usize, filter: Filter) -> io::Result<()> {
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
        table(out, "Files", ["READ", "WRITTEN"], &summary.files, top)?;
    }
    if filter.network {
        table(out, "Network", ["RECEIVED", "SENT"], &summary.network, top)?;
    }
    if filter.other && !summary.other.is_empty() {
        table(out, "Other descriptors", ["READ", "WRITTEN"], &summary.other, top)?;
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

fn table(
    out: &mut dyn Write,
    title: &str,
    words: [&str; 2],
    rows: &[SummaryRow],
    top: usize,
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
        writeln!(
            out,
            "  {:>10} {:>8}  {:>10} {:>8}  {:>6}  {}{notes}",
            bytes(row.read_bytes),
            row.read_calls,
            bytes(row.write_bytes),
            row.write_calls,
            row.errors,
            row.target
        )?;
    }
    if rows.len() > top {
        writeln!(out, "  ... and {} more", rows.len() - top)?;
    }
    Ok(())
}
