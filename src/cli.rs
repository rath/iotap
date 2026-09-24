//! Command-line interface.

use std::path::PathBuf;

use clap::Parser;

/// Trace the file and network I/O of macOS processes.
///
/// iotap reads the kernel trace facility (the source `fs_usage` uses) and reports every read
/// and write syscall of the chosen processes: descriptor, bytes, latency and the file path or
/// socket endpoint. Tracing requires root; run it with sudo.
#[derive(Debug, Parser)]
#[command(name = "iotap", version, about, long_about)]
#[expect(clippy::struct_excessive_bools, reason = "independent command-line flags")]
pub struct Cli {
    /// Process IDs or names to trace. A name matches every process whose name or executable
    /// file name equals it, ignoring case; processes started later under that name are traced
    /// too.
    #[arg(value_name = "TARGET", required_unless_present_any = ["replay", "dump_fds"])]
    pub targets: Vec<String>,

    /// Treat every TARGET as a process name, even when it is numeric.
    #[arg(short = 'n', long)]
    pub name: bool,

    /// Show a live terminal UI instead of streaming events.
    ///
    /// Keys: 1, 2 and 3 switch between the Files, Network and Events tabs; s changes the sort
    /// order; p pauses the view while tracing goes on; r resets the view to zero, though the
    /// summary still covers the whole trace; the arrow keys, Page Up, Page Down, Home and End
    /// select a row of the Files and Network tables and scroll the Events tab; Enter shows the
    /// selected row's details; y copies its path or address; Esc closes the details, then lets
    /// go of the selection, then quits; q quits and prints the summary. The UI stays open after
    /// tracing stops. With --quiet it has no Events tab.
    #[arg(long, conflicts_with = "json")]
    pub tui: bool,

    /// Write JSON Lines: one object per event and notice, then a summary object.
    #[arg(long)]
    pub json: bool,

    /// Print only the summary, not individual events; with --tui, leave out the Events tab.
    #[arg(short, long)]
    pub quiet: bool,

    /// Report only file I/O.
    #[arg(long, conflicts_with = "net_only")]
    pub files_only: bool,

    /// Report only network I/O.
    #[arg(long)]
    pub net_only: bool,

    /// Stop after this many seconds.
    #[arg(short, long, value_name = "SECS")]
    pub duration: Option<u64>,

    /// Rows per table in the text summary.
    #[arg(long, value_name = "N", default_value_t = 30)]
    pub top: usize,

    /// Kernel trace buffer size in records of 64 bytes. Raise it if iotap reports dropped
    /// records.
    #[arg(long, value_name = "RECORDS", default_value_t = 524_288)]
    pub buffer: u32,

    /// Also save the raw trace to FILE, for later --replay.
    #[arg(long, value_name = "FILE", conflicts_with = "replay")]
    pub record: Option<PathBuf>,

    /// Replay a file saved with --record instead of tracing live; does not need root.
    #[arg(long, value_name = "FILE")]
    pub replay: Option<PathBuf>,

    /// Print what each descriptor of PID refers to, then exit (diagnostics).
    #[arg(long, value_name = "PID", hide = true, conflicts_with_all = ["replay", "record", "tui", "json"])]
    pub dump_fds: Option<i32>,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_targets_and_flags() {
        let cli = Cli::try_parse_from(["iotap", "--tui", "123", "Safari"]).unwrap();
        assert_eq!(cli.targets, ["123", "Safari"]);
        assert!(cli.tui);
        assert!(Cli::try_parse_from(["iotap"]).is_err());
        assert!(Cli::try_parse_from(["iotap", "--tui", "--json", "1"]).is_err());
        assert!(Cli::try_parse_from(["iotap", "--tui", "-q", "1"]).is_ok());
        assert!(Cli::try_parse_from(["iotap", "--files-only", "--net-only", "1"]).is_err());
        assert!(Cli::try_parse_from(["iotap", "--replay", "x.iotaprec"]).is_ok());
    }
}
