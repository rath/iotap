//! Command-line interface.

use std::path::PathBuf;

use clap::Parser;

/// Trace the file and network I/O of processes.
///
/// iotap reports every read and write syscall of the chosen processes: descriptor, bytes,
/// latency and the file path or socket endpoint. On macOS it reads the kernel trace facility
/// (the source `fs_usage` uses) and separately measures TCP/UDP traffic, including Skywalk;
/// on Linux it runs an eBPF program of its own. Tracing requires root; run it with sudo.
#[derive(Debug, Parser)]
#[command(name = "iotap", version, about, long_about)]
#[expect(clippy::struct_excessive_bools, reason = "independent command-line flags")]
pub struct Cli {
    /// Process IDs or names to trace. A name matches every process whose name, or the file name
    /// of its executable or of its first argument (the command it was started by), equals it,
    /// ignoring case; processes started later under that name are traced too.
    #[arg(
        value_name = "TARGET",
        required_unless_present_any = ["replay", "dump_fds"],
        conflicts_with = "replay"
    )]
    pub targets: Vec<String>,

    /// Treat every TARGET as a process name, even when it is numeric.
    #[arg(short = 'n', long, conflicts_with = "replay")]
    pub name: bool,

    /// Also trace the processes that traced ones start, and theirs in turn.
    ///
    /// Every descendant is traced, whether running already or started later. On Linux a child
    /// is traced from its start; on macOS from a few milliseconds after, so iotap misses a child
    /// that ends sooner, and says so.
    #[arg(short = 'f', long, conflicts_with = "replay")]
    pub children: bool,

    /// Show a live terminal UI instead of streaming events.
    ///
    /// Keys: 1, 2 and 3 switch between the Files, Network and Events tabs; s changes the sort
    /// order; p pauses the view while tracing goes on; r resets the view to zero, though the
    /// summary still covers the whole trace; i shows network I/O by interface above the tabs,
    /// or hides it again; n shows remote addresses as host names, or as addresses again; the
    /// arrow keys, Page Up, Page Down, Home and End select a row of the Files and Network tables
    /// and scroll the Events tab; Enter shows the selected row's details; y copies its path or
    /// address; Esc closes the details, then lets go of the selection, then quits; q quits and
    /// prints the summary. The UI stays open after tracing stops. With --quiet it has no Events
    /// tab.
    /// On macOS, v switches Network between measured Traffic and Syscalls. The traffic view
    /// has byte counts and rates, while the syscall view keeps call counts and latency.
    #[arg(long, conflicts_with = "json")]
    pub tui: bool,

    /// Write JSON Lines: one object per event and notice, then a summary object.
    #[arg(long)]
    pub json: bool,

    /// Print only the summary, not individual events or traffic samples; with --tui, leave
    /// out the Events tab.
    #[arg(short, long)]
    pub quiet: bool,

    /// Report only file I/O.
    #[arg(long, conflicts_with = "net_only")]
    pub files_only: bool,

    /// Report only network I/O.
    #[arg(long)]
    pub net_only: bool,

    /// Report only network I/O over this network interface, such as en0 or wlan0; repeat the
    /// option for several.
    ///
    /// The name must match exactly, case included. A socket's I/O goes over the interface that
    /// holds its local address, or over the loopback interface when it goes to one of the
    /// host's own addresses. File and other I/O is not reported, and neither is I/O whose
    /// interface iotap cannot tell, such as that of a socket sending from every address.
    #[arg(
        short = 'i',
        long = "interface",
        value_name = "NAME",
        conflicts_with = "files_only"
    )]
    pub interfaces: Vec<String>,

    /// Show remote addresses as host names in the summary, and in the terminal UI from the
    /// start. Names come from the system's resolver (reverse DNS), asked in the background for
    /// the rows shown; event lines keep the addresses.
    #[arg(long, conflicts_with = "json")]
    pub resolve: bool,

    /// Stop after this many seconds.
    #[arg(short, long, value_name = "SECS", conflicts_with = "replay")]
    pub duration: Option<u64>,

    /// Rows per table in the text summary.
    #[arg(long, value_name = "N", default_value_t = 30)]
    pub top: usize,

    /// Kernel trace buffer size in records of 64 bytes, as macOS records are. On Linux the ring
    /// buffer takes as many bytes, rounded up to a power of two, and holds about half as many of
    /// its larger records. Raise it if iotap reports dropped records.
    #[arg(
        long,
        value_name = "RECORDS",
        default_value_t = 524_288,
        conflicts_with = "replay"
    )]
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
        // A replay traces nothing, so what only a live trace uses is refused, not ignored.
        for live_only in [
            &["1234"][..],
            &["-n"],
            &["-f"],
            &["-d", "1"],
            &["--buffer", "1024"],
        ] {
            let mut args = vec!["iotap", "--replay", "x.iotaprec"];
            args.extend(live_only);
            assert!(Cli::try_parse_from(args).is_err(), "{live_only:?}");
        }
        assert!(
            Cli::try_parse_from(["iotap", "--replay", "x.iotaprec", "--json", "-q", "--top", "5"]).is_ok()
        );
        assert!(Cli::try_parse_from(["iotap", "--tui", "--resolve", "1"]).is_ok());
        assert!(Cli::try_parse_from(["iotap", "--json", "--resolve", "1"]).is_err());
        for flag in ["-f", "--children"] {
            assert!(Cli::try_parse_from(["iotap", flag, "1"]).unwrap().children);
        }
        assert!(!Cli::try_parse_from(["iotap", "1"]).unwrap().children);
    }

    #[test]
    fn parses_interfaces() {
        let cli = Cli::try_parse_from(["iotap", "-i", "en0", "--interface", "lo0", "1234"]).unwrap();
        assert_eq!(
            (cli.interfaces, cli.targets),
            (vec!["en0".into(), "lo0".into()], vec!["1234".into()])
        );
        assert!(Cli::try_parse_from(["iotap", "-i", "en0", "--files-only", "1"]).is_err());
        assert!(Cli::try_parse_from(["iotap", "-i", "en0", "--net-only", "1"]).is_ok());
        assert!(Cli::try_parse_from(["iotap", "--replay", "x.iotaprec", "-i", "en0"]).is_ok());
        assert!(Cli::try_parse_from(["iotap", "1"]).unwrap().interfaces.is_empty());
    }
}
