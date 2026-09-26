//! Runs the built binary on recordings made the way a live trace makes them, covering the
//! whole pipeline without root.
#![allow(clippy::unwrap_used, reason = "test setup failures should panic")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use iotap::model::{Endpoint, Proto, Target};
use iotap::record::{Recorder, Recording};
#[cfg(target_os = "macos")]
use iotap::session::UntracedReason;
use iotap::session::{Collect, Filter, Input, Process, Session, SessionInfo};
use iotap::sys::time::{ClockAnchor, Timebase};
use iotap::trace::kdebug::pairing::PathRecords;
#[cfg(target_os = "macos")]
use iotap::trace::kdebug::synth::{Call, Synth};
#[cfg(target_os = "linux")]
use iotap::trace::linux::synth::{Call, Synth, inet_addr};
#[cfg(target_os = "linux")]
use iotap::trace::linux::{Event, Memory, Record};
use iotap::trace::procs::{Fixed, Snapshot};
use iotap::trace::{Records, System};

const PID: i32 = 4242;
/// A child of `PID`, and one that iotap could not trace.
const CHILD: i32 = 4243;
const UNTRACED: i32 = 4244;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("iotap-it-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The calls of a curl-like session, as this system's trace facility records them: open an
/// output file, talk to a server, write the body, exit. A recording replays only on the system
/// that made it. Returns the records, the timebase and trace time they use, and when they end.
#[cfg(target_os = "macos")]
fn traced() -> (Records, Timebase, PathRecords, u64) {
    let mut synth = Synth::new(24_100_000, 2_400);
    let mut records = synth.open(1, PID, "page.html", 4);
    records.extend(synth.call(Call {
        ret: 5,
        ..Call::new(2, PID, 97, [2, 1, 6, 0])
    }));
    records.extend(synth.call(Call {
        errno: libc::EINPROGRESS,
        ..Call::new(2, PID, 98, [5, 0, 16, 0])
    }));
    records.extend(synth.io(2, PID, 133, 5, 517, 517));
    records.extend(synth.io(2, PID, 29, 5, 16_384, 4_096));
    records.extend(synth.call(Call {
        errno: libc::EAGAIN,
        ..Call::new(2, PID, 29, [5, 0, 16_384, 0])
    }));
    records.extend(synth.io(1, PID, 4, 4, 4_096, 4_096));
    records.extend(synth.io(1, PID, 397, 1, 20, 20));
    records.extend(synth.close(1, PID, 4));
    records.push(synth.proc_exit(1, PID, 0));
    let timebase = Timebase { numer: 125, denom: 3 };
    (
        Records::Kdebug(records),
        timebase,
        PathRecords::Whole,
        synth.now(),
    )
}

#[cfg(target_os = "linux")]
fn traced() -> (Records, Timebase, PathRecords, u64) {
    let mut synth = Synth::new(System::HOST, 24_100_000, 100_000);
    let records = vec![
        synth.open(1, PID, "page.html", 4),
        synth.call(Call {
            ret: 5,
            ..Call::new(2, PID, "socket", [2, 1, 6, 0, 0, 0])
        }),
        synth.call(Call {
            ret: -i64::from(libc::EINPROGRESS),
            memory: Memory::Sockaddr(inet_addr("93.184.216.34:443".parse().unwrap())),
            ..Call::new(2, PID, "connect", [5, 0x7fff_0000, 16, 0, 0, 0])
        }),
        synth.io(2, PID, "sendto", 5, 517, 517),
        synth.io(2, PID, "recvfrom", 5, 16_384, 4_096),
        synth.call(Call {
            ret: -i64::from(libc::EAGAIN),
            ..Call::new(2, PID, "recvfrom", [5, 0, 16_384, 0, 0, 0])
        }),
        synth.io(1, PID, "write", 4, 4_096, 4_096),
        synth.io(1, PID, "write", 1, 20, 20),
        synth.close(1, PID, 4),
        synth.exit(PID),
    ];
    let timebase = Timebase { numer: 1, denom: 1 };
    (
        Records::Linux(records),
        timebase,
        PathRecords::default(),
        synth.now(),
    )
}

/// A shell that starts a child, which writes to the terminal it has from the shell, and another
/// child that iotap could not trace, as this system's facility and reader tell of them. Returns
/// the inputs, and the timebase and path layout they use.
#[cfg(target_os = "macos")]
fn family() -> (Vec<Input>, Timebase, PathRecords) {
    let mut synth = Synth::new(24_100_000, 2_400);
    let fork = synth.call(Call {
        ret: u64::from(CHILD.cast_unsigned()),
        ..Call::new(1, PID, 2, [0; 4])
    });
    let mut records = synth.io(5, CHILD, 4, 1, 20, 20);
    records.push(synth.proc_exit(5, CHILD, 0));
    records.push(synth.proc_exit(1, PID, 0));
    let inputs = vec![
        Input::Records(Records::Kdebug(fork)),
        // The reader takes up the children the kdebug records show.
        Input::Attached {
            process: Process {
                pid: CHILD,
                name: "sh".into(),
            },
            parent: Some(PID),
        },
        Input::Untraced {
            pid: UNTRACED,
            parent: Some(PID),
            reason: UntracedReason::Ended,
        },
        Input::Records(Records::Kdebug(records)),
    ];
    let timebase = Timebase { numer: 125, denom: 3 };
    (
        with_end(inputs, timebase, synth.now()),
        timebase,
        PathRecords::Whole,
    )
}

#[cfg(target_os = "linux")]
fn family() -> (Vec<Input>, Timebase, PathRecords) {
    let mut synth = Synth::new(System::HOST, 24_100_000, 100_000);
    // The program tells of each child in the records, and of one it had no room for.
    let untraced = Record {
        event: Event::Fork {
            parent: PID,
            child: UNTRACED,
            traced: false,
        },
        ..synth.fork(PID, UNTRACED)
    };
    let records = vec![
        synth.fork(PID, CHILD),
        untraced,
        synth.io(5, CHILD, "write", 1, 20, 20),
        synth.exit(CHILD),
        synth.exit(PID),
    ];
    let inputs = vec![Input::Records(Records::Linux(records))];
    let timebase = Timebase { numer: 1, denom: 1 };
    (
        with_end(inputs, timebase, synth.now()),
        timebase,
        PathRecords::default(),
    )
}

/// `inputs`, then what the reader sends as the trace ends at `end`: the exits of the processes,
/// and a second later the stop.
fn with_end(mut inputs: Vec<Input>, timebase: Timebase, end: u64) -> Vec<Input> {
    for pid in [CHILD, PID] {
        inputs.push(Input::Exited { pid, ticks: end });
    }
    inputs.push(Input::Stopped {
        ticks: end + timebase.nanos_to_ticks(1_000_000_000),
    });
    inputs
}

/// Where a trace of `name` (`PID`) begins.
fn info(name: &str, timebase: Timebase, path_records: PathRecords) -> SessionInfo {
    SessionInfo {
        timebase,
        anchor: ClockAnchor {
            ticks: 24_000_000,
            unix_nanos: 1_790_000_000_000_000_000,
        },
        processes: vec![Process {
            pid: PID,
            name: name.into(),
        }],
        path_records,
        system: System::HOST,
    }
}

/// What libproc or `/proc` would say of the descriptors of `pid` when tracing it began: its
/// output goes to the terminal.
fn at_the_terminal(procs: &mut Fixed, pid: i32) {
    procs.snapshots.insert(
        pid,
        Snapshot {
            fds: vec![(
                1,
                Target::File {
                    path: "/dev/ttys004".into(),
                },
            )],
            cwd: Some("/Users/me".into()),
            netns: None,
        },
    );
}

/// Records `inputs` the way a live trace does: through the same session and recording wrapper.
fn record(path: &Path, info: SessionInfo, procs: Fixed, inputs: &[Input]) {
    let mut recording = Recording::new(procs, Some(Recorder::create(path, &info).unwrap()));
    let mut session = Session::new(info, Filter::ALL, &mut recording);
    let mut sink = Collect::default();
    for input in inputs {
        recording.input(input);
        session.handle(input, &mut recording, &mut sink).unwrap();
    }
    recording.finish().unwrap();
}

fn write_recording(path: &Path) {
    let (records, timebase, path_records, end) = traced();
    let mut procs = Fixed::default();
    at_the_terminal(&mut procs, PID);
    procs.targets.insert(
        (PID, 5),
        Target::Socket(Endpoint {
            proto: Proto::Tcp,
            local: Some("192.168.1.20:61000".parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            path: None,
        }),
    );
    let inputs = [
        Input::Records(records),
        Input::Exited { pid: PID, ticks: end },
        Input::Stopped {
            ticks: end + timebase.nanos_to_ticks(1_000_000_000),
        },
    ];
    record(path, info("curl", timebase, path_records), procs, &inputs);
}

fn write_family_recording(path: &Path) {
    let (inputs, timebase, path_records) = family();
    let mut procs = Fixed::default();
    at_the_terminal(&mut procs, PID);
    // A child on Linux gets a copy of its parent's descriptors from the trace; on macOS iotap
    // asks libproc about it as it does about any process it begins to trace.
    #[cfg(target_os = "macos")]
    at_the_terminal(&mut procs, CHILD);
    record(path, info("sh", timebase, path_records), procs, &inputs);
}

fn iotap(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iotap"))
        .args(args)
        .env("TZ", "UTC")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn replay_prints_events_and_summary() {
    let dir = TempDir::new("text");
    let path = dir.0.join("curl.iotaprec");
    write_recording(&path);
    let output = iotap(&["--replay", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let text = stdout(&output);
    let pid = PID.to_string();
    let events: Vec<&str> = text
        .lines()
        .filter(|l| l.split_whitespace().nth(1) == Some(pid.as_str()))
        .collect();
    assert_eq!(
        events.len(),
        5,
        "open, socket, connect and close are not I/O: {text}"
    );
    assert!(
        events[0].contains("sendto") && events[0].ends_with("tcp 192.168.1.20:61000 -> 93.184.216.34:443")
    );
    assert!(events[1].contains("recvfrom") && events[1].contains("16384") && events[1].contains("4096"));
    assert!(events[2].contains("EAGAIN"), "{}", events[2]);
    assert!(
        events[3].contains("write") && events[3].ends_with("/Users/me/page.html"),
        "{}",
        events[3]
    );
    assert!(events[4].ends_with("/dev/ttys004"), "{}", events[4]);
    assert!(text.lines().next().unwrap().starts_with("TIME"), "{text}");
    assert!(text.contains("iotap summary: 4242 (curl) traced for"), "{text}");
    assert!(text.contains("Files (2 targets)"), "{text}");
    assert!(text.contains("Network (1 target)"), "{text}");
    assert!(
        text.contains("  network  received 4.0 KiB (2 calls), sent 517 B (1 call)"),
        "{text}"
    );
    assert!(text.contains("5 calls, 1 failed"), "{text}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("4242 (curl) exited"), "{stderr}");
}

#[test]
fn replay_honours_filters_and_quiet() {
    let dir = TempDir::new("filters");
    let path = dir.0.join("curl.iotaprec");
    write_recording(&path);
    let path = path.to_str().unwrap();
    let net = stdout(&iotap(&["--replay", path, "--net-only", "--quiet"]));
    assert!(!net.contains("sendto"), "quiet hides events: {net}");
    assert!(
        net.contains("Network (1 target)") && !net.contains("Files"),
        "{net}"
    );
    let files = stdout(&iotap(&["--replay", path, "--files-only"]));
    assert!(
        !files.contains("tcp ") && files.contains("/Users/me/page.html"),
        "{files}"
    );
}

#[test]
fn replay_rejects_other_files() {
    let dir = TempDir::new("reject");
    let path = dir.0.join("not.iotaprec");
    std::fs::write(&path, b"hello").unwrap();
    let output = iotap(&["--replay", path.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not an iotap recording"), "{stderr}");
}

#[test]
fn replay_writes_json_lines() {
    let dir = TempDir::new("json");
    let path = dir.0.join("curl.iotaprec");
    write_recording(&path);
    let output = iotap(&["--replay", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success(), "{output:?}");
    let lines: Vec<serde_json::Value> = stdout(&output)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let types: Vec<&str> = lines.iter().map(|l| l["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "start", "event", "event", "event", "event", "event", "exited", "summary"
        ]
    );
    assert_eq!(lines[0]["processes"][0]["name"], "curl");
    assert_eq!(lines[2]["bytes"], 4096);
    assert_eq!(lines[2]["target"]["remote"], "93.184.216.34:443");
    assert_eq!(lines[3]["error"], "EAGAIN");
    assert_eq!(
        lines[4]["target"],
        serde_json::json!({"kind": "file", "path": "/Users/me/page.html"})
    );
    let summary = &lines[7];
    assert_eq!(summary["totals"]["net_read"]["bytes"], 4096);
    assert_eq!(summary["network"][0]["target"], "tcp 93.184.216.34:443");
    assert_eq!(summary["files"].as_array().unwrap().len(), 2);
}

#[test]
fn tui_needs_a_terminal() {
    let dir = TempDir::new("tui");
    let path = dir.0.join("curl.iotaprec");
    write_recording(&path);
    let output = iotap(&["--replay", path.to_str().unwrap(), "--tui"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "iotap: --tui needs a terminal, but stdout is redirected\n"
    );
}

#[test]
fn replay_tells_of_children() {
    let dir = TempDir::new("children");
    let path = dir.0.join("sh.iotaprec");
    write_family_recording(&path);
    let path = path.to_str().unwrap();
    let output = iotap(&["--replay", path, "--json"]);
    assert!(output.status.success(), "{output:?}");
    let lines: Vec<serde_json::Value> = stdout(&output)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let of = |kind: &str| -> Vec<&serde_json::Value> { lines.iter().filter(|l| l["type"] == kind).collect() };
    assert_eq!(
        of("attached"),
        [&serde_json::json!({"type": "attached", "pid": CHILD, "name": "sh", "parent": PID})]
    );
    // kdebug finds a child that ended before iotap could trace it; the eBPF program has no room
    // for a child once it traces as many processes as it can.
    let (reason, counted) = if cfg!(target_os = "macos") {
        ("ended", serde_json::json!({"ended": 1, "full": 0}))
    } else {
        ("full", serde_json::json!({"ended": 0, "full": 1}))
    };
    assert_eq!(
        of("untraced"),
        [&serde_json::json!({"type": "untraced", "pid": UNTRACED, "parent": PID, "reason": reason})]
    );
    let events = of("event");
    assert_eq!(events.len(), 1, "{lines:?}");
    assert_eq!(events[0]["pid"], CHILD);
    assert_eq!(
        events[0]["target"],
        serde_json::json!({"kind": "file", "path": "/dev/ttys004"})
    );
    let summary = of("summary")[0];
    assert_eq!(summary["untraced_children"], counted);
    assert_eq!(
        summary["processes"],
        serde_json::json!([{"pid": PID, "name": "sh"}, {"pid": CHILD, "name": "sh"}])
    );

    let output = iotap(&["--replay", path, "--quiet"]);
    let text = stdout(&output);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("now tracing 4243 (sh), a child of 4242\n"),
        "{stderr}"
    );
    let (notice, gap) = if cfg!(target_os = "macos") {
        (
            "4244, a child of 4242, ended before iotap could trace it\n",
            "Note: 1 child process ended before iotap could trace it.\n",
        )
    } else {
        (
            "4244, a child of 4242, is not traced: iotap is tracing as many processes as it can\n",
            "Warning: 1 child process was not traced, as iotap was tracing as many processes as it can.\n",
        )
    };
    assert!(stderr.contains(notice), "{stderr}");
    assert!(text.contains(gap), "{text}");
}
