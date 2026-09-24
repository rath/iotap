//! Runs the built binary on recordings made the way a live trace makes them, covering the
//! whole pipeline without root.
#![allow(clippy::unwrap_used, reason = "test setup failures should panic")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use iotap::model::{Endpoint, Proto, Target};
use iotap::record::{Recorder, Recording};
use iotap::session::{Collect, Filter, Input, Process, Session, SessionInfo};
use iotap::sys::time::{ClockAnchor, Timebase};
use iotap::trace::pairing::PathRecords;
use iotap::trace::procs::{Fixed, Snapshot};
use iotap::trace::synth::{Call, Synth};

const PID: i32 = 4242;

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

/// A curl-like session: open an output file, talk to a server, write the body, exit. The
/// recording is produced by the same session and recording wrapper a live trace uses.
fn write_recording(path: &Path) {
    let info = SessionInfo {
        timebase: Timebase { numer: 125, denom: 3 },
        anchor: ClockAnchor {
            ticks: 24_000_000,
            unix_nanos: 1_790_000_000_000_000_000,
        },
        processes: vec![Process {
            pid: PID,
            name: "curl".into(),
        }],
        path_records: PathRecords::Whole,
    };
    let mut procs = Fixed::default();
    procs.snapshots.insert(
        PID,
        Snapshot {
            fds: vec![(
                1,
                Target::File {
                    path: "/dev/ttys004".into(),
                },
            )],
            cwd: Some("/Users/me".into()),
        },
    );
    procs.targets.insert(
        (PID, 5),
        Target::Socket(Endpoint {
            proto: Proto::Tcp,
            local: Some("192.168.1.20:61000".parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            path: None,
        }),
    );

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
    let stop = synth.now() + 24_000_000;

    let mut recording = Recording::new(procs, Some(Recorder::create(path, &info).unwrap()));
    let mut session = Session::new(info, Filter::ALL, &mut recording);
    let mut sink = Collect::default();
    for input in [
        Input::Records(records),
        Input::Exited { pid: PID },
        Input::Stopped { ticks: stop },
    ] {
        recording.input(&input);
        session.handle(&input, &mut recording, &mut sink).unwrap();
    }
    recording.finish().unwrap();
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
