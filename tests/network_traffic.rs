//! OS counters remain independent of syscall accounting, including through replay and UI state.
#![allow(clippy::unwrap_used, reason = "test setup failures should panic")]

use iotap::model::{Endpoint, Proto, Target, Via};
use iotap::output::{json::JsonSink, text};
use iotap::record::{self, Recorder, Recording};
use iotap::session::{Filter, Input, Process, Session, SessionInfo, Sink};
use iotap::sys::time::{ClockAnchor, Timebase};
use iotap::trace::kdebug::{pairing::PathRecords, synth::Synth};
use iotap::trace::procs::{Fixed, Snapshot};
use iotap::trace::{Records, System};
use iotap::traffic::{self, Observation, State, Status};
use iotap::tui::{
    draw,
    state::{App, Tab},
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

const BASE: u64 = 1_700_000_000_000_000_000;

fn fixture() -> (SessionInfo, Fixed, Vec<Input>) {
    let endpoint = Endpoint {
        proto: Proto::Tcp,
        local: Some("192.0.2.1:54321".parse().unwrap()),
        remote: Some("198.51.100.1:443".parse().unwrap()),
        path: None,
    };
    let info = SessionInfo {
        timebase: Timebase { numer: 1, denom: 1 },
        anchor: ClockAnchor {
            ticks: 0,
            unix_nanos: BASE,
        },
        processes: vec![Process {
            pid: 5,
            name: "radio".into(),
        }],
        path_records: PathRecords::Whole,
        system: System::Macos,
    };
    let mut fixed = Fixed::default();
    fixed.snapshots.insert(
        5,
        Snapshot {
            fds: vec![(7, Target::Socket(endpoint.clone()))],
            ..Snapshot::default()
        },
    );
    let observation = |seconds: u64, received: u64| {
        Input::Network(traffic::Input::Observation(Observation {
            time_ns: BASE + seconds * 1_000_000_000,
            since_ns: BASE,
            started_ns: Some(BASE - 1),
            source: 1,
            process_id: 77,
            pid: 5,
            target: endpoint.clone(),
            interface: Via::Interface("en0".into()),
            received,
            sent: 0,
            closed: false,
        }))
    };
    let mut synth = Synth::new(1_100_000_000, 1000);
    let inputs = vec![
        Input::Network(traffic::Input::Status(Status {
            time_ns: BASE,
            state: State::Active,
            reason: None,
        })),
        observation(1, 1000),
        Input::Records(Records::Kdebug(synth.io(1, 5, 29, 7, 100, 100))),
        Input::Watermark { ticks: 1_200_000_000 },
        observation(2, 1200),
        Input::Stopped { ticks: 2_000_000_001 },
    ];
    (info, fixed, inputs)
}

#[test]
fn recording_preserves_both_accounts_and_exact_output() {
    let (info, fixed, inputs) = fixture();
    let mut data = Vec::new();
    let mut source = Recording::new(fixed, Some(Recorder::new(&mut data, &info).unwrap()));
    let mut session = Session::new(info.clone(), Filter::ALL, &mut source);
    let mut output = JsonSink::new(Vec::new(), false);
    output.start(&info).unwrap();
    for input in &inputs {
        source.input(input);
        session.handle(input, &mut source, &mut output).unwrap();
    }
    let summary = session.summary();
    assert_eq!(summary.totals.net_read.bytes, 100);
    assert_eq!(summary.totals.net_read.calls, 1);
    assert_eq!(summary.network_traffic.as_ref().unwrap().received_bytes, 200);
    output.summary(&summary).unwrap();
    let expected = output.into_inner();
    let mut text_live = Vec::new();
    text::write_summary(&mut text_live, &summary, 30, &Filter::ALL, None).unwrap();
    source.finish().unwrap();
    assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 3);
    let mut replay = record::parse(data.as_slice()).unwrap();
    let mut session = Session::new(replay.info.clone(), Filter::ALL, &mut replay.answers);
    let mut output = JsonSink::new(Vec::new(), false);
    output.start(&replay.info).unwrap();
    for input in &replay.inputs {
        session.handle(input, &mut replay.answers, &mut output).unwrap();
    }
    output.summary(&session.summary()).unwrap();
    assert_eq!(output.into_inner(), expected);
    let mut text_replay = Vec::new();
    text::write_summary(&mut text_replay, &session.summary(), 30, &Filter::ALL, None).unwrap();
    assert_eq!(text_replay, text_live);
    let json = String::from_utf8(expected).unwrap();
    assert!(json.contains("\"type\":\"network_sample\""));
    assert!(json.contains("\"type\":\"event\""));
}

fn key(app: &mut App, session: &Session, ch: char) {
    app.key(
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
        session,
        BASE + 2_000_000_001,
    );
}

fn rendered(app: &mut App, session: &Session, width: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
    let shown = app.model.shown(session, BASE + 2_000_000_001);
    terminal
        .draw(|frame| draw::draw(frame, &mut app.view, &shown))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect()
}

#[test]
fn traffic_and_syscall_views_pause_reset_and_render_separately() {
    let (info, mut fixed, inputs) = fixture();
    let mut session = Session::new(info, Filter::ALL, &mut fixed);
    let mut app = App::default();
    app.view.tab = Tab::Network;
    for input in &inputs {
        session.handle(input, &mut fixed, &mut app).unwrap();
    }
    assert!(app.model.shown(&session, BASE).traffic);
    assert_eq!(app.model.shown(&session, BASE).stats.totals().net_read.bytes, 200);
    let traffic = rendered(&mut app, &session, 120);
    assert!(traffic.contains("Network: Traffic"));
    assert!(traffic.contains("CONNS"));
    assert!(!traffic.contains("CALLS"));
    assert!(!traffic.contains("FAILED"));
    rendered(&mut app, &session, 50);
    key(&mut app, &session, 'v');
    assert_eq!(app.model.shown(&session, BASE).stats.totals().net_read.bytes, 100);
    assert!(rendered(&mut app, &session, 120).contains("CALLS"));
    key(&mut app, &session, 'p');
    key(&mut app, &session, 'v');
    assert!(app.model.shown(&session, BASE).paused);
    assert_eq!(app.model.shown(&session, BASE).stats.totals().net_read.bytes, 200);
    key(&mut app, &session, 'r');
    assert_eq!(app.model.shown(&session, BASE).stats.totals().net_read.bytes, 0);
    assert_eq!(session.summary().network_traffic.unwrap().received_bytes, 200);
    key(&mut app, &session, 'v');
    assert_eq!(app.model.shown(&session, BASE).stats.totals().net_read.bytes, 0);
    app.message("showing host names".into());
    app.view.names = true;
    assert!(rendered(&mut app, &session, 100).contains("showing host names"));
}

#[test]
fn unavailable_statistics_are_visible_and_quiet_keeps_status_but_not_samples() {
    let (info, mut fixed, _) = fixture();
    let mut session = Session::new(info, Filter::ALL, &mut fixed);
    let mut app = App::default();
    app.view.tab = Tab::Network;
    let status = Status {
        time_ns: BASE,
        state: State::Unavailable,
        reason: Some("statistics unavailable; syscall tracing continues".into()),
    };
    session
        .handle(
            &Input::Network(traffic::Input::Status(status.clone())),
            &mut fixed,
            &mut app,
        )
        .unwrap();
    assert!(!app.model.shown(&session, BASE).traffic);
    assert!(rendered(&mut app, &session, 120).contains("statistics unavailable"));
    let mut output = JsonSink::new(Vec::new(), true);
    output.network(&traffic::Update::Status(status)).unwrap();
    let sample = traffic::Sample {
        time_ns: BASE + 1,
        interval_start_ns: BASE,
        source: 1,
        process_id: 1,
        pid: 5,
        target: Endpoint::unresolved(Proto::Udp),
        interface: Via::Unknown,
        received_bytes: 10,
        sent_bytes: 0,
    };
    output.network(&traffic::Update::Sample(sample)).unwrap();
    let output = String::from_utf8(output.into_inner()).unwrap();
    assert!(output.contains("network_status"));
    assert!(!output.contains("network_sample"));
}

#[test]
fn interface_filters_apply_to_measured_bytes_and_file_only_omits_them() {
    for (filter, expected) in [
        (
            Filter {
                interfaces: vec!["en0".into()],
                ..Filter::ALL
            },
            Some(200),
        ),
        (
            Filter {
                interfaces: vec!["en1".into()],
                ..Filter::ALL
            },
            Some(0),
        ),
        (
            Filter {
                network: false,
                ..Filter::ALL
            },
            None,
        ),
    ] {
        let (info, mut fixed, inputs) = fixture();
        let mut session = Session::new(info, filter, &mut fixed);
        let mut sink = JsonSink::new(Vec::new(), false);
        for input in &inputs {
            session.handle(input, &mut fixed, &mut sink).unwrap();
        }
        assert_eq!(
            session.summary().network_traffic.map(|s| s.received_bytes),
            expected
        );
    }
}

#[test]
fn measured_history_tolerates_late_intervals_and_extreme_timestamps() {
    let mut stats = iotap::stats::Stats::default();
    let mut sample = traffic::Sample {
        time_ns: 3_000_000_000,
        interval_start_ns: 2_000_000_000,
        source: 1,
        process_id: 1,
        pid: 5,
        target: Endpoint::unresolved(Proto::Tcp),
        interface: Via::Unknown,
        received_bytes: 100,
        sent_bytes: 0,
    };
    stats.record_traffic(&sample);
    sample.source = 2;
    sample.time_ns = 2_000_000_000;
    sample.interval_start_ns = 1_000_000_000;
    stats.record_traffic(&sample);
    assert_eq!(
        stats
            .history()
            .iter()
            .map(|s| (s.unix_sec, s.net_read))
            .collect::<Vec<_>>(),
        [(1, 100), (2, 100)]
    );
    assert_eq!(
        stats.summary_rows(iotap::model::Category::Network)[0].connections,
        Some(2)
    );
    sample.time_ns = u64::MAX;
    sample.interval_start_ns = u64::MAX - 1_000_000_000;
    stats.record_traffic(&sample);
    assert_eq!(stats.totals().net_read.bytes, 300);
}
