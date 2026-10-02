//! Wires the command line to the kernel reader, the session and the chosen output.

use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use crate::cli::Cli;
use crate::hosts::Hosts;
use crate::interfaces::Table;
use crate::output::json::JsonSink;
use crate::output::printable;
use crate::output::text::{self, TextSink};
use crate::reader::{self, ReaderConfig};
use crate::record::{self, Answers, Recorder, Recording};
use crate::session::{Discard, Filter, Input, Session, SessionInfo, Sink, Summary};
use crate::sys::time::{self, ClockAnchor, Timebase};
use crate::sys::{self, Facility, FacilityError};
use crate::target::{self, Spec, Tracked};
use crate::trace::System;
use crate::trace::procs::{Live, ProcSource, Snapshot};
use crate::tui::state::{App, Tab};
use crate::tui::{self, Feed};

/// Process source of a live trace: libproc or `/proc`, optionally recorded to a file.
type LiveSource = Recording<Live, BufWriter<File>>;

type Stdout = BufWriter<io::StdoutLock<'static>>;

/// Contexts for failures of the output and of the terminal UI.
const WRITE_FAILED: &str = "cannot write output";
const TUI_FAILED: &str = "the terminal UI failed";

/// The stdout format chosen on the command line.
enum Printer {
    Text(TextSink<Stdout>),
    Json(JsonSink<Stdout>),
}

impl Printer {
    fn new(cli: &Cli, info: &SessionInfo) -> io::Result<Self> {
        let out = BufWriter::with_capacity(1 << 16, io::stdout().lock());
        if cli.json {
            let mut sink = JsonSink::new(out, cli.quiet);
            sink.start(info)?;
            Ok(Self::Json(sink))
        } else {
            Ok(Self::Text(TextSink::new(out, cli.quiet)))
        }
    }

    fn sink(&mut self) -> &mut dyn Sink {
        match self {
            Self::Text(sink) => sink,
            Self::Json(sink) => sink,
        }
    }

    /// Writes the summary; as text, with the host names `hosts` finds for its network rows.
    fn summary(self, summary: &Summary, cli: &Cli, mut hosts: Option<Hosts>) -> io::Result<()> {
        match self {
            Self::Text(sink) => {
                let mut out = sink.into_inner();
                text::write_summary(&mut out, summary, cli.top, &filter(cli), hosts.as_mut())?;
                out.flush()
            }
            Self::Json(mut sink) => sink.summary(summary),
        }
    }
}

/// What shows the session's output while tracing.
enum Output {
    Printer(Printer),
    /// The terminal UI, which prints its summary as text once the terminal is restored.
    Tui(Box<App>),
}

/// Runs iotap as the command line asks.
pub fn run(cli: &Cli) -> Result<ExitCode> {
    install_panic_hook();
    if let Some(pid) = cli.dump_fds {
        return dump_fds(pid);
    }
    if cli.tui && !io::stdout().is_terminal() {
        bail!("--tui needs a terminal, but stdout is redirected");
    }
    if let Some(path) = &cli.replay {
        return replay(cli, path);
    }
    trace_live(cli)
}

/// What the session reports, from the command-line filters. Only network I/O goes over an
/// interface, so naming interfaces leaves out file and other I/O.
pub fn filter(cli: &Cli) -> Filter {
    let network_only = cli.net_only || !cli.interfaces.is_empty();
    Filter {
        files: !network_only,
        network: !cli.files_only,
        other: !cli.files_only && !network_only,
        interfaces: cli.interfaces.clone(),
    }
}

/// What to tell of the interfaces `wanted` that `table` does not list, when the table comes
/// from the system or, for `replay`, from a recording.
fn interface_warnings(wanted: &[String], table: &Table, replay: bool) -> Vec<String> {
    if wanted.is_empty() {
        return Vec::new();
    }
    if table.is_empty() {
        return vec![if replay {
            "the recording lists no network interfaces, so --interface matches no I/O".to_owned()
        } else {
            "the system listed no network interfaces, so --interface matches no I/O".to_owned()
        }];
    }
    wanted
        .iter()
        .filter(|name| table.names().all(|known| known != name.as_str()))
        .map(|name| {
            let missing = if replay {
                format!("the recording lists no network interface named '{name}'")
            } else {
                format!("no network interface is named '{name}'")
            };
            match table.names().find(|known| known.eq_ignore_ascii_case(name)) {
                Some(like) => format!("{missing}; did you mean '{like}'?"),
                None => missing,
            }
        })
        .collect()
}

/// Tells of the interfaces `-i` names that the session's table does not list, on stderr and,
/// in the terminal UI, in the status line, which hides stderr.
fn warn_of_interfaces(cli: &Cli, session: &Session, app: Option<&mut App>) {
    let warnings = interface_warnings(&cli.interfaces, session.interfaces(), cli.replay.is_some());
    for warning in &warnings {
        let _ = writeln!(io::stderr(), "iotap: {warning}");
    }
    if let Some(app) = app
        && !warnings.is_empty()
    {
        app.message(warnings.join("; "));
    }
}

/// The terminal UI for the command line: without an Events tab for `--quiet`, and showing host
/// names from the start for `--resolve`.
fn tui_app(cli: &Cli) -> App {
    let mut app = App::new(if cli.quiet { &Tab::TARGETS } else { &Tab::ALL });
    app.view.names = cli.resolve;
    app
}

/// The host names for the summary printed after the terminal UI: those it showed as it quit.
fn shown_hosts(app: &mut App) -> Option<Hosts> {
    app.view.names.then(|| std::mem::take(&mut app.view.hosts))
}

fn trace_live(cli: &Cli) -> Result<ExitCode> {
    if !sys::is_root() {
        bail!(FacilityError::NotPermitted);
    }
    let own_pid = i32::try_from(std::process::id())?;
    // Before anything is configured, so that no signal ends iotap while the trace facility is
    // held and there is no release to run: starting it alone takes a fifth of a second on macOS.
    // A signal that arrives on the way only sets `stop`, which the reader and the consumer see.
    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = watch_signals(&stop)?;
    let targets = Targets::resolve(cli, own_pid)?;

    let timebase = Timebase::host();
    let anchor = ClockAnchor::now();
    #[cfg(target_os = "macos")]
    let network = filter(cli)
        .network
        .then(|| sys::network_stats::Collector::start(&targets.tracked, anchor, timebase));
    let pids: Vec<i32> = targets.tracked.iter().map(|t| t.pid).collect();
    let mut facility = Facility::start(cli.buffer, &pids, cli.children)?;
    let info = SessionInfo {
        timebase,
        anchor,
        processes: targets.tracked.iter().map(Tracked::process).collect(),
        path_records: Facility::path_records(),
        system: System::HOST,
    };
    let recorder = match &cli.record {
        Some(path) => {
            Some(Recorder::create(path, &info).with_context(|| format!("cannot create {}", path.display()))?)
        }
        None => None,
    };
    // Said once the kernel records the targets' calls and the recording, if any, is open.
    let _ = writeln!(io::stderr(), "iotap: {}", targets.announcement(cli));
    let mut src = Recording::new(Live, recorder);
    let mut session = Session::new(info, filter(cli), &mut src);

    let config = ReaderConfig {
        follow: targets.follow,
        checked: targets.listed,
        children: cli.children,
        // Short, so that the system is asked about new descriptors before most are closed again.
        wait: Duration::from_millis(10),
        poll: Duration::from_millis(250),
        own_pid,
    };
    let deadline = deadline(cli.duration, Instant::now());
    let mut output = if cli.tui {
        Output::Tui(Box::new(tui_app(cli)))
    } else {
        Output::Printer(Printer::new(cli, session.info())?)
    };
    match &mut output {
        Output::Tui(app) => warn_of_interfaces(cli, &session, Some(app)),
        Output::Printer(_) => warn_of_interfaces(cli, &session, None),
    }

    let (tx, rx) = mpsc::channel();
    let (facility_ref, stop_ref, config_ref) = (&mut facility, &*stop, &config);
    let (consumed, read) = thread::scope(|scope| {
        let reader = thread::Builder::new()
            .name("kernel-reader".into())
            .spawn_scoped(scope, move || {
                reader::run(facility_ref, targets.tracked, config_ref, &tx, stop_ref)
            })
            .context("cannot start the kernel reader")?;
        let _stops_reader = StopOnDrop(stop_ref);
        let mut input = LiveInput {
            rx: &rx,
            src: &mut src,
            stop: stop_ref,
            deadline,
            expired: false,
            reported: false,
            #[cfg(target_os = "macos")]
            network,
        };
        let consumed = match &mut output {
            Output::Printer(printer) => consume(&mut input, &mut session, printer.sink()),
            Output::Tui(app) => watch_live(&mut input, &mut session, &interrupted, app),
        };
        stop_ref.store(true, Ordering::SeqCst);
        let read = reader.join().map_err(|_| anyhow!("the kernel reader panicked"))?;
        anyhow::Ok((consumed, read))
    })?;
    // Give the trace facility back before anything else can fail.
    drop(facility);

    let saved = src.finish();
    let (printer, hosts, failed) = match output {
        Output::Printer(printer) => (printer, cli.resolve.then(Hosts::system), WRITE_FAILED),
        Output::Tui(mut app) => (
            Printer::new(cli, session.info())?,
            shown_hosts(&mut app),
            TUI_FAILED,
        ),
    };
    if !finish_output(consumed, failed)?
        || !finish_output(printer.summary(&session.summary(), cli, hosts), WRITE_FAILED)?
    {
        return Ok(ExitCode::SUCCESS);
    }
    read?;
    if let Some(path) = &cli.record {
        saved.with_context(|| format!("the recording {} is incomplete", path.display()))?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Live input: what the reader thread sends, saved as it arrives when recording.
struct LiveInput<'a> {
    #[cfg(target_os = "macos")]
    network: Option<sys::network_stats::Collector>,
    rx: &'a Receiver<Input>,
    src: &'a mut LiveSource,
    stop: &'a AtomicBool,
    deadline: Option<Instant>,
    /// Set once the deadline has stopped tracing.
    expired: bool,
    /// Set once a recording failure has been reported.
    reported: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Nothing arrived in time.
    Idle,
    Handled,
    /// The reader stopped tracing; nothing follows.
    Stopped,
    /// The reader went away without stopping, which means it failed.
    Closed,
}

impl LiveInput<'_> {
    #[cfg(target_os = "macos")]
    fn network_step(&mut self, session: &mut Session, sink: &mut dyn Sink) -> io::Result<()> {
        if let Some(network) = &mut self.network {
            for data in network.drain() {
                let input = Input::Network(data);
                self.src.input(&input);
                session.handle(&input, self.src, sink)?;
            }
        }
        Ok(())
    }

    /// Waits up to `wait` for the next input and hands it to the session.
    fn step(&mut self, session: &mut Session, sink: &mut dyn Sink, wait: Duration) -> io::Result<Step> {
        #[cfg(target_os = "macos")]
        self.network_step(session, sink)?;
        if !self.expired && self.deadline.is_some_and(|at| Instant::now() >= at) {
            self.expired = true;
            self.stop.store(true, Ordering::SeqCst);
        }
        let input = match self.rx.recv_timeout(wait) {
            Ok(input) => input,
            Err(RecvTimeoutError::Timeout) => return Ok(Step::Idle),
            Err(RecvTimeoutError::Disconnected) => {
                #[cfg(target_os = "macos")]
                {
                    if let Some(network) = &mut self.network {
                        network.finish();
                    }
                    self.network_step(session, sink)?;
                }
                return Ok(Step::Closed);
            }
        };
        #[cfg(target_os = "macos")]
        let input = {
            match &input {
                Input::Attached { process, .. } => {
                    if let Some(network) = &self.network {
                        let info = session.info();
                        network.add_pid(
                            process.pid,
                            info.anchor.unix_nanos_at(info.timebase, time::now_ticks()),
                        );
                    }
                }
                Input::Stopped { .. } => {
                    if let Some(network) = &mut self.network {
                        network.finish();
                    }
                    self.network_step(session, sink)?;
                }
                _ => {}
            }
            if matches!(input, Input::Stopped { .. }) && self.network.is_some() {
                Input::Stopped {
                    ticks: time::now_ticks(),
                }
            } else {
                input
            }
        };
        self.src.input(&input);
        session.handle(&input, self.src, sink)?;
        sink.flush()?;
        Ok(if matches!(input, Input::Stopped { .. }) {
            Step::Stopped
        } else {
            Step::Handled
        })
    }

    /// Describes a recording failure, once.
    fn recording_error(&mut self) -> Option<String> {
        if self.reported {
            return None;
        }
        let err = self.src.error()?;
        self.reported = true;
        Some(format!("recording stopped: {err}; tracing continues"))
    }
}

/// Feeds live input to the session until tracing stops or the reader goes away.
fn consume(input: &mut LiveInput<'_>, session: &mut Session, sink: &mut dyn Sink) -> io::Result<()> {
    loop {
        let step = input.step(session, sink, Duration::from_millis(100))?;
        if let Some(message) = input.recording_error() {
            let _ = writeln!(io::stderr(), "iotap: {message}");
        }
        if matches!(step, Step::Stopped | Step::Closed) {
            return session.finish(sink);
        }
    }
}

/// Shows live input in the terminal UI until the user quits, then takes in what the reader
/// still delivers so the summary covers every record read from the kernel.
fn watch_live(
    input: &mut LiveInput<'_>,
    session: &mut Session,
    interrupted: &AtomicBool,
    app: &mut App,
) -> io::Result<()> {
    let mut feed = LiveFeed {
        input,
        interrupted,
        ended: false,
    };
    let shown = tui::run(session, &mut feed, app);
    let ended = feed.ended;
    input.stop.store(true, Ordering::SeqCst);
    let drained = if ended {
        Ok(())
    } else {
        consume(input, session, &mut Discard)
    };
    shown.and(drained)
}

/// Live input for the terminal UI.
struct LiveFeed<'a, 'b> {
    input: &'a mut LiveInput<'b>,
    interrupted: &'a AtomicBool,
    /// Set once the reader has stopped or gone away.
    ended: bool,
}

impl Feed for LiveFeed<'_, '_> {
    fn pump(&mut self, session: &mut Session, app: &mut App, until: Instant) -> io::Result<Option<String>> {
        loop {
            let wait = until.saturating_duration_since(Instant::now());
            let step = self.input.step(session, app, wait)?;
            if let Some(message) = self.input.recording_error() {
                app.message(message);
            }
            match step {
                Step::Idle => return Ok(None),
                Step::Handled if Instant::now() >= until => return Ok(None),
                Step::Handled => {}
                Step::Stopped => {
                    self.ended = true;
                    let why = if self.input.expired {
                        "the --duration limit was reached"
                    } else if session.all_exited() {
                        "every traced process has exited"
                    } else {
                        "tracing was interrupted"
                    };
                    return Ok(Some(format!("Tracing stopped: {why}.")));
                }
                Step::Closed => {
                    self.ended = true;
                    session.finish(app)?;
                    return Ok(Some(
                        "The kernel reader failed; its error follows the summary.".to_owned(),
                    ));
                }
            }
        }
    }

    fn now_ns(&self, session: &Session) -> u64 {
        if self.ended {
            return session.now_ns();
        }
        let info = session.info();
        info.anchor.unix_nanos_at(info.timebase, time::now_ticks())
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}

/// A recording, fed to the terminal UI as fast as the session takes it.
struct ReplayFeed<'a> {
    inputs: std::vec::IntoIter<Input>,
    answers: Answers,
    interrupted: &'a AtomicBool,
}

impl Feed for ReplayFeed<'_> {
    fn pump(&mut self, session: &mut Session, app: &mut App, until: Instant) -> io::Result<Option<String>> {
        for input in self.inputs.by_ref() {
            session.handle(&input, &mut self.answers, app)?;
            if Instant::now() >= until {
                return Ok(None);
            }
        }
        session.finish(app)?;
        Ok(Some("End of the recording.".to_owned()))
    }

    fn now_ns(&self, session: &Session) -> u64 {
        session.now_ns()
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}

/// Replays a recording through the same session and output as a live trace.
fn replay(cli: &Cli, path: &Path) -> Result<ExitCode> {
    let replay = record::read(path)
        .and_then(|replay| record::check_system(&replay.info).map(|()| replay))
        .with_context(|| format!("cannot replay {}", path.display()))?;
    if replay.truncated {
        let _ = writeln!(
            io::stderr(),
            "iotap: the recording ends abruptly; replaying what it holds"
        );
    }
    let processes: Vec<String> = replay
        .info
        .processes
        .iter()
        .map(|p| format!("{} ({})", p.pid, printable(&p.name)))
        .collect();
    let _ = writeln!(
        io::stderr(),
        "iotap: replaying {} ({}): {}",
        path.display(),
        replay.created_by,
        processes.join(", ")
    );
    let mut answers = replay.answers;
    let mut session = Session::new(replay.info, filter(cli), &mut answers);
    if cli.tui {
        // A replay has nothing to stop; only the request to quit matters.
        let interrupted = watch_signals(&Arc::new(AtomicBool::new(false)))?;
        let mut feed = ReplayFeed {
            inputs: replay.inputs.into_iter(),
            answers,
            interrupted: &interrupted,
        };
        let mut app = tui_app(cli);
        warn_of_interfaces(cli, &session, Some(&mut app));
        if finish_output(tui::run(&mut session, &mut feed, &mut app), TUI_FAILED)? {
            // The summary covers the whole recording, as it does without --tui.
            for input in feed.inputs.by_ref() {
                session.handle(&input, &mut feed.answers, &mut Discard)?;
            }
            session.finish(&mut Discard)?;
            let printer = Printer::new(cli, session.info())?;
            let hosts = shown_hosts(&mut app);
            finish_output(printer.summary(&session.summary(), cli, hosts), WRITE_FAILED)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    warn_of_interfaces(cli, &session, None);
    let mut printer = Printer::new(cli, session.info())?;
    let sink = printer.sink();
    let fed = replay
        .inputs
        .iter()
        .try_for_each(|input| {
            session.handle(input, &mut answers, sink)?;
            sink.flush()
        })
        .and_then(|()| session.finish(sink))
        .and_then(|()| sink.flush());
    if finish_output(fed, WRITE_FAILED)? {
        let hosts = cli.resolve.then(Hosts::system);
        finish_output(printer.summary(&session.summary(), cli, hosts), WRITE_FAILED)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// False when stdout was closed by its reader, as with `| head`, which is not an error.
fn finish_output(result: io::Result<()>, failed: &'static str) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err).context(failed),
    }
}

/// What the command line asks to trace.
struct Targets {
    /// The processes to trace from the start: those the targets name, then with `--children`
    /// their running descendants.
    tracked: Vec<Tracked>,
    /// How many of `tracked` the targets name.
    named: usize,
    /// Names whose new processes are traced too.
    follow: Vec<String>,
    /// The processes the names were matched against, which are not new.
    listed: Vec<Tracked>,
}

impl Targets {
    fn resolve(cli: &Cli, own_pid: i32) -> Result<Self> {
        let specs: Vec<Spec> = cli.targets.iter().map(|raw| Spec::parse(raw, cli.name)).collect();
        let target::Resolved { mut tracked, listed } = target::resolve(&specs, own_pid)?;
        let named = tracked.len();
        if cli.children {
            // Traced from the start, as the processes the targets name are.
            let roots: Vec<i32> = tracked.iter().map(|t| t.pid).collect();
            tracked.extend(target::descendants(&roots, own_pid));
        }
        let follow = specs
            .into_iter()
            .filter_map(|spec| match spec {
                Spec::Name(name) => Some(name),
                Spec::Pid(_) => None,
            })
            .collect();
        Ok(Self {
            tracked,
            named,
            follow,
            listed,
        })
    }

    /// Says what iotap traces: the processes the targets name, new processes of the followed
    /// names, and with `--children` every descendant.
    fn announcement(&self, cli: &Cli) -> String {
        let (targets, running) = self.tracked.split_at(self.named);
        let list: Vec<String> = targets
            .iter()
            .map(|t| format!("{} ({})", t.pid, printable(&t.name)))
            .collect();
        let mut what = vec![match list.len() {
            1 => list[0].clone(),
            n => format!("{n} processes: {}", list.join(", ")),
        }];
        if !self.follow.is_empty() {
            let names: Vec<String> = self.follow.iter().map(|n| format!("'{n}'")).collect();
            what.push(format!("new processes named {}", names.join(" or ")));
        }
        if cli.children {
            let whose = if what.len() == 1 && list.len() == 1 {
                "its"
            } else {
                "their"
            };
            what.push(match running.len() {
                0 => format!("{whose} descendants"),
                n => format!("{whose} descendants ({n} running now)"),
            });
        }
        if let [_, .., last] = &mut what[..] {
            *last = format!("and {last}");
        }
        let how = if cli.tui {
            "press q to quit"
        } else {
            "press Ctrl-C to stop"
        };
        let only = if cli.interfaces.is_empty() {
            String::new()
        } else {
            format!(
                "; reporting only network I/O over {}",
                cli.interfaces.join(" or ")
            )
        };
        format!("tracing {}{only}; {how}", what.join(", "))
    }
}

/// When a trace of `secs` seconds that begins at `now` ends. A duration beyond what the clock
/// can add, which is longer than anyone will wait, has no end.
fn deadline(secs: Option<u64>, now: Instant) -> Option<Instant> {
    now.checked_add(Duration::from_secs(secs?))
}

/// Sets a flag when dropped. A panic in the thread that consumes the reader's input unwinds
/// through the thread scope, which waits for the reader before it goes on; this stops the
/// reader, so that the process ends instead of tracing on with nobody to hear it.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// How long the terminal UI has to leave once iotap is asked to stop.
const UI_GRACE: Duration = Duration::from_secs(2);

/// The first signal asks for a clean stop: it sets `stop` and the returned flag. A second one
/// gives up at once, in case output is blocked, and so does the first when the terminal UI is
/// still there [`UI_GRACE`] later: a terminal that has hung up leaves the UI stuck in reading
/// its events, and it never gets to see the flag.
///
/// Every signal that ends a process by default, and that someone can send it, asks for the stop
/// rather than ends iotap: dying of one would skip the release of the trace facility.
fn watch_signals(stop: &Arc<AtomicBool>) -> Result<Arc<AtomicBool>> {
    use signal_hook::consts::{SIGALRM, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};
    let mut signals =
        signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM])?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let (stop, flag) = (Arc::clone(stop), Arc::clone(&interrupted));
    thread::Builder::new().name("signals".into()).spawn(move || {
        for (received, _) in signals.forever().enumerate() {
            if received == 0 {
                flag.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
                let _ = thread::Builder::new().name("ui-watchdog".into()).spawn(|| {
                    thread::sleep(UI_GRACE);
                    if tui::is_active() {
                        give_up();
                    }
                });
            } else {
                give_up();
            }
        }
    })?;
    Ok(interrupted)
}

/// Ends iotap at once, for when the clean stop does not happen: releases the trace facility,
/// restores the terminal and exits as a process does that a signal interrupted.
fn give_up() -> ! {
    sys::release();
    tui::emergency_restore();
    std::process::exit(130)
}

/// Releases the trace facility before the default panic output. The terminal UI installs its
/// own hook on top, so a panic restores the terminal first.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        sys::release();
        previous(info);
    }));
}

fn dump_fds(pid: i32) -> Result<ExitCode> {
    let snapshot = Live
        .snapshot(pid)
        .with_context(|| format!("cannot read the descriptors of pid {pid}"))?;
    write_snapshot(&mut io::stdout().lock(), &snapshot)?;
    Ok(ExitCode::SUCCESS)
}

/// Writes the working directory and descriptors of `snapshot`, one to a line. The process names
/// them all, so control characters are written as `?`.
fn write_snapshot(out: &mut dyn Write, snapshot: &Snapshot) -> io::Result<()> {
    if let Some(cwd) = &snapshot.cwd {
        writeln!(out, " cwd  {}", printable(cwd))?;
    }
    for (fd, target) in &snapshot.fds {
        writeln!(out, "{fd:>4}  {}", printable(&target.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::interfaces::{Interface, Listing};

    fn process(pid: i32, name: &str) -> Tracked {
        Tracked {
            pid,
            name: name.into(),
            start: (0, 0),
            exe: None,
            arg0: None,
            parent: 1,
        }
    }

    #[test]
    fn the_announcement_says_what_is_traced() {
        let cli = |args: &[&str]| Cli::try_parse_from(["iotap"].iter().chain(args)).unwrap();
        let targets = |tracked: &[(i32, &str)], named, follow: &[&str]| Targets {
            tracked: tracked.iter().map(|&(pid, name)| process(pid, name)).collect(),
            named,
            follow: follow.iter().map(|&name| name.to_owned()).collect(),
            listed: Vec::new(),
        };
        let make = targets(&[(10, "make")], 1, &[]);
        assert_eq!(
            make.announcement(&cli(&["10"])),
            "tracing 10 (make); press Ctrl-C to stop"
        );
        assert_eq!(
            make.announcement(&cli(&["-f", "10"])),
            "tracing 10 (make), and its descendants; press Ctrl-C to stop"
        );
        let both = targets(&[(10, "make"), (20, "ninja"), (11, "sh"), (12, "cc")], 2, &[]);
        assert_eq!(
            both.announcement(&cli(&["-f", "--tui", "10", "20"])),
            "tracing 2 processes: 10 (make), 20 (ninja), and their descendants (2 running now); \
             press q to quit"
        );
        let followed = targets(&[(10, "make")], 1, &["make"]);
        assert_eq!(
            followed.announcement(&cli(&["make"])),
            "tracing 10 (make), and new processes named 'make'; press Ctrl-C to stop"
        );
        assert_eq!(
            followed.announcement(&cli(&["-f", "make"])),
            "tracing 10 (make), new processes named 'make', and their descendants; \
             press Ctrl-C to stop"
        );
        assert_eq!(
            make.announcement(&cli(&["-i", "wlP9s9", "-i", "lo", "10"])),
            "tracing 10 (make); reporting only network I/O over wlP9s9 or lo; press Ctrl-C to stop"
        );
    }

    #[test]
    fn interfaces_leave_out_file_and_other_io() {
        let cli = |args: &[&str]| Cli::try_parse_from(["iotap"].iter().chain(args)).unwrap();
        assert_eq!(filter(&cli(&["1"])), Filter::ALL);
        let only = filter(&cli(&["-i", "en0", "1"]));
        assert_eq!(
            (only.files, only.network, only.other, only.interfaces),
            (false, true, false, vec!["en0".to_owned()])
        );
    }

    #[test]
    fn warns_of_interfaces_the_table_does_not_list() {
        let listing = Listing {
            interfaces: ["lo", "wlP9s9"]
                .iter()
                .map(|&name| Interface {
                    name: name.into(),
                    index: 1,
                    loopback: name == "lo",
                    addrs: Vec::new(),
                })
                .collect(),
            netns: None,
        };
        let table = Table::new(listing, 0, 1);
        let wanted = |names: &[&str]| -> Vec<String> { names.iter().map(|&name| name.to_owned()).collect() };
        assert!(interface_warnings(&[], &table, false).is_empty());
        assert!(interface_warnings(&wanted(&["wlP9s9", "lo"]), &table, false).is_empty());
        assert_eq!(
            interface_warnings(&wanted(&["wlp9s9", "eth9"]), &table, false),
            [
                "no network interface is named 'wlp9s9'; did you mean 'wlP9s9'?",
                "no network interface is named 'eth9'"
            ]
        );
        assert_eq!(
            interface_warnings(&wanted(&["eth9"]), &table, true),
            ["the recording lists no network interface named 'eth9'"]
        );
        let empty = Table::new(Listing::default(), 0, 1);
        assert_eq!(
            interface_warnings(&wanted(&["eth9"]), &empty, true),
            ["the recording lists no network interfaces, so --interface matches no I/O"]
        );
    }

    #[test]
    fn a_duration_beyond_the_clock_is_no_deadline() {
        let now = Instant::now();
        assert_eq!(deadline(None, now), None);
        assert_eq!(deadline(Some(0), now), Some(now));
        assert_eq!(deadline(Some(90), now), Some(now + Duration::from_secs(90)));
        assert_eq!(deadline(Some(u64::MAX), now), None);
    }

    #[test]
    fn a_panic_in_the_consumer_stops_the_reader() {
        let stop = AtomicBool::new(false);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _stops_reader = StopOnDrop(&stop);
            panic!("the consumer failed");
        }));
        assert!(unwound.is_err());
        assert!(stop.load(Ordering::SeqCst));
        // And a normal end of the scope stops it just the same.
        let stop = AtomicBool::new(false);
        drop(StopOnDrop(&stop));
        assert!(stop.load(Ordering::SeqCst));
    }

    #[test]
    fn dumped_descriptors_cannot_act_on_the_terminal_or_forge_a_line() {
        // A directory and a file named by the process: each escapes the terminal's title and
        // starts a line that looks like one of the dump's.
        let hostile = "/tmp/a\x1b]0;pwned\x07\n   9  /etc/shadow";
        let snapshot = Snapshot {
            fds: vec![(3, crate::model::Target::File { path: hostile.into() })],
            cwd: Some(hostile.into()),
            netns: None,
        };
        let mut out = Vec::new();
        write_snapshot(&mut out, &snapshot).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            " cwd  /tmp/a?]0;pwned??   9  /etc/shadow\n   3  /tmp/a?]0;pwned??   9  /etc/shadow\n"
        );
    }
}
