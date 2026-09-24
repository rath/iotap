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
use crate::output::json::JsonSink;
use crate::output::text::{self, TextSink};
use crate::reader::{self, ReaderConfig};
use crate::record::{self, Answers, Recorder, Recording};
use crate::session::{Discard, Filter, Input, Session, SessionInfo, Sink, Summary};
use crate::sys;
use crate::sys::kdebug::{self, Kdebug, KdebugConfig, KdebugError, TypeFilter};
use crate::sys::time::{self, ClockAnchor, Timebase};
use crate::target::{self, Spec, Tracked};
use crate::trace::codes;
use crate::trace::pairing::PathRecords;
use crate::trace::procs::{Live, ProcSource};
use crate::tui::state::{App, Tab};
use crate::tui::{self, Feed};

/// Process source of a live trace: libproc, optionally recorded to a file.
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

    fn summary(self, summary: &Summary, cli: &Cli) -> io::Result<()> {
        match self {
            Self::Text(sink) => {
                let mut out = sink.into_inner();
                text::write_summary(&mut out, summary, cli.top, filter(cli))?;
                out.flush()
            }
            Self::Json(mut sink) => sink.summary(summary),
        }
    }
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

/// What the session reports, from the command-line filters.
pub fn filter(cli: &Cli) -> Filter {
    Filter {
        files: !cli.net_only,
        network: !cli.files_only,
        other: !cli.files_only && !cli.net_only,
    }
}

/// The terminal UI's tabs: `--quiet` leaves out individual events there too.
fn tabs(cli: &Cli) -> &'static [Tab] {
    if cli.quiet { &Tab::TARGETS } else { &Tab::ALL }
}

/// Classes the kernel records: BSD syscalls, file-system lookups and process lifecycle.
pub fn type_filter() -> TypeFilter {
    let mut filter = TypeFilter::default();
    filter
        .allow(codes::CLASS_BSD, codes::SUBCLASS_BSD_SYSCALL)
        .allow(codes::CLASS_FSYSTEM, codes::SUBCLASS_FSRW)
        .allow(codes::CLASS_BSD, codes::SUBCLASS_BSD_PROC);
    filter
}

fn trace_live(cli: &Cli) -> Result<ExitCode> {
    if !sys::is_root() {
        bail!(KdebugError::NotPermitted);
    }
    let own_pid = i32::try_from(std::process::id())?;
    let specs: Vec<Spec> = cli.targets.iter().map(|raw| Spec::parse(raw, cli.name)).collect();
    let tracked = target::resolve(&specs, own_pid)?;
    let follow: Vec<String> = specs
        .iter()
        .filter_map(|spec| match spec {
            Spec::Name(name) => Some(name.clone()),
            Spec::Pid(_) => None,
        })
        .collect();

    let timebase = Timebase::host();
    let anchor = ClockAnchor::now();
    let pids = tracked.iter().map(|t| t.pid).collect();
    let kd = Kdebug::start(&KdebugConfig {
        buffer_events: cli.buffer,
        filter: type_filter(),
        pids,
    })?;
    let info = SessionInfo {
        timebase,
        anchor,
        processes: tracked.iter().map(Tracked::process).collect(),
        path_records: sys::os_release().map_or_else(PathRecords::default, |r| PathRecords::for_release(&r)),
    };
    let recorder = match &cli.record {
        Some(path) => {
            Some(Recorder::create(path, &info).with_context(|| format!("cannot create {}", path.display()))?)
        }
        None => None,
    };
    // Said once the kernel records the targets' calls and the recording, if any, is open.
    announce(&tracked, &follow, cli.tui);
    let mut src = Recording::new(Live, recorder);
    let mut session = Session::new(info, filter(cli), &mut src);

    let stop = Arc::new(AtomicBool::new(false));
    let interrupted = watch_signals(&stop)?;
    let config = ReaderConfig {
        follow,
        // Short, so that libproc is asked about new descriptors before most are closed again.
        wait: Duration::from_millis(10),
        poll: Duration::from_millis(250),
        own_pid,
    };
    let deadline = cli
        .duration
        .map(|secs| Instant::now() + Duration::from_secs(secs));
    // The terminal UI prints its summary as text once the terminal is restored.
    let mut printer = if cli.tui {
        None
    } else {
        Some(Printer::new(cli, session.info())?)
    };

    let (tx, rx) = mpsc::channel();
    let (kd_ref, stop_ref, config_ref) = (&kd, &*stop, &config);
    let (consumed, read) = thread::scope(|scope| {
        let reader = thread::Builder::new()
            .name("kdebug-reader".into())
            .spawn_scoped(scope, move || {
                reader::run(kd_ref, tracked, config_ref, &tx, stop_ref)
            })
            .context("cannot start the kernel reader")?;
        let mut input = LiveInput {
            rx: &rx,
            src: &mut src,
            stop: stop_ref,
            deadline,
            expired: false,
            reported: false,
        };
        let consumed = match printer.as_mut() {
            Some(printer) => consume(&mut input, &mut session, printer.sink()),
            None => watch_live(&mut input, &mut session, &interrupted, tabs(cli)),
        };
        stop_ref.store(true, Ordering::SeqCst);
        let read = reader.join().map_err(|_| anyhow!("the kernel reader panicked"))?;
        anyhow::Ok((consumed, read))
    })?;
    // Give the trace facility back before anything else can fail.
    drop(kd);

    let saved = src.finish();
    let (printer, failed) = match printer {
        Some(printer) => (printer, WRITE_FAILED),
        None => (Printer::new(cli, session.info())?, TUI_FAILED),
    };
    if !finish_output(consumed, failed)?
        || !finish_output(printer.summary(&session.summary(), cli), WRITE_FAILED)?
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
    /// Waits up to `wait` for the next input and hands it to the session.
    fn step(&mut self, session: &mut Session, sink: &mut dyn Sink, wait: Duration) -> io::Result<Step> {
        if !self.expired && self.deadline.is_some_and(|at| Instant::now() >= at) {
            self.expired = true;
            self.stop.store(true, Ordering::SeqCst);
        }
        let input = match self.rx.recv_timeout(wait) {
            Ok(input) => input,
            Err(RecvTimeoutError::Timeout) => return Ok(Step::Idle),
            Err(RecvTimeoutError::Disconnected) => return Ok(Step::Closed),
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
    tabs: &'static [Tab],
) -> io::Result<()> {
    let mut feed = LiveFeed {
        input,
        interrupted,
        ended: false,
    };
    let shown = tui::run(session, &mut feed, tabs);
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
    let replay = record::read(path).with_context(|| format!("cannot replay {}", path.display()))?;
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
        .map(|p| format!("{} ({})", p.pid, p.name))
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
        if finish_output(tui::run(&mut session, &mut feed, tabs(cli)), TUI_FAILED)? {
            // The summary covers the whole recording, as it does without --tui.
            for input in feed.inputs.by_ref() {
                session.handle(&input, &mut feed.answers, &mut Discard)?;
            }
            session.finish(&mut Discard)?;
            let printer = Printer::new(cli, session.info())?;
            finish_output(printer.summary(&session.summary(), cli), WRITE_FAILED)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
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
        finish_output(printer.summary(&session.summary(), cli), WRITE_FAILED)?;
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

fn announce(tracked: &[Tracked], follow: &[String], tui: bool) {
    let list: Vec<String> = tracked
        .iter()
        .map(|t| format!("{} ({})", t.pid, t.name))
        .collect();
    let what = match list.len() {
        1 => list[0].clone(),
        n => format!("{n} processes: {}", list.join(", ")),
    };
    let also = if follow.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = follow.iter().map(|n| format!("'{n}'")).collect();
        format!(", and new processes named {}", names.join(" or "))
    };
    let how = if tui {
        "press q to quit"
    } else {
        "press Ctrl-C to stop"
    };
    let _ = writeln!(io::stderr(), "iotap: tracing {what}{also}; {how}");
}

/// The first signal asks for a clean stop: it sets `stop` and the returned flag. A second one
/// releases the trace facility, restores the terminal and exits at once, in case output is
/// blocked.
fn watch_signals(stop: &Arc<AtomicBool>) -> Result<Arc<AtomicBool>> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let (stop, flag) = (Arc::clone(stop), Arc::clone(&interrupted));
    thread::Builder::new().name("signals".into()).spawn(move || {
        for (received, _) in signals.forever().enumerate() {
            if received == 0 {
                flag.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
            } else {
                kdebug::release();
                tui::emergency_restore();
                std::process::exit(130);
            }
        }
    })?;
    Ok(interrupted)
}

/// Releases the trace facility before the default panic output. The terminal UI installs its
/// own hook on top, so a panic restores the terminal first.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        kdebug::release();
        previous(info);
    }));
}

fn dump_fds(pid: i32) -> Result<ExitCode> {
    let snapshot = Live
        .snapshot(pid)
        .with_context(|| format!("cannot read the descriptors of pid {pid}"))?;
    let mut out = io::stdout().lock();
    if let Some(cwd) = &snapshot.cwd {
        writeln!(out, " cwd  {cwd}")?;
    }
    for (fd, target) in &snapshot.fds {
        writeln!(out, "{fd:>4}  {target}")?;
    }
    Ok(ExitCode::SUCCESS)
}
