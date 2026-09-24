//! Wires the command line to the kernel reader, the session and the chosen output.

use std::fs::File;
use std::io::{self, BufWriter, Write};
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
use crate::record::{self, Recorder, Recording};
use crate::session::{Filter, Input, Session, SessionInfo, Sink, Summary};
use crate::sys;
use crate::sys::kdebug::{self, Kdebug, KdebugConfig, KdebugError, TypeFilter};
use crate::sys::time::{ClockAnchor, Timebase};
use crate::target::{self, Spec, Tracked};
use crate::trace::codes;
use crate::trace::procs::{Live, ProcSource};

/// Process source of a live trace: libproc, optionally recorded to a file.
type LiveSource = Recording<Live, BufWriter<File>>;

type Stdout = BufWriter<io::StdoutLock<'static>>;

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
    announce(&tracked, &follow);

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
    };
    let recorder = match &cli.record {
        Some(path) => {
            Some(Recorder::create(path, &info).with_context(|| format!("cannot create {}", path.display()))?)
        }
        None => None,
    };
    let mut src = Recording::new(Live, recorder);
    let mut session = Session::new(info, filter(cli), &mut src);

    let stop = Arc::new(AtomicBool::new(false));
    watch_signals(&stop)?;
    let config = ReaderConfig {
        follow,
        wait: Duration::from_millis(50),
        poll: Duration::from_millis(250),
        own_pid,
    };
    let deadline = cli
        .duration
        .map(|secs| Instant::now() + Duration::from_secs(secs));
    let mut printer = Printer::new(cli, session.info())?;

    let (tx, rx) = mpsc::channel();
    let (kd_ref, stop_ref, config_ref) = (&kd, &*stop, &config);
    let (consumed, read) = thread::scope(|scope| {
        let reader = thread::Builder::new()
            .name("kdebug-reader".into())
            .spawn_scoped(scope, move || {
                reader::run(kd_ref, tracked, config_ref, &tx, stop_ref)
            })
            .context("cannot start the kernel reader")?;
        let consumed = consume(&rx, &mut session, &mut src, printer.sink(), stop_ref, deadline);
        stop_ref.store(true, Ordering::SeqCst);
        let read = reader.join().map_err(|_| anyhow!("the kernel reader panicked"))?;
        anyhow::Ok((consumed, read))
    })?;
    // Give the trace facility back before anything else can fail.
    drop(kd);

    let saved = src.finish();
    if !finish_output(consumed)? || !finish_output(printer.summary(&session.summary(), cli))? {
        return Ok(ExitCode::SUCCESS);
    }
    read?;
    if let Some(path) = &cli.record {
        saved.with_context(|| format!("the recording {} is incomplete", path.display()))?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Feeds reader input to the session until tracing stops or the reader goes away.
fn consume(
    rx: &Receiver<Input>,
    session: &mut Session,
    src: &mut LiveSource,
    sink: &mut dyn Sink,
    stop: &AtomicBool,
    deadline: Option<Instant>,
) -> io::Result<()> {
    let mut reported = false;
    loop {
        if deadline.is_some_and(|at| Instant::now() >= at) {
            stop.store(true, Ordering::SeqCst);
        }
        let input = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(input) => input,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };
        let last = matches!(input, Input::Stopped { .. });
        src.input(&input);
        session.handle(&input, src, sink)?;
        sink.flush()?;
        if !reported && let Some(err) = src.error() {
            let _ = writeln!(io::stderr(), "iotap: recording stopped: {err}; tracing continues");
            reported = true;
        }
        if last {
            return Ok(());
        }
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
    let mut printer = Printer::new(cli, session.info())?;
    let sink = printer.sink();
    let fed = replay.inputs.iter().try_for_each(|input| {
        session.handle(input, &mut answers, sink)?;
        sink.flush()
    });
    if finish_output(fed)? {
        finish_output(printer.summary(&session.summary(), cli))?;
    }
    Ok(ExitCode::SUCCESS)
}

/// False when stdout was closed by its reader, as with `| head`, which is not an error.
fn finish_output(result: io::Result<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err).context("cannot write output"),
    }
}

fn announce(tracked: &[Tracked], follow: &[String]) {
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
    let _ = writeln!(io::stderr(), "iotap: tracing {what}{also}; press Ctrl-C to stop");
}

/// The first signal asks for a clean stop; a second one releases the trace facility and exits
/// at once, in case output is blocked.
fn watch_signals(stop: &Arc<AtomicBool>) -> Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?;
    let stop = Arc::clone(stop);
    thread::Builder::new().name("signals".into()).spawn(move || {
        for (received, _) in signals.forever().enumerate() {
            if received == 0 {
                stop.store(true, Ordering::SeqCst);
            } else {
                kdebug::release();
                std::process::exit(130);
            }
        }
    })?;
    Ok(())
}

/// Releases the trace facility before the default panic output.
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
