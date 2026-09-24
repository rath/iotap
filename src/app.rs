//! Wires the command line to the kernel reader, the session and the chosen output.

use std::io::{self, BufWriter, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::cli::Cli;
use crate::output::text::{self, TextSink};
use crate::reader::{self, ReaderConfig};
use crate::session::{Filter, Input, Session, SessionInfo, Sink};
use crate::sys;
use crate::sys::kdebug::{self, Kdebug, KdebugConfig, KdebugError, TypeFilter};
use crate::sys::time::{ClockAnchor, Timebase};
use crate::target::{self, Spec, Tracked};
use crate::trace::codes;
use crate::trace::procs::{Live, ProcSource};

/// Runs iotap as the command line asks.
pub fn run(cli: &Cli) -> Result<ExitCode> {
    install_panic_hook();
    if let Some(pid) = cli.dump_fds {
        return dump_fds(pid);
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
    let mut src = Live;
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
    let mut sink = TextSink::new(BufWriter::with_capacity(1 << 16, io::stdout().lock()), cli.quiet);

    let (tx, rx) = mpsc::channel();
    let (kd_ref, stop_ref, config_ref) = (&kd, &*stop, &config);
    let (consumed, read) = thread::scope(|scope| {
        let reader = thread::Builder::new()
            .name("kdebug-reader".into())
            .spawn_scoped(scope, move || {
                reader::run(kd_ref, tracked, config_ref, &tx, stop_ref)
            });
        let consumed = consume(&rx, &mut session, &mut src, &mut sink, stop_ref, deadline);
        stop_ref.store(true, Ordering::SeqCst);
        let read = match reader {
            Ok(handle) => handle
                .join()
                .map_err(|_| anyhow::anyhow!("the kernel reader panicked"))?
                .map_err(anyhow::Error::from),
            Err(err) => Err(anyhow::Error::from(err).context("cannot start the kernel reader")),
        };
        anyhow::Ok((consumed, read))
    })?;
    // Give the trace facility back before anything else can fail.
    drop(kd);

    match consumed {
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => return Ok(ExitCode::SUCCESS),
        Err(err) => return Err(err).context("cannot write output"),
        Ok(()) => {}
    }
    let mut out = sink.into_inner();
    text::write_summary(&mut out, &session.summary(), cli.top, filter(cli))?;
    out.flush()?;
    read?;
    Ok(ExitCode::SUCCESS)
}

/// Feeds reader input to the session until tracing stops or the reader goes away.
fn consume(
    rx: &Receiver<Input>,
    session: &mut Session,
    src: &mut dyn ProcSource,
    sink: &mut dyn Sink,
    stop: &AtomicBool,
    deadline: Option<Instant>,
) -> io::Result<()> {
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
        session.handle(&input, src, sink)?;
        sink.flush()?;
        if last {
            return Ok(());
        }
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
