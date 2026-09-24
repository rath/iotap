//! The kernel reader: drains the trace buffer and watches the traced processes. It runs on its
//! own thread and does nothing slow, so the kernel buffer is emptied promptly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use crate::session::Input;
use crate::sys::kdebug::{Kdebug, KdebugError};
use crate::sys::proc as libproc;
use crate::sys::time;
use crate::target::{self, Tracked};

/// How often an idle reader still says how far the trace has been read, so that the consumer
/// can settle what it asked libproc about.
const IDLE_WATERMARK: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub struct ReaderConfig {
    /// Names whose newly started processes should be traced too.
    pub follow: Vec<String>,
    /// Longest wait for the kernel buffer to fill before reading anyway.
    pub wait: Duration,
    /// How often to check the traced processes.
    pub poll: Duration,
    /// iotap's own pid, never traced.
    pub own_pid: i32,
}

/// Reads until `stop` is set or every traced process is gone, then sends
/// [`Input::Stopped`]. Returns early if the consumer hangs up.
pub fn run(
    kd: &Kdebug,
    tracked: Vec<Tracked>,
    config: &ReaderConfig,
    tx: &Sender<Input>,
    stop: &AtomicBool,
) -> Result<(), KdebugError> {
    let mut watch = Watch::new(tracked, config);
    let mut buf = Vec::new();
    let mut last_poll = Instant::now();
    let mut last_watermark = Instant::now();
    // Records went out after the last watermark.
    let mut unmarked = false;
    loop {
        let stopping = stop.load(Ordering::SeqCst);
        if !stopping {
            kd.wait(config.wait)?;
        }
        let read_at = time::now_ticks();
        let Some(count) = drain(kd, &mut buf, tx)? else {
            return Ok(());
        };
        if count > 0 {
            unmarked = true;
        } else if unmarked || last_watermark.elapsed() >= IDLE_WATERMARK {
            // The read found nothing, so every record before it has been sent.
            if tx.send(Input::Watermark { ticks: read_at }).is_err() {
                return Ok(());
            }
            unmarked = false;
            last_watermark = Instant::now();
        }
        if stopping {
            break;
        }
        if last_poll.elapsed() >= config.poll {
            last_poll = Instant::now();
            for input in watch.poll(kd) {
                if tx.send(input).is_err() {
                    return Ok(());
                }
            }
            if watch.is_empty() {
                // Records of the last moments may still be in per-CPU buffers.
                for _ in 0..2 {
                    thread::sleep(Duration::from_millis(20));
                    if drain(kd, &mut buf, tx)?.is_none() {
                        return Ok(());
                    }
                }
                break;
            }
        }
    }
    let _ = tx.send(Input::Stopped {
        ticks: time::now_ticks(),
    });
    Ok(())
}

/// Moves buffered records to the consumer. Returns how many there were, or `None` if the
/// consumer is gone.
fn drain(
    kd: &Kdebug,
    buf: &mut Vec<crate::sys::kdebug::KdBuf>,
    tx: &Sender<Input>,
) -> Result<Option<usize>, KdebugError> {
    let count = kd.read(buf)?;
    if count > 0 && tx.send(Input::Records(buf[..count].to_vec())).is_err() {
        return Ok(None);
    }
    Ok(Some(count))
}

/// Liveness, exec and name-follow bookkeeping for the traced processes.
struct Watch {
    tracked: Vec<Tracked>,
    follow: Vec<String>,
    own_pid: i32,
    /// Start times of processes already checked against `follow`.
    seen: HashMap<i32, (u64, u64)>,
}

impl Watch {
    fn new(tracked: Vec<Tracked>, config: &ReaderConfig) -> Self {
        let mut watch = Self {
            tracked,
            follow: config.follow.clone(),
            own_pid: config.own_pid,
            seen: HashMap::new(),
        };
        if !watch.follow.is_empty() {
            // Processes running now were matched at startup; only later ones are new.
            for process in target::all_processes(watch.own_pid) {
                watch.seen.insert(process.pid, process.start);
            }
        }
        watch
    }

    fn is_empty(&self) -> bool {
        self.tracked.is_empty()
    }

    fn poll(&mut self, kd: &Kdebug) -> Vec<Input> {
        let mut inputs = Vec::new();
        self.tracked.retain_mut(|process| {
            let alive = libproc::info(process.pid).is_some_and(|info| info.start == process.start)
                // exec gives the process a new kernel proc without the trace flag; flag it again.
                && kd.add_pid(process.pid).is_ok();
            if !alive {
                inputs.push(Input::Exited { pid: process.pid });
                return false;
            }
            let exe = libproc::exe_path(process.pid);
            if exe.is_some() && exe != process.exe {
                process.exe.clone_from(&exe);
                inputs.push(Input::Exec {
                    pid: process.pid,
                    path: exe.unwrap_or_default(),
                });
            }
            true
        });
        if !self.follow.is_empty() {
            self.follow_new(kd, &mut inputs);
        }
        inputs
    }

    fn follow_new(&mut self, kd: &Kdebug, inputs: &mut Vec<Input>) {
        let pids = libproc::list_pids();
        self.seen.retain(|pid, _| pids.contains(pid));
        for pid in pids {
            if pid == self.own_pid || self.tracked.iter().any(|t| t.pid == pid) {
                continue;
            }
            let Some(info) = libproc::info(pid) else { continue };
            if self.seen.insert(pid, info.start) == Some(info.start) {
                continue;
            }
            let exe = libproc::exe_path(pid);
            if !self
                .follow
                .iter()
                .any(|name| target::name_matches(name, &info.name, exe.as_deref()))
            {
                continue;
            }
            if kd.add_pid(pid).is_ok() {
                let process = Tracked {
                    pid,
                    name: info.name,
                    start: info.start,
                    exe,
                };
                inputs.push(Input::Attached(process.process()));
                self.tracked.push(process);
            }
        }
    }
}
