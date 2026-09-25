//! The kernel reader: drains the trace buffer and watches the traced processes. It runs on its
//! own thread and does nothing slow, so the kernel buffer is emptied promptly.

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use crate::session::Input;
use crate::sys::proc::{self, ProcInfo};
use crate::sys::time;
use crate::target::Tracked;
use crate::trace::Records;

/// How often an idle reader still says how far the trace has been read, so that the consumer
/// can settle what it asked the system about.
const IDLE_WATERMARK: Duration = Duration::from_millis(100);

/// How many polls after its first check a process that matched no followed name is checked
/// again: a program may name itself through argv[0] a moment after it starts, as Node.js
/// programs do by setting `process.title`, and on Linux exec renames a process a moment before
/// the new program's arguments are in place. Two seconds at the interval iotap polls at.
const RECHECKS: u8 = 8;

/// What one read of the kernel buffer found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// The records taken, in order; `None` when there were none.
    pub records: Option<Records>,
    /// Every record stamped before this trace time has now been read; `None` when the read
    /// cannot vouch for that.
    pub complete_to: Option<u64>,
}

/// A kernel trace facility while iotap owns it: kdebug, or iotap's eBPF program.
pub trait Tracer {
    type Error: Error + Send + Sync + 'static;

    /// Blocks until records wait or `timeout` passes.
    fn wait(&mut self, timeout: Duration) -> Result<(), Self::Error>;

    /// Takes the records waiting now.
    fn read(&mut self) -> Result<Read, Self::Error>;

    /// Traces `pid` too. Harmless for a process already traced; a facility that stops tracing a
    /// process when it runs exec, as kdebug does, traces it again.
    fn add_pid(&mut self, pid: i32) -> Result<(), Self::Error>;

    /// Stops tracing `pid`, which is gone, so that a later process given the same pid is not
    /// traced by mistake. Harmless when the facility let the process go by itself, as kdebug
    /// does.
    fn remove_pid(&mut self, _pid: i32) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Takes what the facility still holds once tracing stops. Called once, after the last read.
    fn finish(&mut self) -> Result<Option<Records>, Self::Error> {
        Ok(None)
    }
}

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
pub fn run<T: Tracer>(
    tracer: &mut T,
    tracked: Vec<Tracked>,
    config: &ReaderConfig,
    tx: &Sender<Input>,
    stop: &AtomicBool,
) -> Result<(), T::Error> {
    let mut watch = Watch::new(tracked, config);
    let mut last_poll = Instant::now();
    let mut marks = Marks::new();
    loop {
        let stopping = stop.load(Ordering::SeqCst);
        if !stopping {
            tracer.wait(config.wait)?;
        }
        if !marks.forward(tracer.read()?, tx) {
            return Ok(());
        }
        if stopping {
            break;
        }
        if last_poll.elapsed() >= config.poll {
            last_poll = Instant::now();
            for input in watch.poll(tracer)? {
                if tx.send(input).is_err() {
                    return Ok(());
                }
            }
            if watch.is_empty() {
                // Records of the last moments may still be in per-CPU buffers.
                for _ in 0..2 {
                    thread::sleep(Duration::from_millis(20));
                    if !marks.forward(tracer.read()?, tx) {
                        return Ok(());
                    }
                }
                break;
            }
        }
    }
    if let Some(records) = tracer.finish()?
        && tx.send(Input::Records(records)).is_err()
    {
        return Ok(());
    }
    let _ = tx.send(Input::Stopped {
        ticks: time::now_ticks(),
    });
    Ok(())
}

/// Hands what reads find to the consumer and tells it how far the trace has been read: after
/// records went out, and now and then while idle.
struct Marks {
    /// Records went out after the last watermark.
    unmarked: bool,
    last: Instant,
}

impl Marks {
    fn new() -> Self {
        Self {
            unmarked: false,
            last: Instant::now(),
        }
    }

    /// Sends what `read` found. Returns false if the consumer is gone.
    fn forward(&mut self, read: Read, tx: &Sender<Input>) -> bool {
        if let Some(records) = read.records {
            if tx.send(Input::Records(records)).is_err() {
                return false;
            }
            self.unmarked = true;
        }
        if let Some(ticks) = read.complete_to
            && (self.unmarked || self.last.elapsed() >= IDLE_WATERMARK)
        {
            if tx.send(Input::Watermark { ticks }).is_err() {
                return false;
            }
            self.unmarked = false;
            self.last = Instant::now();
        }
        true
    }
}

/// Liveness, exec and name-follow bookkeeping for the traced processes.
struct Watch {
    tracked: Vec<Tracked>,
    follow: Vec<String>,
    own_pid: i32,
    /// Processes already checked against `follow`, by pid.
    seen: HashMap<i32, Seen>,
}

/// A process checked against the followed names. exec renames a process without starting it
/// anew, and the new name may be one to follow.
struct Seen {
    start: (u64, u64),
    name: String,
    /// Polls left in which it is checked again.
    rechecks: u8,
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
            for info in proc::list_pids().into_iter().filter_map(proc::info) {
                let seen = Seen {
                    start: info.start,
                    name: info.name,
                    rechecks: 0,
                };
                watch.seen.insert(info.pid, seen);
            }
        }
        watch
    }

    fn is_empty(&self) -> bool {
        self.tracked.is_empty()
    }

    fn poll<T: Tracer>(&mut self, tracer: &mut T) -> Result<Vec<Input>, T::Error> {
        let mut inputs = Vec::new();
        let mut gone = Vec::new();
        self.tracked.retain_mut(|process| {
            let alive = proc::info(process.pid).is_some_and(|info| info.start == process.start)
                // kdebug loses a process at exec, which gives it a new kernel proc without the
                // trace flag; tracing it again brings it back.
                && tracer.add_pid(process.pid).is_ok();
            if !alive {
                // Every record of the process was stamped before now.
                inputs.push(Input::Exited {
                    pid: process.pid,
                    ticks: time::now_ticks(),
                });
                gone.push(process.pid);
                return false;
            }
            let exe = proc::exe_path(process.pid);
            if exe.is_some() && exe != process.exe {
                process.exe.clone_from(&exe);
                inputs.push(Input::Exec {
                    pid: process.pid,
                    path: exe.unwrap_or_default(),
                });
            }
            true
        });
        for pid in gone {
            tracer.remove_pid(pid)?;
        }
        if !self.follow.is_empty() {
            self.follow_new(tracer, &mut inputs);
        }
        Ok(inputs)
    }

    fn follow_new<T: Tracer>(&mut self, tracer: &mut T, inputs: &mut Vec<Input>) {
        let pids = proc::list_pids();
        self.seen.retain(|pid, _| pids.contains(pid));
        for pid in pids {
            if pid == self.own_pid || self.tracked.iter().any(|t| t.pid == pid) {
                continue;
            }
            let Some(info) = proc::info(pid) else { continue };
            if !self.due(&info) {
                continue;
            }
            let process = Tracked {
                pid,
                name: info.name,
                start: info.start,
                exe: proc::exe_path(pid),
                arg0: proc::arg0(pid),
            };
            if !self.follow.iter().any(|name| process.is_named(name)) {
                continue;
            }
            if tracer.add_pid(pid).is_ok() {
                inputs.push(Input::Attached(process.process()));
                self.tracked.push(process);
            }
        }
    }

    /// Notes the process `info` describes. True when it is to be checked against `follow`: when
    /// it is new or exec has renamed it, and on the [`RECHECKS`] polls after.
    fn due(&mut self, info: &ProcInfo) -> bool {
        if let Some(seen) = self.seen.get_mut(&info.pid)
            && seen.start == info.start
            && seen.name == info.name
        {
            let due = seen.rechecks > 0;
            seen.rechecks = seen.rechecks.saturating_sub(1);
            return due;
        }
        let seen = Seen {
            start: info.start,
            name: info.name.clone(),
            rechecks: RECHECKS,
        };
        self.seen.insert(info.pid, seen);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::mpsc::{self, Receiver};

    use super::*;
    use crate::sys::proc::Sleeper;
    use crate::trace::kdebug::synth::Synth;

    /// Hands out scripted reads. Once they run out, reads find nothing and, when given `stop`,
    /// ask the reader to stop.
    struct Scripted<'a> {
        reads: VecDeque<Read>,
        stop: Option<&'a AtomicBool>,
        added: Vec<i32>,
        removed: Vec<i32>,
        /// What the facility still holds at the end.
        held: Option<Records>,
    }

    impl<'a> Scripted<'a> {
        fn new(reads: impl IntoIterator<Item = Read>, stop: Option<&'a AtomicBool>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                stop,
                added: Vec::new(),
                removed: Vec::new(),
                held: None,
            }
        }
    }

    impl Tracer for Scripted<'_> {
        type Error = io::Error;

        fn wait(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn read(&mut self) -> io::Result<Read> {
            if let Some(read) = self.reads.pop_front() {
                return Ok(read);
            }
            if let Some(stop) = self.stop {
                stop.store(true, Ordering::SeqCst);
            }
            Ok(Read {
                records: None,
                complete_to: Some(time::now_ticks()),
            })
        }

        fn add_pid(&mut self, pid: i32) -> io::Result<()> {
            self.added.push(pid);
            Ok(())
        }

        fn remove_pid(&mut self, pid: i32) -> io::Result<()> {
            self.removed.push(pid);
            Ok(())
        }

        fn finish(&mut self) -> io::Result<Option<Records>> {
            Ok(self.held.take())
        }
    }

    fn found(records: &Records) -> Read {
        Read {
            records: Some(records.clone()),
            complete_to: None,
        }
    }

    fn complete(ticks: u64) -> Read {
        Read {
            records: None,
            complete_to: Some(ticks),
        }
    }

    fn config(poll: Duration) -> ReaderConfig {
        ReaderConfig {
            follow: Vec::new(),
            wait: Duration::ZERO,
            poll,
            own_pid: 0,
        }
    }

    /// A process that is not running: no process has the largest pid.
    fn gone() -> Tracked {
        Tracked {
            pid: i32::MAX,
            name: "gone".into(),
            start: (1, 0),
            exe: None,
            arg0: None,
        }
    }

    fn sent(rx: &Receiver<Input>) -> Vec<Input> {
        rx.try_iter().collect()
    }

    #[test]
    fn forwards_records_and_marks_what_was_read_until_stopped() {
        let stop = AtomicBool::new(false);
        let records = Records::Kdebug(Synth::new(0, 1).io(1, 2, 3, 4, 5, 5));
        let mut tracer = Scripted::new([found(&records), complete(70)], Some(&stop));
        let (tx, rx) = mpsc::channel();
        // It never polls the processes, so only the stop flag ends it.
        run(&mut tracer, Vec::new(), &config(Duration::MAX), &tx, &stop).unwrap();
        let got = sent(&rx);
        // The read that finds nothing says the trace has been read up to its time.
        assert_eq!(
            got[..2],
            [Input::Records(records), Input::Watermark { ticks: 70 }]
        );
        assert!(matches!(got.last(), Some(Input::Stopped { .. })), "{got:?}");
    }

    #[test]
    fn a_read_that_reaches_the_end_marks_its_own_records() {
        let stop = AtomicBool::new(false);
        let records = Records::Kdebug(Synth::new(0, 1).io(1, 2, 3, 4, 5, 5));
        let read = Read {
            complete_to: Some(90),
            ..found(&records)
        };
        let mut tracer = Scripted::new([read], Some(&stop));
        let (tx, rx) = mpsc::channel();
        run(&mut tracer, Vec::new(), &config(Duration::MAX), &tx, &stop).unwrap();
        let got = sent(&rx);
        assert_eq!(
            got[..2],
            [Input::Records(records), Input::Watermark { ticks: 90 }]
        );
    }

    #[test]
    fn what_the_facility_holds_at_the_end_comes_before_the_stop() {
        let stop = AtomicBool::new(false);
        let records = Records::Kdebug(Synth::new(0, 1).io(1, 2, 3, 4, 5, 5));
        let mut tracer = Scripted::new([], Some(&stop));
        tracer.held = Some(records.clone());
        let (tx, rx) = mpsc::channel();
        run(&mut tracer, Vec::new(), &config(Duration::MAX), &tx, &stop).unwrap();
        let got = sent(&rx);
        let [.., last_records, stopped] = &got[..] else {
            panic!("{got:?}")
        };
        assert_eq!(*last_records, Input::Records(records));
        assert!(matches!(stopped, Input::Stopped { .. }), "{got:?}");
    }

    #[test]
    fn reports_exits_and_traces_running_processes_again() {
        let stop = AtomicBool::new(false);
        let me = Tracked::probe(i32::try_from(std::process::id()).unwrap()).unwrap();
        let mut tracer = Scripted::new([complete(1), complete(2)], Some(&stop));
        let before = time::now_ticks();
        let (tx, rx) = mpsc::channel();
        run(
            &mut tracer,
            vec![me.clone(), gone()],
            &config(Duration::ZERO),
            &tx,
            &stop,
        )
        .unwrap();
        let got = sent(&rx);
        // It was gone when the reader looked, which was after `before`.
        assert!(
            matches!(got.first(), Some(&Input::Exited { pid: i32::MAX, ticks }) if ticks >= before),
            "{got:?}"
        );
        assert!(matches!(got.last(), Some(Input::Stopped { .. })), "{got:?}");
        // Every poll traces the running process again, in case it ran exec.
        assert!(tracer.added.len() >= 2, "{:?}", tracer.added);
        assert!(
            tracer.added.iter().all(|&pid| pid == me.pid),
            "{:?}",
            tracer.added
        );
        assert_eq!(tracer.removed, [i32::MAX], "only the process that is gone");
    }

    #[test]
    fn a_process_is_checked_for_a_while_and_again_once_exec_renames_it() {
        let mut watch = Watch::new(Vec::new(), &config(Duration::ZERO));
        let process = |name: &str, start: u64| ProcInfo {
            pid: 70,
            name: name.into(),
            start: (start, 0),
        };
        let mut checks = |info: &ProcInfo| (0..20).filter(|_| watch.due(info)).count();
        // When first seen, and on the polls after, in which it may still name itself.
        assert_eq!(checks(&process("sh", 5)), 1 + usize::from(RECHECKS));
        // exec keeps the process and its start time, and names it after the new program.
        assert_eq!(checks(&process("python3", 5)), 1 + usize::from(RECHECKS));
        // A later process given the same pid.
        assert_eq!(checks(&process("python3", 6)), 1 + usize::from(RECHECKS));
    }

    #[test]
    fn follows_a_new_process_by_the_command_it_was_started_as() {
        let me = i32::try_from(std::process::id()).unwrap();
        let command = format!("iotap-follow-{me}");
        let config = ReaderConfig {
            follow: vec![command.clone()],
            own_pid: me,
            ..config(Duration::ZERO)
        };
        let mut watch = Watch::new(Vec::new(), &config);
        let sleeper = Sleeper::start(&command);
        let mut tracer = Scripted::new([], None);
        let inputs = watch.poll(&mut tracer).unwrap();
        assert!(
            matches!(&inputs[..], [Input::Attached(process)] if process.pid == sleeper.pid()),
            "{inputs:?}"
        );
        assert_eq!(tracer.added, [sleeper.pid()]);
    }

    #[test]
    fn stops_by_itself_once_every_process_is_gone() {
        let stop = AtomicBool::new(false);
        let mut tracer = Scripted::new([], None);
        let (tx, rx) = mpsc::channel();
        run(&mut tracer, vec![gone()], &config(Duration::ZERO), &tx, &stop).unwrap();
        let got = sent(&rx);
        assert!(
            matches!(
                &got[..],
                [Input::Exited { pid: i32::MAX, .. }, Input::Stopped { .. }]
            ),
            "{got:?}"
        );
        assert!(
            tracer.added.is_empty(),
            "a process that is gone is not traced again"
        );
        assert_eq!(tracer.removed, [i32::MAX]);
    }
}
