//! The kernel reader: drains the trace buffer and watches the traced processes. It runs on its
//! own thread and does nothing slow, so the kernel buffer is emptied promptly.

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use crate::session::{Input, UntracedReason};
use crate::sys::proc::{self, ProcInfo};
use crate::sys::time;
use crate::target::{self, Tracked};
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
    /// Processes that traced ones started, as the records show them, when iotap follows child
    /// processes.
    pub spawned: Vec<Spawn>,
}

/// A process that a traced one started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spawn {
    /// The traced process that started it, when the facility knows.
    pub parent: Option<i32>,
    pub child: i32,
    /// The facility traces it now; when not, it could not.
    pub traced: bool,
    /// The records tell the session of it, as they do on Linux. Otherwise the reader does.
    pub in_trace: bool,
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
    /// Trace the processes that traced ones start, and their running descendants.
    pub children: bool,
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
        if !read_once(tracer, &mut watch, &mut marks, tx)? {
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
                // Records of the last moments may still be in per-CPU buffers, among them those
                // of a child that the last traced process started as it ended.
                for _ in 0..2 {
                    thread::sleep(Duration::from_millis(20));
                    if !read_once(tracer, &mut watch, &mut marks, tx)? {
                        return Ok(());
                    }
                }
                if watch.is_empty() {
                    break;
                }
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

/// Reads once, passes the records on, and takes up the processes they show traced ones started.
/// Returns false if the consumer is gone.
fn read_once<T: Tracer>(
    tracer: &mut T,
    watch: &mut Watch,
    marks: &mut Marks,
    tx: &Sender<Input>,
) -> Result<bool, T::Error> {
    let mut read = tracer.read()?;
    let spawned = std::mem::take(&mut read.spawned);
    if !marks.forward(read, tx) {
        return Ok(false);
    }
    let inputs = watch.spawned(tracer, spawned)?;
    Ok(inputs.into_iter().all(|input| tx.send(input).is_ok()))
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

/// Liveness, exec, name-follow and child bookkeeping for the traced processes.
struct Watch {
    tracked: Vec<Tracked>,
    follow: Vec<String>,
    children: bool,
    /// The descendants that traced processes had when tracing began have been looked for.
    swept: bool,
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
            children: config.children,
            swept: false,
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
        if self.children && !self.swept {
            // Processes started after the traced ones were listed but before the facility
            // followed children.
            self.swept = true;
            let roots: Vec<i32> = self.tracked.iter().map(|t| t.pid).collect();
            self.adopt(tracer, &roots, &mut inputs);
        }
        if !self.follow.is_empty() {
            self.follow_new(tracer, &mut inputs);
        }
        Ok(inputs)
    }

    /// Takes up the processes that traced ones started, as a read found them, and says what the
    /// session must learn of them besides what the records tell it.
    fn spawned<T: Tracer>(&mut self, tracer: &mut T, spawns: Vec<Spawn>) -> Result<Vec<Input>, T::Error> {
        let mut inputs = Vec::new();
        for spawn in spawns {
            let untraced = Input::Untraced {
                pid: spawn.child,
                parent: spawn.parent,
                reason: UntracedReason::Ended,
            };
            if !spawn.traced {
                // The facility gave up on it; the records tell why, if they tell of it at all.
                if !spawn.in_trace {
                    inputs.push(untraced);
                }
                continue;
            }
            // It takes the place of any earlier process given its pid, which is gone.
            self.tracked.retain(|t| t.pid != spawn.child);
            let Some(mut child) = Tracked::probe(spawn.child) else {
                // The records that tell of a child may not tell of its end.
                inputs.push(if spawn.in_trace {
                    Input::Exited {
                        pid: spawn.child,
                        ticks: time::now_ticks(),
                    }
                } else {
                    untraced
                });
                // The facility traces it, and must let its pid go.
                tracer.remove_pid(spawn.child)?;
                continue;
            };
            if spawn.in_trace {
                // To the session the child runs its parent's program until it calls exec, so
                // the next poll reports an exec it has made already.
                child.exe = spawn
                    .parent
                    .and_then(|pid| self.tracked.iter().find(|t| t.pid == pid))
                    .and_then(|parent| parent.exe.clone());
            } else {
                // A parent that the facility did not name is the child's, unless the child was
                // handed to another process when its parent ended.
                let parent = spawn.parent.or_else(|| {
                    let known = self.tracked.iter().any(|t| t.pid == child.parent);
                    known.then_some(child.parent)
                });
                inputs.push(Input::Attached {
                    process: child.process(),
                    parent,
                });
            }
            self.tracked.push(child);
        }
        Ok(inputs)
    }

    /// Traces the running descendants of `roots` that are not traced yet.
    fn adopt<T: Tracer>(&mut self, tracer: &mut T, roots: &[i32], inputs: &mut Vec<Input>) {
        for child in target::descendants(roots, self.own_pid) {
            if self.tracked.iter().any(|t| t.pid == child.pid) || tracer.add_pid(child.pid).is_err() {
                continue;
            }
            inputs.push(Input::Attached {
                process: child.process(),
                parent: Some(child.parent),
            });
            self.tracked.push(child);
        }
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
            let process = Tracked::with(info);
            if !self.follow.iter().any(|name| process.is_named(name)) {
                continue;
            }
            if tracer.add_pid(pid).is_ok() {
                inputs.push(Input::Attached {
                    process: process.process(),
                    parent: None,
                });
                self.tracked.push(process);
                if self.children {
                    self.adopt(tracer, &[pid], inputs);
                }
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
            Ok(complete(time::now_ticks()))
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
            ..Read::default()
        }
    }

    fn complete(ticks: u64) -> Read {
        Read {
            complete_to: Some(ticks),
            ..Read::default()
        }
    }

    /// A read that shows the processes of `spawned` started.
    fn spawning(spawned: impl IntoIterator<Item = Spawn>) -> Read {
        Read {
            spawned: spawned.into_iter().collect(),
            ..Read::default()
        }
    }

    fn config(poll: Duration) -> ReaderConfig {
        ReaderConfig {
            follow: Vec::new(),
            children: false,
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
            parent: 1,
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
            parent: 1,
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
            matches!(
                &inputs[..],
                [Input::Attached { process, parent: None }] if process.pid == sleeper.pid()
            ),
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

    /// The test process, and a watch over it that follows children but has looked for its
    /// descendants already, which in a test include those of other tests.
    fn watching_me() -> (Tracked, Watch) {
        let me = Tracked::probe(i32::try_from(std::process::id()).unwrap()).unwrap();
        let config = ReaderConfig {
            children: true,
            ..config(Duration::ZERO)
        };
        let mut watch = Watch::new(vec![me.clone()], &config);
        watch.swept = true;
        (me, watch)
    }

    #[test]
    fn takes_up_children_the_records_tell_the_session_of() {
        let (me, mut watch) = watching_me();
        let sleeper = Sleeper::start(&format!("iotap-spawned-{}", me.pid));
        let mut tracer = Scripted::new([], None);
        let spawn = Spawn {
            parent: Some(me.pid),
            child: sleeper.pid(),
            traced: true,
            in_trace: true,
        };
        let inputs = watch.spawned(&mut tracer, vec![spawn]).unwrap();
        assert!(inputs.is_empty(), "{inputs:?}");
        // To the session the child runs its parent's program, so the exec it made is reported.
        let inputs = watch.poll(&mut tracer).unwrap();
        assert!(
            matches!(
                &inputs[..],
                [Input::Exec { pid, path }] if *pid == sleeper.pid() && path.ends_with("/sleep")
            ),
            "{inputs:?}"
        );
    }

    #[test]
    fn tells_of_children_the_records_do_not() {
        let (me, mut watch) = watching_me();
        let sleeper = Sleeper::start(&format!("iotap-spawned-{}", me.pid));
        let mut tracer = Scripted::new([], None);
        // A parent the facility does not name is the child's own.
        let spawn = Spawn {
            parent: None,
            child: sleeper.pid(),
            traced: true,
            in_trace: false,
        };
        let inputs = watch.spawned(&mut tracer, vec![spawn]).unwrap();
        assert!(
            matches!(
                &inputs[..],
                [Input::Attached { process, parent: Some(parent) }]
                    if process.pid == sleeper.pid() && *parent == me.pid
            ),
            "{inputs:?}"
        );
        assert!(watch.poll(&mut tracer).unwrap().is_empty());
    }

    #[test]
    fn children_gone_or_refused_are_not_watched() {
        let (_, mut watch) = watching_me();
        let mut tracer = Scripted::new([], None);
        let gone = |in_trace| Spawn {
            parent: Some(7),
            child: i32::MAX,
            traced: true,
            in_trace,
        };
        let untraced = Input::Untraced {
            pid: i32::MAX,
            parent: Some(7),
            reason: UntracedReason::Ended,
        };
        // Where the records tell of a child, they may not tell of its end. Either way the
        // facility lets its pid go.
        let inputs = watch.spawned(&mut tracer, vec![gone(true)]).unwrap();
        assert!(
            matches!(&inputs[..], [Input::Exited { pid: i32::MAX, .. }]),
            "{inputs:?}"
        );
        assert_eq!(tracer.removed, [i32::MAX]);
        assert_eq!(
            watch.spawned(&mut tracer, vec![gone(false)]).unwrap(),
            std::slice::from_ref(&untraced)
        );
        assert_eq!(tracer.removed, [i32::MAX; 2]);
        // One the facility could not trace: the records say so where they tell of children.
        let refused = |in_trace| Spawn {
            traced: false,
            ..gone(in_trace)
        };
        assert!(
            watch
                .spawned(&mut tracer, vec![refused(true)])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            watch.spawned(&mut tracer, vec![refused(false)]).unwrap(),
            [untraced]
        );
        assert_eq!(watch.tracked.len(), 1, "only the test process");
    }

    #[test]
    fn looks_for_running_descendants_once() {
        let (me, mut watch) = watching_me();
        watch.swept = false;
        let sleeper = Sleeper::start(&format!("iotap-swept-{}", me.pid));
        let mut tracer = Scripted::new([], None);
        let inputs = watch.poll(&mut tracer).unwrap();
        assert!(
            inputs.iter().any(|input| matches!(
                input,
                Input::Attached { process, parent: Some(parent) }
                    if process.pid == sleeper.pid() && *parent == me.pid
            )),
            "{inputs:?}"
        );
        assert!(tracer.added.contains(&sleeper.pid()));
        // Later children are for the facility to find.
        let later = Sleeper::start(&format!("iotap-swept-{}", me.pid));
        let inputs = watch.poll(&mut tracer).unwrap();
        assert!(
            !inputs.iter().any(|input| matches!(
                input,
                Input::Attached { process, .. } if process.pid == later.pid()
            )),
            "{inputs:?}"
        );
    }

    #[test]
    fn keeps_reading_for_a_child_started_as_the_last_process_ended() {
        let stop = AtomicBool::new(false);
        let sleeper = Sleeper::start(&format!("iotap-orphan-{}", std::process::id()));
        let spawn = Spawn {
            parent: Some(i32::MAX),
            child: sleeper.pid(),
            traced: true,
            in_trace: false,
        };
        // By the first poll the only traced process is gone; its child shows up a read later.
        let mut tracer = Scripted::new([complete(1), spawning([spawn])], Some(&stop));
        let config = ReaderConfig {
            children: true,
            ..config(Duration::ZERO)
        };
        let (tx, rx) = mpsc::channel();
        run(&mut tracer, vec![gone()], &config, &tx, &stop).unwrap();
        let got = sent(&rx);
        assert!(
            got.iter().any(|input| matches!(
                input,
                Input::Attached { process, parent: Some(i32::MAX) } if process.pid == sleeper.pid()
            )),
            "{got:?}"
        );
        assert!(matches!(got.last(), Some(Input::Stopped { .. })), "{got:?}");
    }
}
