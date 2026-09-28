//! The deterministic core: turns reader input into I/O events, notices and statistics.
//!
//! A session depends only on its input and on the answers of its [`ProcSource`], never on
//! wall-clock time, so a recording replays to the same output.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::interfaces::Table;
use crate::model::{Category, Endpoint, IoEvent, Op, Proto, Provenance, ResultUnit, Target, Via};
use crate::stats::{InterfaceTotals, Stats, SummaryRow, Totals};
use crate::sys::time::{ClockAnchor, Timebase};
use crate::trace::call::{Completed, Role};
use crate::trace::fdtable::{FdTable, Found, Verdict};
use crate::trace::kdebug::{self, pairing::PathRecords};
use crate::trace::linux;
use crate::trace::procs::ProcSource;
use crate::trace::{Decode, Records, Step, System, Traced};

/// A traced process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: i32,
    pub name: String,
}

/// A traced process and whether it is still running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStatus {
    pub pid: i32,
    pub name: String,
    pub alive: bool,
}

/// Facts fixed when tracing starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub timebase: Timebase,
    /// Read before tracing was enabled.
    pub anchor: ClockAnchor,
    pub processes: Vec<Process>,
    /// How the kernel that made the records lays out lookup paths.
    #[serde(default)]
    pub path_records: PathRecords,
    /// The system the records come from.
    #[serde(default)]
    pub system: System,
}

/// Why a process that a traced one started is not traced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntracedReason {
    /// It ended before iotap could begin to trace it, as a child can on macOS.
    Ended,
    /// iotap was tracing as many processes as it can.
    Full,
}

/// Processes that traced ones started and that were not traced, by why.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UntracedChildren {
    /// Ended before iotap could begin to trace them.
    pub ended: u64,
    /// Started while iotap was tracing as many processes as it can.
    pub full: u64,
}

/// What the kernel reader delivers, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Records(Records),
    /// A process is now traced too: a newly started one matching a traced name, or one that
    /// `parent`, a traced process, started. What it did before is not in the trace.
    Attached {
        process: Process,
        parent: Option<i32>,
    },
    /// A process that `parent`, a traced process, started is not traced.
    Untraced {
        pid: i32,
        parent: Option<i32>,
        reason: UntracedReason,
    },
    /// A traced process replaced its program image.
    Exec {
        pid: i32,
        path: String,
    },
    /// The reader found a traced process gone at trace time `ticks`. Records it made before
    /// exiting may still be on their way, so the exit counts once the trace reaches `ticks`.
    Exited {
        pid: i32,
        ticks: u64,
    },
    /// Tracing stopped at this trace time.
    Stopped {
        ticks: u64,
    },
    /// Every record up to this trace time has been delivered.
    Watermark {
        ticks: u64,
    },
}

/// Something to tell the user besides I/O events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The kernel dropped records because its buffer overflowed; totals undercount.
    LostEvents {
        time_ns: u64,
    },
    /// A process is now traced too; `parent` is set for one that a traced process started.
    Attached {
        process: Process,
        parent: Option<i32>,
    },
    /// A process that a traced one started is not traced.
    Untraced {
        pid: i32,
        parent: Option<i32>,
        reason: UntracedReason,
    },
    Exec {
        pid: i32,
        path: String,
    },
    Exited(Process),
}

/// Receives what a session produces.
pub trait Sink {
    fn event(&mut self, event: &IoEvent) -> io::Result<()>;
    fn notice(&mut self, notice: &Notice) -> io::Result<()>;
    /// Called after each input has been handled.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Which kinds of targets to report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub files: bool,
    pub network: bool,
    pub other: bool,
    /// The network interfaces whose I/O to report, by name; empty for I/O over any interface or
    /// none.
    pub interfaces: Vec<String>,
}

impl Filter {
    pub const ALL: Self = Self {
        files: true,
        network: true,
        other: true,
        interfaces: Vec::new(),
    };

    pub fn accepts(&self, category: Category) -> bool {
        match category {
            Category::File => self.files,
            Category::Network => self.network,
            Category::Other => self.other,
        }
    }

    /// True when I/O over `via` is reported.
    pub fn accepts_interface(&self, via: &Via) -> bool {
        self.interfaces.is_empty()
            || via
                .name()
                .is_some_and(|name| self.interfaces.iter().any(|wanted| wanted == name))
    }
}

/// End-of-session report.
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub duration_ns: u64,
    pub processes: Vec<Process>,
    pub totals: Totals,
    /// Network I/O by the interface it went over.
    pub interfaces: Vec<InterfaceTotals>,
    /// Times the kernel reported dropped records.
    pub lost_events: u64,
    /// Calls whose END was not seen.
    pub unfinished_calls: u64,
    /// Calls whose START was not seen, mostly calls already blocked when tracing began.
    pub calls_started_before_trace: u64,
    pub untraced_children: UntracedChildren,
    /// Calls left out for going over an interface that iotap cannot tell, while only some
    /// interfaces are reported.
    pub unknown_interface_calls: u64,
    pub files: Vec<SummaryRow>,
    pub network: Vec<SummaryRow>,
    pub other: Vec<SummaryRow>,
}

#[derive(Debug)]
struct ProcessState {
    name: String,
    alive: bool,
}

/// Output held back until the answers its event's target rests on are settled.
#[derive(Debug)]
enum Held {
    Event {
        event: IoEvent,
        /// The unconfirmed answer of the system the target came from.
        answer: Option<u64>,
    },
    Notice(Notice),
}

impl Held {
    fn is_ready(&self) -> bool {
        !matches!(self, Self::Event { answer: Some(_), .. })
    }
}

/// Puts the records of the session's system together.
#[derive(Debug)]
enum Decoder {
    Kdebug(kdebug::Decoder),
    Linux(linux::Decoder),
}

impl Decoder {
    fn new(info: &SessionInfo) -> Self {
        match info.system {
            System::Macos => Self::Kdebug(kdebug::Decoder::new(info.path_records)),
            System::LinuxAarch64 | System::LinuxX86_64 => Self::Linux(linux::Decoder::new(info.system)),
        }
    }

    fn unfinished_calls(&self) -> u64 {
        match self {
            Self::Kdebug(decoder) => decoder.unfinished_calls(),
            Self::Linux(decoder) => decoder.unfinished_calls(),
        }
    }

    fn calls_started_before_trace(&self) -> u64 {
        match self {
            Self::Kdebug(decoder) => decoder.calls_started_before_trace(),
            Self::Linux(decoder) => decoder.calls_started_before_trace(),
        }
    }
}

#[derive(Debug)]
pub struct Session {
    info: SessionInfo,
    filter: Filter,
    decoder: Decoder,
    fds: FdTable,
    interfaces: Table,
    stats: Stats,
    processes: BTreeMap<i32, ProcessState>,
    lost_events: u64,
    untraced: UntracedChildren,
    unknown_interface_calls: u64,
    last_ticks: u64,
    stopped_ticks: Option<u64>,
    unknown: Arc<Target>,
    /// Stands in for an unidentified descriptor that a socket-only call used.
    some_socket: Arc<Target>,
    /// Events and notices waiting, in order, for the first of them to be settled.
    held: VecDeque<Held>,
    /// Processes the reader found gone, by the trace time it looked, waiting for the trace to
    /// get there.
    exits: VecDeque<(u64, i32)>,
}

impl Session {
    /// Starts a session, lists the host's interfaces and loads the descriptor tables of the
    /// initial processes.
    pub fn new(info: SessionInfo, filter: Filter, src: &mut dyn ProcSource) -> Self {
        let retry_ticks = info.timebase.nanos_to_ticks(1_000_000_000);
        let mut session = Self {
            filter,
            decoder: Decoder::new(&info),
            fds: FdTable::new(retry_ticks),
            interfaces: Table::new(src.interfaces(), info.anchor.ticks, retry_ticks),
            stats: Stats::default(),
            processes: BTreeMap::new(),
            lost_events: 0,
            untraced: UntracedChildren::default(),
            unknown_interface_calls: 0,
            last_ticks: info.anchor.ticks,
            stopped_ticks: None,
            unknown: Arc::new(Target::Unknown),
            some_socket: Arc::new(Target::Socket(Endpoint::unresolved(Proto::Other))),
            held: VecDeque::new(),
            exits: VecDeque::new(),
            info,
        };
        for process in session.info.processes.clone() {
            let alive = session.fds.attach(process.pid, src);
            session.processes.insert(
                process.pid,
                ProcessState {
                    name: process.name,
                    alive,
                },
            );
        }
        session
    }

    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Which kinds of targets the session reports.
    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    /// The host's network interfaces as last listed.
    pub fn interfaces(&self) -> &Table {
        &self.interfaces
    }

    /// Name of a traced process.
    pub fn process_name(&self, pid: i32) -> Option<&str> {
        self.processes.get(&pid).map(|p| p.name.as_str())
    }

    /// Every process traced so far, in pid order.
    pub fn processes(&self) -> Vec<ProcessStatus> {
        self.processes
            .iter()
            .map(|(&pid, state)| ProcessStatus {
                pid,
                name: state.name.clone(),
                alive: state.alive,
            })
            .collect()
    }

    /// Times the kernel reported dropped records.
    pub fn lost_events(&self) -> u64 {
        self.lost_events
    }

    /// True once every traced process has exited.
    pub fn all_exited(&self) -> bool {
        self.processes.values().all(|p| !p.alive)
    }

    /// Wall-clock time of the latest input, in Unix nanoseconds.
    pub fn now_ns(&self) -> u64 {
        self.unix_ns(self.stopped_ticks.unwrap_or(self.last_ticks))
    }

    pub fn handle(&mut self, input: &Input, src: &mut dyn ProcSource, sink: &mut dyn Sink) -> io::Result<()> {
        // Records only ever come in the format of the session's system.
        match input {
            Input::Records(Records::Kdebug(records)) => {
                for record in records {
                    let step = match &mut self.decoder {
                        Decoder::Kdebug(decoder) => decoder.decode(record),
                        Decoder::Linux(_) => None,
                    };
                    if let Some(step) = step {
                        self.step(step, src, sink)?;
                    }
                }
            }
            Input::Records(Records::Linux(records)) => {
                for record in records {
                    let step = match &mut self.decoder {
                        Decoder::Linux(decoder) => decoder.decode(record),
                        Decoder::Kdebug(_) => None,
                    };
                    if let Some(step) = step {
                        self.step(step, src, sink)?;
                    }
                }
            }
            Input::Attached { process, parent } => {
                let alive = self.fds.attach(process.pid, src);
                self.processes.insert(
                    process.pid,
                    ProcessState {
                        name: process.name.clone(),
                        alive,
                    },
                );
                let attached = Notice::Attached {
                    process: process.clone(),
                    parent: *parent,
                };
                self.hold(Held::Notice(attached), sink)?;
            }
            Input::Untraced { pid, parent, reason } => self.untraced(*pid, *parent, *reason, sink)?,
            Input::Exec { pid, path } => {
                if let Some(name) = path.rsplit('/').next().filter(|n| !n.is_empty())
                    && let Some(state) = self.processes.get_mut(pid)
                {
                    name.clone_into(&mut state.name);
                }
                self.fds.attach(*pid, src);
                let exec = Notice::Exec {
                    pid: *pid,
                    path: path.clone(),
                };
                self.hold(Held::Notice(exec), sink)?;
            }
            Input::Exited { pid, ticks } => {
                self.exits.push_back((*ticks, *pid));
                self.reach(self.last_ticks, sink)?;
            }
            Input::Stopped { ticks } => {
                self.stopped_ticks = Some((*ticks).max(self.last_ticks));
                self.finish(sink)?;
            }
            Input::Watermark { ticks } => {
                self.last_ticks = self.last_ticks.max(*ticks);
                self.reach(*ticks, sink)?;
                self.fds.advance(*ticks);
                self.settle(sink)?;
            }
        }
        Ok(())
    }

    /// Settles every answer still unconfirmed and emits what waited for it, exits included.
    /// Call it when no more input will come; a `Stopped` input does it too.
    pub fn finish(&mut self, sink: &mut dyn Sink) -> io::Result<()> {
        self.reach(u64::MAX, sink)?;
        self.fds.finish();
        self.settle(sink)
    }

    pub fn summary(&self) -> Summary {
        let end = self.stopped_ticks.unwrap_or(self.last_ticks);
        let duration_ns = self
            .info
            .timebase
            .ticks_to_nanos(end.saturating_sub(self.info.anchor.ticks));
        let processes = self
            .processes
            .iter()
            .map(|(&pid, state)| Process {
                pid,
                name: state.name.clone(),
            })
            .collect();
        Summary {
            duration_ns,
            processes,
            totals: *self.stats.totals(),
            interfaces: self.stats.interface_totals(),
            lost_events: self.lost_events,
            unfinished_calls: self.decoder.unfinished_calls(),
            calls_started_before_trace: self.decoder.calls_started_before_trace(),
            untraced_children: self.untraced,
            unknown_interface_calls: self.unknown_interface_calls,
            files: self.stats.summary_rows(Category::File),
            network: self.stats.summary_rows(Category::Network),
            other: self.stats.summary_rows(Category::Other),
        }
    }

    /// Applies what one record tells.
    fn step(&mut self, step: Step, src: &mut dyn ProcSource, sink: &mut dyn Sink) -> io::Result<()> {
        // A process found gone before this record made no more calls after it.
        self.reach(step.ts, sink)?;
        self.last_ticks = self.last_ticks.max(step.ts);
        match step.traced {
            Some(Traced::Call(done)) => self.completed(&done, src, sink)?,
            Some(Traced::ProcExit { pid }) => self.exited(pid, sink)?,
            Some(Traced::Fork {
                parent,
                child,
                traced: true,
            }) => self.forked(parent, child, sink)?,
            Some(Traced::Fork {
                parent,
                child,
                traced: false,
            }) => self.untraced(child, Some(parent), UntracedReason::Full, sink)?,
            Some(Traced::LostEvents) => self.lost(step.ts, src, sink)?,
            None => {}
        }
        // Every record up to this one has been seen now.
        self.fds.advance(step.ts);
        self.settle(sink)
    }

    /// Traces `child`, which `parent` has just started. Until it calls exec, the child runs its
    /// parent's program, with a copy of its parent's descriptors.
    fn forked(&mut self, parent: i32, child: i32, sink: &mut dyn Sink) -> io::Result<()> {
        let name = self
            .processes
            .get(&parent)
            .map_or_else(|| "?".to_owned(), |state| state.name.clone());
        self.fds.fork(parent, child);
        self.processes.insert(
            child,
            ProcessState {
                name: name.clone(),
                alive: true,
            },
        );
        let attached = Notice::Attached {
            process: Process { pid: child, name },
            parent: Some(parent),
        };
        self.hold(Held::Notice(attached), sink)
    }

    /// Counts a process that a traced one started and that is not traced, and says so.
    fn untraced(
        &mut self,
        pid: i32,
        parent: Option<i32>,
        reason: UntracedReason,
        sink: &mut dyn Sink,
    ) -> io::Result<()> {
        match reason {
            UntracedReason::Ended => self.untraced.ended += 1,
            UntracedReason::Full => self.untraced.full += 1,
        }
        self.hold(Held::Notice(Notice::Untraced { pid, parent, reason }), sink)
    }

    /// Reloads the descriptor tables after the kernel dropped records before trace time `ts`,
    /// and says so.
    fn lost(&mut self, ts: u64, src: &mut dyn ProcSource, sink: &mut dyn Sink) -> io::Result<()> {
        self.lost_events += 1;
        let alive: Vec<i32> = self
            .processes
            .iter()
            .filter(|(_, p)| p.alive)
            .map(|(&pid, _)| pid)
            .collect();
        for pid in alive {
            self.fds.attach(pid, src);
        }
        let lost = Notice::LostEvents {
            time_ns: self.unix_ns(ts),
        };
        self.hold(Held::Notice(lost), sink)
    }

    /// Emits `item` now, or queues it behind what is already waiting.
    fn hold(&mut self, item: Held, sink: &mut dyn Sink) -> io::Result<()> {
        if self.held.is_empty() && item.is_ready() {
            return self.emit(item, sink);
        }
        self.held.push_back(item);
        Ok(())
    }

    /// Applies the descriptor table's verdicts to waiting events and emits the ones at the
    /// front that no longer wait.
    fn settle(&mut self, sink: &mut dyn Sink) -> io::Result<()> {
        let verdicts = self.fds.take_verdicts();
        if !verdicts.is_empty() {
            let outcome: HashMap<u64, Option<(Arc<Target>, Provenance)>> = verdicts
                .into_iter()
                .map(|verdict| match verdict {
                    Verdict::Confirmed(answer) => (answer, None),
                    Verdict::Stale {
                        answer,
                        target,
                        provenance,
                    } => (answer, Some((target, provenance))),
                })
                .collect();
            for held in &mut self.held {
                if let Held::Event { event, answer } = held
                    && let Some(settled) = answer.and_then(|id| outcome.get(&id))
                {
                    if let Some((target, provenance)) = settled {
                        event.target = target.clone();
                        event.provenance = *provenance;
                    }
                    *answer = None;
                }
            }
        }
        while self.held.front().is_some_and(Held::is_ready) {
            if let Some(item) = self.held.pop_front() {
                self.emit(item, sink)?;
            }
        }
        Ok(())
    }

    fn emit(&mut self, item: Held, sink: &mut dyn Sink) -> io::Result<()> {
        let mut event = match item {
            Held::Notice(notice) => return sink.notice(&notice),
            Held::Event { event, .. } => event,
        };
        // Only sockets take these calls, so an unidentified descriptor is at least a socket.
        if *event.target == Target::Unknown
            && event.op.needs_socket()
            && !matches!(event.errno, libc::EBADF | libc::ENOTSOCK)
        {
            event.target = self.some_socket.clone();
        }
        if !self.filter.accepts(event.target.category()) {
            return Ok(());
        }
        event.interface = self.interfaces.via(&event.target, self.fds.netns(event.pid));
        if !self.filter.accepts_interface(&event.interface) {
            if event.interface == Via::Unknown {
                self.unknown_interface_calls += 1;
            }
            return Ok(());
        }
        self.stats.record(&event);
        sink.event(&event)
    }

    fn completed(
        &mut self,
        done: &Completed,
        src: &mut dyn ProcSource,
        sink: &mut dyn Sink,
    ) -> io::Result<()> {
        let Role::Io { op, fd_arg, len_arg } = done.call.role else {
            self.fds.apply(done, src);
            return Ok(());
        };
        let (event, answer) = self.io_event(done, op, fd_arg, len_arg, src);
        self.hold(Held::Event { event, answer }, sink)
    }

    fn io_event(
        &mut self,
        done: &Completed,
        op: Op,
        fd_arg: usize,
        len_arg: Option<usize>,
        src: &mut dyn ProcSource,
    ) -> (IoEvent, Option<u64>) {
        let fd = done.arg_i32(fd_arg);
        let Found {
            target,
            provenance,
            answer,
        } = match fd {
            Some(fd) => self.fds.target(done.pid, fd, done.end_ts, src),
            None => Found {
                target: self.unknown.clone(),
                provenance: Provenance::None,
                answer: None,
            },
        };
        // The interface is told as the event is emitted, from its settled target; here the
        // interfaces are listed again if the target's local address is new to them.
        if let Target::Socket(endpoint) = &*target
            && self
                .interfaces
                .wants_listing(endpoint, self.fds.netns(done.pid), done.end_ts)
        {
            self.interfaces.update(src.interfaces(), done.end_ts);
        }
        let unit = op.result_unit();
        let ret = done.is_ok().then(|| done.ret_u64());
        let event = IoEvent {
            time_ns: self.unix_ns(done.end_ts),
            pid: done.pid,
            tid: done.tid,
            op,
            syscall: done.call.name,
            fd,
            requested: len_arg.and_then(|index| done.arg(index)),
            bytes: ret.filter(|_| unit == ResultUnit::Bytes),
            messages: ret.filter(|_| unit == ResultUnit::Messages),
            errno: done.errno,
            latency_ns: done
                .latency_ticks()
                .map(|ticks| self.info.timebase.ticks_to_nanos(ticks)),
            target,
            provenance,
            interface: Via::NoInterface,
        };
        (event, answer)
    }

    /// Applies the exits the reader saw by trace time `ticks`, which the trace has reached.
    fn reach(&mut self, ticks: u64, sink: &mut dyn Sink) -> io::Result<()> {
        while let Some(&(seen, pid)) = self.exits.front() {
            if seen > ticks {
                break;
            }
            self.exits.pop_front();
            self.exited(pid, sink)?;
        }
        Ok(())
    }

    fn exited(&mut self, pid: i32, sink: &mut dyn Sink) -> io::Result<()> {
        match self.processes.get_mut(&pid) {
            Some(state) if state.alive => {
                state.alive = false;
                let process = Process {
                    pid,
                    name: state.name.clone(),
                };
                self.fds.detach(pid);
                self.hold(Held::Notice(Notice::Exited(process)), sink)
            }
            _ => Ok(()),
        }
    }

    fn unix_ns(&self, ticks: u64) -> u64 {
        self.info.anchor.unix_nanos_at(self.info.timebase, ticks)
    }
}

/// A sink that drops everything, for input whose output nobody will see.
#[derive(Debug, Default)]
pub struct Discard;

impl Sink for Discard {
    fn event(&mut self, _: &IoEvent) -> io::Result<()> {
        Ok(())
    }

    fn notice(&mut self, _: &Notice) -> io::Result<()> {
        Ok(())
    }
}

/// A sink that keeps everything; for tests.
#[derive(Debug, Default)]
pub struct Collect {
    pub events: Vec<IoEvent>,
    pub notices: Vec<Notice>,
}

impl Sink for Collect {
    fn event(&mut self, event: &IoEvent) -> io::Result<()> {
        self.events.push(event.clone());
        Ok(())
    }

    fn notice(&mut self, notice: &Notice) -> io::Result<()> {
        self.notices.push(notice.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::{Interface, Listing};
    use crate::model::{Endpoint, Proto};
    use crate::trace::kdebug::KdBuf;
    use crate::trace::kdebug::synth::{Call, Synth};
    use crate::trace::linux::synth::{self as linux_synth, Synth as LinuxSynth};
    use crate::trace::linux::{Event, Memory, Record};
    use crate::trace::procs::{Fixed, Snapshot};

    const PID: i32 = 501;

    fn info() -> SessionInfo {
        SessionInfo {
            timebase: Timebase { numer: 1, denom: 1 },
            anchor: ClockAnchor {
                ticks: 1_000,
                unix_nanos: 1_700_000_000_000_000_000,
            },
            processes: vec![Process {
                pid: PID,
                name: "demo".into(),
            }],
            path_records: PathRecords::Whole,
            system: System::Macos,
        }
    }

    fn procs() -> Fixed {
        let mut procs = Fixed::default();
        procs.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![(
                    1,
                    Target::File {
                        path: "/dev/ttys001".into(),
                    },
                )],
                cwd: Some("/work".into()),
                netns: None,
            },
        );
        procs
    }

    #[test]
    fn traces_file_and_socket_io() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut records = synth.open(7, PID, "data.txt", 3);
        records.extend(synth.io(7, PID, 3, 3, 4096, 1000));
        let read_end = synth.now();
        records.extend(synth.io(7, PID, 397, 1, 12, 12));
        records.extend(synth.close(7, PID, 3));
        records.extend(synth.call(Call {
            ret: 4,
            ..Call::new(8, PID, 97, [2, 1, 0, 0])
        }));
        let peer = Endpoint {
            proto: Proto::Tcp,
            local: Some("10.0.0.2:5000".parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            path: None,
        };
        src.targets.insert((PID, 4), Target::Socket(peer.clone()));
        records.extend(synth.call(Call::new(8, PID, 98, [4, 0, 16, 0])));
        records.extend(synth.io(8, PID, 133, 4, 517, 517));
        records.extend(synth.io(8, PID, 29, 4, 16_384, 3_000));

        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        let lines: Vec<String> = sink
            .events
            .iter()
            .map(|e| format!("{} {:?} {:?} {}", e.syscall, e.fd, e.bytes, e.target))
            .collect();
        assert_eq!(
            lines,
            [
                "read Some(3) Some(1000) /work/data.txt",
                "write_nocancel Some(1) Some(12) /dev/ttys001",
                "sendto Some(4) Some(517) tcp 10.0.0.2:5000 -> 93.184.216.34:443",
                "recvfrom Some(4) Some(3000) tcp 10.0.0.2:5000 -> 93.184.216.34:443",
            ]
        );
        let read = &sink.events[0];
        assert_eq!(
            (read.requested, read.latency_ns, read.provenance),
            (Some(4096), Some(10), Provenance::Traced)
        );
        assert_eq!(sink.events[1].provenance, Provenance::Snapshot);
        // With a 1:1 timebase, wall time is the anchor plus the tick offset.
        assert_eq!(read.time_ns, 1_700_000_000_000_000_000 + (read_end - 1_000));

        let totals = *session.stats().totals();
        assert_eq!((totals.file_read.bytes, totals.file_write.bytes), (1000, 12));
        assert_eq!((totals.net_write.bytes, totals.net_read.bytes), (517, 3000));
    }

    #[test]
    fn a_copy_onto_a_descriptor_of_the_same_file_does_not_hold_up_the_events_after_it() {
        let mut src = procs();
        // libproc describes fd 5, which the trace never saw made, long after the calls below.
        src.targets.insert(
            (PID, 5),
            Target::File {
                path: "/srv/shared".into(),
            },
        );
        src.answered_at = 50_000;
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        // dup(5) makes 6 rest on that answer, and dup2(6, 5) gives the number back to the same
        // file.
        let mut records = synth.call(Call {
            ret: 6,
            ..Call::new(7, PID, 41, [5, 0, 0, 0])
        });
        records.extend(synth.call(Call {
            ret: 5,
            ..Call::new(7, PID, 90, [6, 5, 0, 0])
        }));
        records.extend(synth.io(7, PID, 4, 5, 8, 8));
        records.extend(synth.io(7, PID, 4, 1, 20, 20));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        assert!(sink.events.is_empty(), "the answer is not checked yet");
        session
            .handle(&Input::Stopped { ticks: 60_000 }, &mut src, &mut sink)
            .unwrap();
        let shown: Vec<String> = sink
            .events
            .iter()
            .map(|e| format!("{:?} {}", e.fd, e.target))
            .collect();
        assert_eq!(shown, ["Some(5) /srv/shared", "Some(1) /dev/ttys001"]);
    }

    #[test]
    fn an_answer_stamped_with_the_last_time_there_is_does_not_hold_back_the_end() {
        let mut src = procs();
        // A recording may stamp what libproc said with any time.
        src.targets.insert(
            (PID, 5),
            Target::File {
                path: "/srv/late".into(),
            },
        );
        src.answered_at = u64::MAX;
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let records = synth.io(7, PID, 4, 5, 8, 8);
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        assert!(sink.events.is_empty(), "the answer is not checked yet");
        session
            .handle(&Input::Stopped { ticks: 60_000 }, &mut src, &mut sink)
            .unwrap();
        assert_eq!(sink.events.len(), 1);
        assert_eq!(
            *sink.events[0].target,
            Target::File {
                path: "/srv/late".into()
            }
        );
    }

    #[test]
    fn events_wait_for_libproc_and_drop_stale_answers() {
        let mut src = procs();
        src.interfaces = vec![listing(&[])];
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        // Two connections one after the other on fd 4. libproc is asked late about both, and
        // by then fd 4 is the second connection.
        let later = Endpoint {
            local: Some("10.0.0.2:5001".parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        };
        src.targets.insert((PID, 4), Target::Socket(later));
        src.answered_at = 50_000;
        let mut records = Vec::new();
        for len in [10, 20] {
            records.extend(synth.call(Call {
                ret: 4,
                ..Call::new(8, PID, 97, [2, 1, 0, 0])
            }));
            records.extend(synth.call(Call::new(8, PID, 98, [4, 0, 16, 0])));
            records.extend(synth.io(8, PID, 133, 4, len, len));
            if len == 10 {
                records.extend(synth.close(8, PID, 4));
            }
        }
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        let shown = |sink: &Collect| -> Vec<String> {
            sink.events
                .iter()
                .map(|e| format!("{:?} {}", e.bytes, e.target))
                .collect()
        };
        // The close came before the answer, so the first send keeps what the trace knows.
        assert_eq!(shown(&sink), ["Some(10) tcp ?"]);
        let late = Input::Attached {
            process: Process {
                pid: 9,
                name: "late".into(),
            },
            parent: None,
        };
        session.handle(&late, &mut src, &mut sink).unwrap();
        assert!(sink.notices.is_empty(), "the notice waits behind the second send");
        session
            .handle(&Input::Watermark { ticks: 50_000 }, &mut src, &mut sink)
            .unwrap();
        assert_eq!(sink.events.len(), 1, "the trace is not past the answer yet");
        session
            .handle(&Input::Watermark { ticks: 50_001 }, &mut src, &mut sink)
            .unwrap();
        assert_eq!(
            shown(&sink),
            [
                "Some(10) tcp ?",
                "Some(20) tcp 10.0.0.2:5001 -> 93.184.216.34:443"
            ]
        );
        assert_eq!(sink.notices.len(), 1);
        assert_eq!(session.stats().totals().net_write.bytes, 30);
        // Each takes the interface of the target it was settled with.
        let interfaces: Vec<String> = sink.events.iter().map(|e| e.interface.to_string()).collect();
        assert_eq!(interfaces, ["?", "en0"]);
    }

    #[test]
    fn a_file_opened_again_on_its_number_keeps_the_name_libproc_gave() {
        let reads = |other_file: bool| -> Vec<String> {
            let mut src = procs();
            // Asked late, libproc describes whatever holds fd 3 by then: the second open.
            src.targets.insert(
                (PID, 3),
                Target::File {
                    path: "/usr/share/dict/web2".into(),
                },
            );
            src.answered_at = 50_000;
            let mut session = Session::new(info(), Filter::ALL, &mut src);
            let mut synth = Synth::new(2_000, 10);
            // `/usr/share/dict/words` links to `web2`, so the kernel reports only that name.
            synth.find_vnode(0xabc0);
            let mut records = synth.open(8, PID, "web2", 3);
            records.extend(synth.io(8, PID, 3, 3, 100, 100));
            records.extend(synth.close(8, PID, 3));
            // getcwd holds the number for a moment in between.
            records.extend(synth.open(8, PID, ".", 3));
            records.extend(synth.close(8, PID, 3));
            synth.find_vnode(if other_file { 0xdef0 } else { 0xabc0 });
            records.extend(synth.open(8, PID, "web2", 3));
            records.extend(synth.io(8, PID, 3, 3, 200, 200));
            let mut sink = Collect::default();
            session
                .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
                .unwrap();
            assert!(sink.events.is_empty(), "both reads wait for their answers");
            session
                .handle(&Input::Watermark { ticks: 50_001 }, &mut src, &mut sink)
                .unwrap();
            sink.events.iter().map(|e| e.target.to_string()).collect()
        };
        assert_eq!(reads(false), ["/usr/share/dict/web2", "/usr/share/dict/web2"]);
        // Another file of that name on the number: the first read keeps what the trace says.
        assert_eq!(reads(true), ["/work/web2", "/usr/share/dict/web2"]);
    }

    #[test]
    fn stopping_releases_what_still_waits() {
        let mut src = procs();
        src.answered_at = 1 << 40;
        src.targets
            .insert((PID, 6), Target::File { path: "/late".into() });
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let records = synth.io(7, PID, 3, 6, 8, 8);
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        assert!(sink.events.is_empty());
        session
            .handle(&Input::Stopped { ticks: 9_000 }, &mut src, &mut sink)
            .unwrap();
        assert_eq!(sink.events[0].target.to_string(), "/late");
        assert_eq!(sink.events[0].provenance, Provenance::Lazy);
    }

    #[test]
    fn socket_only_calls_mark_unknown_descriptors_as_sockets() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        // socketpair(2) returns its descriptors through memory, and these were closed before
        // they could be looked up. Only calls that need a socket reveal what they were.
        let mut records = synth.io(7, PID, 28, 9, 0, 3);
        records.extend(synth.io(7, PID, 3, 9, 16, 3));
        records.extend(synth.call(Call {
            errno: libc::ENOTSOCK,
            ..Call::new(7, PID, 133, [8, 0, 5, 0])
        }));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        let targets: Vec<String> = sink.events.iter().map(|e| e.target.to_string()).collect();
        assert_eq!(targets, ["socket", "<unknown>", "<unknown>"]);
        assert_eq!(sink.events[0].provenance, Provenance::None);
        let totals = *session.stats().totals();
        assert_eq!((totals.net_write.bytes, totals.other_read.bytes), (3, 3));
    }

    #[test]
    fn lost_records_reload_descriptors_and_warn() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut records = vec![synth.syscall_start(7, 3, [1, 0, 8, 0])];
        records.push(synth.lost_events());
        // The END of the read begun before the loss is an orphan; fd 1 is still known.
        records.push(synth.syscall_end(7, 3, PID, 0, [8, 0]));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        assert!(matches!(sink.notices[..], [Notice::LostEvents { .. }]));
        assert_eq!(sink.events.len(), 1);
        assert_eq!((sink.events[0].fd, sink.events[0].bytes), (None, Some(8)));
        assert_eq!(*sink.events[0].target, Target::Unknown);
        let summary = session.summary();
        assert_eq!(
            (
                summary.lost_events,
                summary.unfinished_calls,
                summary.calls_started_before_trace
            ),
            (1, 1, 1)
        );
        assert_eq!(session.lost_events(), 1);
    }

    #[test]
    fn process_exit_is_reported_once() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut sink = Collect::default();
        session
            .handle(
                &Input::Records(Records::Kdebug(vec![synth.proc_exit(7, PID, 0)])),
                &mut src,
                &mut sink,
            )
            .unwrap();
        session
            .handle(&Input::Exited { pid: PID, ticks: 0 }, &mut src, &mut sink)
            .unwrap();
        assert_eq!(
            sink.notices,
            [Notice::Exited(Process {
                pid: PID,
                name: "demo".into()
            })]
        );
        assert!(session.all_exited());
        session
            .handle(
                &Input::Stopped {
                    ticks: 1_000 + 5_000_000_000,
                },
                &mut src,
                &mut sink,
            )
            .unwrap();
        assert_eq!(session.summary().duration_ns, 5_000_000_000);
    }

    #[test]
    fn an_exit_the_reader_saw_waits_for_the_trace_to_reach_it() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut sink = Collect::default();
        // The reader looked at 2_500 and found the process gone; its last write, stamped
        // earlier, arrives after that.
        session
            .handle(
                &Input::Exited {
                    pid: PID,
                    ticks: 2_500,
                },
                &mut src,
                &mut sink,
            )
            .unwrap();
        assert!(!session.all_exited());
        let write = synth.io(7, PID, 4, 1, 5, 5);
        session
            .handle(&Input::Records(Records::Kdebug(write)), &mut src, &mut sink)
            .unwrap();
        assert_eq!(sink.events.len(), 1);
        assert_eq!(
            *sink.events[0].target,
            Target::File {
                path: "/dev/ttys001".into()
            },
            "the descriptor table still held the process"
        );
        assert!(sink.notices.is_empty());
        session
            .handle(&Input::Watermark { ticks: 2_499 }, &mut src, &mut sink)
            .unwrap();
        assert!(sink.notices.is_empty());
        session
            .handle(&Input::Watermark { ticks: 2_500 }, &mut src, &mut sink)
            .unwrap();
        assert!(matches!(
            sink.notices[..],
            [Notice::Exited(Process { pid: PID, .. })]
        ));
        assert!(session.all_exited());

        // Once no more input comes, every exit counts.
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        session
            .handle(
                &Input::Exited {
                    pid: PID,
                    ticks: 9_000,
                },
                &mut src,
                &mut Discard,
            )
            .unwrap();
        session
            .handle(&Input::Stopped { ticks: 3_000 }, &mut src, &mut Discard)
            .unwrap();
        assert!(session.all_exited());
    }

    /// Linux records whose numbers mean the same on any host.
    #[test]
    fn traces_linux_records() {
        let mut src = procs();
        let info = SessionInfo {
            system: System::LinuxX86_64,
            ..info()
        };
        let mut session = Session::new(info, Filter::ALL, &mut src);
        let mut synth = LinuxSynth::new(System::LinuxX86_64, 2_000, 10);
        let call = linux_synth::Call::new;
        let records = vec![
            synth.open(7, PID, "/srv/data.txt", 3),
            synth.io(7, PID, "read", 3, 4096, 1000),
            // pipe2 and socketpair store their descriptors in memory.
            synth.call(linux_synth::Call {
                memory: Memory::Fds([4, 5]),
                ..call(7, PID, "pipe2", [0xffff_f000, 0, 0, 0, 0, 0])
            }),
            synth.io(7, PID, "write", 5, 3, 3),
            // AF_UNIX, SOCK_STREAM.
            synth.call(linux_synth::Call {
                memory: Memory::Fds([6, 7]),
                ..call(7, PID, "socketpair", [1, 1, 0, 0xffff_e000, 0, 0])
            }),
            synth.io(7, PID, "sendto", 6, 2, 2),
            // Everything from descriptor 3 up.
            synth.call(call(7, PID, "close_range", [3, u64::from(u32::MAX), 0, 0, 0, 0])),
            synth.io(7, PID, "read", 3, 10, 10),
            synth.lost(40),
            Record {
                ts: synth.now() + 1,
                dropped: 40,
                event: Event::InProgress { calls: 2 },
            },
            synth.exit(PID),
        ];
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Linux(records)), &mut src, &mut sink)
            .unwrap();
        let shown: Vec<String> = sink
            .events
            .iter()
            .map(|e| format!("{} {:?} {}", e.syscall, e.bytes, e.target))
            .collect();
        assert_eq!(
            shown,
            [
                "read Some(1000) /srv/data.txt",
                "write Some(3) <pipe>",
                "sendto Some(2) unix",
                "read Some(10) <unknown>"
            ]
        );
        assert_eq!(sink.events[0].latency_ns, Some(10));
        assert!(matches!(
            sink.notices[..],
            [Notice::LostEvents { .. }, Notice::Exited(_)]
        ));
        let summary = session.summary();
        assert_eq!((summary.lost_events, summary.unfinished_calls), (1, 2));
        assert!(session.all_exited());
    }

    #[test]
    fn a_file_with_no_name_is_not_taken_for_the_directory_it_was_made_in() {
        let mut src = procs();
        // What /proc says of the descriptor that open(dir, O_TMPFILE) returned.
        src.targets.insert(
            (PID, 5),
            Target::File {
                path: "/tmp/#7301".into(),
            },
        );
        let info = SessionInfo {
            system: System::LinuxX86_64,
            ..info()
        };
        let mut session = Session::new(info, Filter::ALL, &mut src);
        let mut synth = LinuxSynth::new(System::LinuxX86_64, 2_000, 10);
        let (o_tmpfile, o_rdwr) = (0o20_200_000, 2);
        let records = vec![
            synth.call(linux_synth::Call {
                ret: 5,
                memory: Memory::Path(b"/tmp".to_vec()),
                ..linux_synth::Call::new(
                    7,
                    PID,
                    "openat",
                    [
                        linux_synth::AT_FDCWD,
                        0xffff_0000,
                        o_tmpfile | o_rdwr,
                        0o600,
                        0,
                        0,
                    ],
                )
            }),
            synth.io(7, PID, "write", 5, 4096, 4096),
        ];
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Linux(records)), &mut src, &mut sink)
            .unwrap();
        let shown: Vec<String> = sink
            .events
            .iter()
            .map(|e| format!("{} {:?} {}", e.syscall, e.bytes, e.target))
            .collect();
        assert_eq!(shown, ["write Some(4096) /tmp/#7301"]);
    }

    #[test]
    fn a_child_is_traced_with_its_parents_descriptors() {
        const CHILD: i32 = 777;
        let mut src = procs();
        let info = SessionInfo {
            system: System::LinuxX86_64,
            ..info()
        };
        let mut session = Session::new(info, Filter::ALL, &mut src);
        let mut synth = LinuxSynth::new(System::LinuxX86_64, 2_000, 10);
        let untraced = Record {
            ts: synth.now() + 1,
            dropped: 0,
            event: Event::Fork {
                parent: PID,
                child: 778,
                traced: false,
            },
        };
        let records = vec![
            synth.open(7, PID, "/srv/data.txt", 3),
            untraced,
            synth.fork(PID, CHILD),
            synth.io(CHILD, CHILD, "read", 3, 4096, 1000),
            synth.io(CHILD, CHILD, "write", 1, 12, 12),
            synth.close(CHILD, CHILD, 3),
            synth.open(CHILD, CHILD, "/srv/log.txt", 4),
            synth.io(CHILD, CHILD, "write", 4, 3, 3),
            synth.io(7, PID, "read", 3, 4096, 20),
            synth.exit(CHILD),
        ];
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Linux(records)), &mut src, &mut sink)
            .unwrap();
        let shown: Vec<String> = sink
            .events
            .iter()
            .map(|e| format!("{} {} {:?} {}", e.pid, e.syscall, e.bytes, e.target))
            .collect();
        assert_eq!(
            shown,
            [
                "777 read Some(1000) /srv/data.txt",
                "777 write Some(12) /dev/ttys001",
                "777 write Some(3) /srv/log.txt",
                "501 read Some(20) /srv/data.txt",
            ]
        );
        let demo = |pid| Process {
            pid,
            name: "demo".into(),
        };
        assert_eq!(
            sink.notices,
            [
                Notice::Untraced {
                    pid: 778,
                    parent: Some(PID),
                    reason: UntracedReason::Full
                },
                Notice::Attached {
                    process: demo(CHILD),
                    parent: Some(PID)
                },
                Notice::Exited(demo(CHILD)),
            ]
        );
        let summary = session.summary();
        assert_eq!(summary.processes, [demo(PID), demo(CHILD)]);
        assert_eq!(summary.untraced_children, UntracedChildren { ended: 0, full: 1 });
        assert!(!session.all_exited(), "the parent runs on");
    }

    #[test]
    fn untraced_children_are_counted_by_why() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut sink = Collect::default();
        for pid in [600, 601] {
            let untraced = Input::Untraced {
                pid,
                parent: None,
                reason: UntracedReason::Ended,
            };
            session.handle(&untraced, &mut src, &mut sink).unwrap();
        }
        assert_eq!(sink.notices.len(), 2);
        assert_eq!(
            session.summary().untraced_children,
            UntracedChildren { ended: 2, full: 0 }
        );
    }

    /// Linux records whose numbers are Linux's own.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_numbers_mean_what_they_mean_on_linux() {
        let mut src = procs();
        let peer = Target::Socket(Endpoint {
            local: Some("10.0.0.2:5000".parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        });
        src.targets.insert((PID, 4), peer);
        let info = SessionInfo {
            system: System::HOST,
            ..info()
        };
        let mut session = Session::new(info, Filter::ALL, &mut src);
        let mut synth = LinuxSynth::new(System::HOST, 2_000, 10);
        let call = linux_synth::Call::new;
        let cloexec = u64::try_from(libc::F_DUPFD_CLOEXEC).unwrap();
        let sock_type = u64::try_from(libc::SOCK_STREAM | libc::SOCK_CLOEXEC).unwrap();
        let records = vec![
            // Relative to the working directory.
            synth.open(7, PID, "data.txt", 3),
            synth.call(linux_synth::Call {
                ret: 10,
                ..call(7, PID, "fcntl", [3, cloexec, 10, 0, 0, 0])
            }),
            synth.io(7, PID, "read", 10, 5, 5),
            synth.call(linux_synth::Call {
                ret: 4,
                ..call(7, PID, "socket", [2, sock_type, 0, 0, 0, 0])
            }),
            synth.io(7, PID, "sendto", 4, 9, 9),
        ];
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Linux(records)), &mut src, &mut sink)
            .unwrap();
        let targets: Vec<String> = sink.events.iter().map(|e| e.target.to_string()).collect();
        assert_eq!(
            targets,
            ["/work/data.txt", "tcp 10.0.0.2:5000 -> 93.184.216.34:443"]
        );
    }

    /// The loopback interface, and en0 with 10.0.0.2 and `more` besides.
    fn listing(more: &[&str]) -> Listing {
        let mut addrs = vec!["10.0.0.2".parse().unwrap()];
        addrs.extend(more.iter().map(|addr| addr.parse::<std::net::IpAddr>().unwrap()));
        Listing {
            interfaces: vec![
                Interface {
                    name: "lo0".into(),
                    index: 1,
                    loopback: true,
                    addrs: vec!["127.0.0.1".parse().unwrap()],
                },
                Interface {
                    name: "en0".into(),
                    index: 4,
                    loopback: false,
                    addrs,
                },
            ],
            netns: Some(7),
        }
    }

    /// A TCP connection from `local` to 93.184.216.34:443 on `fd`, which libproc describes.
    fn connect(synth: &mut Synth, src: &mut Fixed, fd: i32, local: &str) -> Vec<KdBuf> {
        let peer = Endpoint {
            local: Some(local.parse().unwrap()),
            remote: Some("93.184.216.34:443".parse().unwrap()),
            ..Endpoint::unresolved(Proto::Tcp)
        };
        src.targets.insert((PID, fd), Target::Socket(peer));
        let fd = u64::from(fd.cast_unsigned());
        let mut records = synth.call(Call {
            ret: fd,
            ..Call::new(8, PID, 97, [2, 1, 0, 0])
        });
        records.extend(synth.call(Call::new(8, PID, 98, [fd, 0, 16, 0])));
        records
    }

    fn interfaces_of(sink: &Collect) -> Vec<String> {
        sink.events
            .iter()
            .map(|e| format!("{} {}", e.interface, e.target))
            .collect()
    }

    #[test]
    fn events_name_the_interface_their_socket_uses() {
        let mut src = procs();
        src.interfaces = vec![listing(&[])];
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut records = synth.io(7, PID, 4, 1, 12, 12);
        records.extend(connect(&mut synth, &mut src, 4, "10.0.0.2:5000"));
        records.extend(synth.io(8, PID, 133, 4, 517, 517));
        records.extend(connect(&mut synth, &mut src, 5, "127.0.0.1:5001"));
        records.extend(synth.io(8, PID, 29, 5, 100, 40));
        // A send on a descriptor iotap cannot identify, which is at least a socket.
        records.extend(synth.io(8, PID, 133, 9, 20, 20));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        assert_eq!(
            interfaces_of(&sink),
            [
                "none /dev/ttys001",
                "en0 tcp 10.0.0.2:5000 -> 93.184.216.34:443",
                "lo0 tcp 127.0.0.1:5001 -> 93.184.216.34:443",
                "? socket",
            ]
        );
        assert_eq!(src.interfaces_asked, 1);
        let summary = session.summary();
        let totals: Vec<(String, u64, u64)> = summary
            .interfaces
            .iter()
            .map(|t| (t.interface.to_string(), t.read_bytes, t.write_bytes))
            .collect();
        assert_eq!(
            totals,
            [
                ("en0".to_owned(), 0, 517),
                ("lo0".to_owned(), 40, 0),
                ("?".to_owned(), 0, 20)
            ]
        );
        assert_eq!(summary.unknown_interface_calls, 0);
    }

    #[test]
    fn a_new_local_address_lists_the_interfaces_again() {
        let mut src = procs();
        // A VPN comes up after tracing starts.
        src.interfaces = vec![listing(&[]), listing(&["10.8.0.2"])];
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        // More than a second after the first listing.
        let mut synth = Synth::new(2_000_000_000, 10);
        let mut records = connect(&mut synth, &mut src, 4, "10.8.0.2:5000");
        records.extend(synth.io(8, PID, 133, 4, 10, 10));
        records.extend(synth.io(8, PID, 133, 4, 10, 10));
        // Another new address within the second waits for the next listing.
        records.extend(connect(&mut synth, &mut src, 5, "10.9.0.2:5000"));
        records.extend(synth.io(8, PID, 133, 5, 10, 10));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        let shown: Vec<String> = sink.events.iter().map(|e| e.interface.to_string()).collect();
        assert_eq!(shown, ["en0", "en0", "?"]);
        assert_eq!(src.interfaces_asked, 2);
        let names: Vec<&str> = session.interfaces().names().collect();
        assert_eq!(names, ["lo0", "en0"]);
    }

    #[test]
    fn processes_in_another_network_namespace_list_nothing() {
        let mut src = procs();
        src.interfaces = vec![listing(&[])];
        if let Some(snapshot) = src.snapshots.get_mut(&PID) {
            snapshot.netns = Some(8);
        }
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000_000_000, 10);
        // 10.0.0.2 is the host's address, and the container's own only by chance.
        let mut records = connect(&mut synth, &mut src, 4, "10.0.0.2:5000");
        records.extend(synth.io(8, PID, 133, 4, 10, 10));
        records.extend(connect(&mut synth, &mut src, 5, "172.17.0.2:5000"));
        records.extend(synth.io(8, PID, 133, 5, 10, 10));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        let shown: Vec<String> = sink.events.iter().map(|e| e.interface.to_string()).collect();
        assert_eq!(shown, ["?", "?"]);
        assert_eq!(src.interfaces_asked, 1);
    }

    #[test]
    fn the_interface_filter_keeps_named_interfaces_and_counts_unknown_ones() {
        let mut src = procs();
        src.interfaces = vec![listing(&[])];
        let filter = Filter {
            files: false,
            other: false,
            interfaces: vec!["en0".into()],
            ..Filter::ALL
        };
        let mut session = Session::new(info(), filter, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut records = synth.io(7, PID, 4, 1, 12, 12);
        records.extend(connect(&mut synth, &mut src, 4, "10.0.0.2:5000"));
        records.extend(synth.io(8, PID, 133, 4, 517, 517));
        records.extend(connect(&mut synth, &mut src, 5, "127.0.0.1:5001"));
        records.extend(synth.io(8, PID, 133, 5, 1, 1));
        let unix = Endpoint {
            path: Some("/var/run/mDNSResponder".into()),
            ..Endpoint::unresolved(Proto::Unix)
        };
        src.targets.insert((PID, 6), Target::Socket(unix));
        records.extend(synth.io(8, PID, 133, 6, 2, 2));
        records.extend(synth.io(8, PID, 133, 9, 20, 20));
        records.extend(synth.io(8, PID, 133, 9, 20, 20));
        let mut sink = Collect::default();
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut sink)
            .unwrap();
        assert_eq!(
            interfaces_of(&sink),
            ["en0 tcp 10.0.0.2:5000 -> 93.184.216.34:443"]
        );
        let summary = session.summary();
        assert_eq!(summary.unknown_interface_calls, 2);
        assert_eq!(summary.totals.events, 1);
        assert_eq!(summary.interfaces.len(), 1);
    }

    #[test]
    fn filter_drops_other_categories() {
        let mut src = procs();
        let filter = Filter {
            files: false,
            other: false,
            ..Filter::ALL
        };
        let mut session = Session::new(info(), filter, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut sink = Collect::default();
        session
            .handle(
                &Input::Records(Records::Kdebug(synth.io(7, PID, 4, 1, 5, 5))),
                &mut src,
                &mut sink,
            )
            .unwrap();
        assert!(sink.events.is_empty());
        assert_eq!(session.stats().totals().events, 0);
    }

    #[test]
    fn attach_and_exec_update_processes() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut sink = Collect::default();
        let child = Process {
            pid: 777,
            name: "demo".into(),
        };
        let attached = Input::Attached {
            process: child.clone(),
            parent: Some(PID),
        };
        session.handle(&attached, &mut src, &mut sink).unwrap();
        session
            .handle(
                &Input::Exec {
                    pid: PID,
                    path: "/usr/bin/other".into(),
                },
                &mut src,
                &mut sink,
            )
            .unwrap();
        assert_eq!(session.process_name(PID), Some("other"));
        assert_eq!(
            sink.notices[0],
            Notice::Attached {
                process: child,
                parent: Some(PID)
            }
        );
        assert!(!session.all_exited());
        session
            .handle(&Input::Exited { pid: 777, ticks: 0 }, &mut src, &mut Discard)
            .unwrap();
        let status = |pid, name: &str, alive| ProcessStatus {
            pid,
            name: name.into(),
            alive,
        };
        assert_eq!(
            session.processes(),
            [status(PID, "other", true), status(777, "demo", false)]
        );
    }
}
