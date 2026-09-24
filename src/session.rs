//! The deterministic core: turns reader input into I/O events, notices and statistics.
//!
//! A session depends only on its input and on the answers of its [`ProcSource`], never on
//! wall-clock time, so a recording replays to the same output.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::{Category, Endpoint, IoEvent, Op, Proto, Provenance, ResultUnit, Target};
use crate::stats::{Stats, SummaryRow, Totals};
use crate::sys::time::{ClockAnchor, Timebase};
use crate::trace::call::{Completed, Role};
use crate::trace::fdtable::{FdTable, Found, Verdict};
use crate::trace::kdebug::{self, pairing::PathRecords};
use crate::trace::procs::ProcSource;
use crate::trace::{Decode, Records, Step, Traced};

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
}

/// What the kernel reader delivers, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Records(Records),
    /// A newly started process matching a traced name is now traced too.
    Attached(Process),
    /// A traced process replaced its program image.
    Exec {
        pid: i32,
        path: String,
    },
    /// A traced process is gone.
    Exited {
        pid: i32,
    },
    /// Tracing stopped at this mach time.
    Stopped {
        ticks: u64,
    },
    /// Every record up to this mach time has been delivered.
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
    Attached(Process),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filter {
    pub files: bool,
    pub network: bool,
    pub other: bool,
}

impl Filter {
    pub const ALL: Self = Self {
        files: true,
        network: true,
        other: true,
    };

    pub fn accepts(self, category: Category) -> bool {
        match category {
            Category::File => self.files,
            Category::Network => self.network,
            Category::Other => self.other,
        }
    }
}

/// End-of-session report.
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub duration_ns: u64,
    pub processes: Vec<Process>,
    pub totals: Totals,
    /// Times the kernel reported dropped records.
    pub lost_events: u64,
    /// Calls whose END was not seen.
    pub unfinished_calls: u64,
    /// Calls whose START was not seen, mostly calls already blocked when tracing began.
    pub calls_started_before_trace: u64,
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
        /// The unconfirmed libproc answer the target came from.
        answer: Option<u64>,
    },
    Notice(Notice),
}

impl Held {
    fn is_ready(&self) -> bool {
        !matches!(self, Self::Event { answer: Some(_), .. })
    }
}

#[derive(Debug)]
pub struct Session {
    info: SessionInfo,
    filter: Filter,
    /// Puts kdebug records together.
    kdebug: kdebug::Decoder,
    fds: FdTable,
    stats: Stats,
    processes: BTreeMap<i32, ProcessState>,
    lost_events: u64,
    last_ticks: u64,
    stopped_ticks: Option<u64>,
    unknown: Arc<Target>,
    /// Stands in for an unidentified descriptor that a socket-only call used.
    some_socket: Arc<Target>,
    /// Events and notices waiting, in order, for the first of them to be settled.
    held: VecDeque<Held>,
}

impl Session {
    /// Starts a session and loads the descriptor tables of the initial processes.
    pub fn new(info: SessionInfo, filter: Filter, src: &mut dyn ProcSource) -> Self {
        let retry_ticks = info.timebase.nanos_to_ticks(1_000_000_000);
        let mut session = Self {
            filter,
            kdebug: kdebug::Decoder::new(info.path_records),
            fds: FdTable::new(retry_ticks),
            stats: Stats::default(),
            processes: BTreeMap::new(),
            lost_events: 0,
            last_ticks: info.anchor.ticks,
            stopped_ticks: None,
            unknown: Arc::new(Target::Unknown),
            some_socket: Arc::new(Target::Socket(Endpoint::unresolved(Proto::Other))),
            held: VecDeque::new(),
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
    pub fn filter(&self) -> Filter {
        self.filter
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
        match input {
            Input::Records(Records::Kdebug(records)) => {
                for record in records {
                    if let Some(step) = self.kdebug.decode(record) {
                        self.step(step, src, sink)?;
                    }
                }
            }
            Input::Attached(process) => {
                let alive = self.fds.attach(process.pid, src);
                self.processes.insert(
                    process.pid,
                    ProcessState {
                        name: process.name.clone(),
                        alive,
                    },
                );
                self.hold(Held::Notice(Notice::Attached(process.clone())), sink)?;
            }
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
            Input::Exited { pid } => self.exited(*pid, sink)?,
            Input::Stopped { ticks } => {
                self.stopped_ticks = Some((*ticks).max(self.last_ticks));
                self.finish(sink)?;
            }
            Input::Watermark { ticks } => {
                self.last_ticks = self.last_ticks.max(*ticks);
                self.fds.advance(*ticks);
                self.settle(sink)?;
            }
        }
        Ok(())
    }

    /// Settles every answer still unconfirmed and emits what waited for it. Call it when no
    /// more input will come; a `Stopped` input does it too.
    pub fn finish(&mut self, sink: &mut dyn Sink) -> io::Result<()> {
        self.fds.advance(u64::MAX);
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
            lost_events: self.lost_events,
            unfinished_calls: self.kdebug.unfinished_calls(),
            calls_started_before_trace: self.kdebug.calls_started_before_trace(),
            files: self.stats.summary_rows(Category::File),
            network: self.stats.summary_rows(Category::Network),
            other: self.stats.summary_rows(Category::Other),
        }
    }

    /// Applies what one record tells.
    fn step(&mut self, step: Step, src: &mut dyn ProcSource, sink: &mut dyn Sink) -> io::Result<()> {
        self.last_ticks = self.last_ticks.max(step.ts);
        match step.traced {
            Some(Traced::Call(done)) => self.completed(&done, src, sink)?,
            Some(Traced::ProcExit { pid }) => self.exited(pid, sink)?,
            Some(Traced::LostEvents) => self.lost(step.ts, src, sink)?,
            None => {}
        }
        // Every record up to this one has been seen now.
        self.fds.advance(step.ts);
        self.settle(sink)
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
        };
        (event, answer)
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
    use crate::model::{Endpoint, Proto};
    use crate::trace::kdebug::synth::{Call, Synth};
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
    fn events_wait_for_libproc_and_drop_stale_answers() {
        let mut src = procs();
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
        session
            .handle(
                &Input::Attached(Process {
                    pid: 9,
                    name: "late".into(),
                }),
                &mut src,
                &mut sink,
            )
            .unwrap();
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
            .handle(&Input::Exited { pid: PID }, &mut src, &mut sink)
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
    fn filter_drops_other_categories() {
        let mut src = procs();
        let filter = Filter {
            files: false,
            network: true,
            other: false,
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
        session
            .handle(&Input::Attached(child.clone()), &mut src, &mut sink)
            .unwrap();
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
        assert_eq!(sink.notices[0], Notice::Attached(child));
        assert!(!session.all_exited());
        session
            .handle(&Input::Exited { pid: 777 }, &mut src, &mut Discard)
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
