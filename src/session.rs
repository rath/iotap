//! The deterministic core: turns reader input into I/O events, notices and statistics.
//!
//! A session depends only on its input and on the answers of its [`ProcSource`], never on
//! wall-clock time, so a recording replays to the same output.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::{Category, IoEvent, Op, Provenance, ResultUnit, Target};
use crate::stats::{Stats, SummaryRow, Totals};
use crate::sys::kdebug::KdBuf;
use crate::sys::time::{ClockAnchor, Timebase};
use crate::trace::codes::Role;
use crate::trace::decode::{Kind, decode};
use crate::trace::fdtable::FdTable;
use crate::trace::pairing::{Completed, Pairer};
use crate::trace::procs::ProcSource;

/// A traced process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: i32,
    pub name: String,
}

/// Facts fixed when tracing starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub timebase: Timebase,
    /// Read before tracing was enabled.
    pub anchor: ClockAnchor,
    pub processes: Vec<Process>,
}

/// What the kernel reader delivers, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Records(Vec<KdBuf>),
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
    Exited {
        pid: i32,
    },
}

/// Receives what a session produces.
pub trait Sink {
    fn event(&mut self, event: &IoEvent) -> io::Result<()>;
    fn notice(&mut self, notice: &Notice) -> io::Result<()>;
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

#[derive(Debug)]
pub struct Session {
    info: SessionInfo,
    filter: Filter,
    pairer: Pairer,
    fds: FdTable,
    stats: Stats,
    processes: BTreeMap<i32, ProcessState>,
    lost_events: u64,
    last_ticks: u64,
    stopped_ticks: Option<u64>,
    unknown: Arc<Target>,
}

impl Session {
    /// Starts a session and loads the descriptor tables of the initial processes.
    pub fn new(info: SessionInfo, filter: Filter, src: &mut dyn ProcSource) -> Self {
        let retry_ticks = info.timebase.nanos_to_ticks(1_000_000_000);
        let mut session = Self {
            filter,
            pairer: Pairer::default(),
            fds: FdTable::new(retry_ticks),
            stats: Stats::default(),
            processes: BTreeMap::new(),
            lost_events: 0,
            last_ticks: info.anchor.ticks,
            stopped_ticks: None,
            unknown: Arc::new(Target::Unknown),
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

    /// Name of a traced process.
    pub fn process_name(&self, pid: i32) -> Option<&str> {
        self.processes.get(&pid).map(|p| p.name.as_str())
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
            Input::Records(records) => {
                for record in records {
                    self.record(record, src, sink)?;
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
                sink.notice(&Notice::Attached(process.clone()))?;
            }
            Input::Exec { pid, path } => {
                if let Some(name) = path.rsplit('/').next().filter(|n| !n.is_empty())
                    && let Some(state) = self.processes.get_mut(pid)
                {
                    name.clone_into(&mut state.name);
                }
                self.fds.attach(*pid, src);
                sink.notice(&Notice::Exec {
                    pid: *pid,
                    path: path.clone(),
                })?;
            }
            Input::Exited { pid } => self.exited(*pid, sink)?,
            Input::Stopped { ticks } => {
                self.stopped_ticks = Some((*ticks).max(self.last_ticks));
            }
        }
        Ok(())
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
            unfinished_calls: self.pairer.orphan_starts(),
            calls_started_before_trace: self.pairer.orphan_ends(),
            files: self.stats.summary_rows(Category::File),
            network: self.stats.summary_rows(Category::Network),
            other: self.stats.summary_rows(Category::Other),
        }
    }

    fn record(&mut self, record: &KdBuf, src: &mut dyn ProcSource, sink: &mut dyn Sink) -> io::Result<()> {
        let Some(event) = decode(record) else {
            return Ok(());
        };
        self.last_ticks = self.last_ticks.max(event.ts);
        match event.kind {
            Kind::LostEvents => {
                self.lost_events += 1;
                self.pairer.clear();
                let alive: Vec<i32> = self
                    .processes
                    .iter()
                    .filter(|(_, p)| p.alive)
                    .map(|(&pid, _)| pid)
                    .collect();
                for pid in alive {
                    self.fds.attach(pid, src);
                }
                sink.notice(&Notice::LostEvents {
                    time_ns: self.unix_ns(event.ts),
                })
            }
            Kind::ProcExit { pid } => self.exited(pid, sink),
            Kind::Syscall(_) | Kind::Lookup => match self.pairer.push(&event) {
                Some(done) => self.completed(&done, src, sink),
                None => Ok(()),
            },
        }
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
        let event = self.io_event(done, op, fd_arg, len_arg, src);
        if !self.filter.accepts(event.target.category()) {
            return Ok(());
        }
        self.stats.record(&event);
        sink.event(&event)
    }

    fn io_event(
        &mut self,
        done: &Completed,
        op: Op,
        fd_arg: usize,
        len_arg: Option<usize>,
        src: &mut dyn ProcSource,
    ) -> IoEvent {
        let fd = done.arg_i32(fd_arg);
        let (target, provenance) = match fd {
            Some(fd) => self.fds.target(done.pid, fd, done.end_ts, src),
            None => (self.unknown.clone(), Provenance::None),
        };
        let unit = op.result_unit();
        let ret = done.is_ok().then(|| done.ret_u64());
        IoEvent {
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
        }
    }

    fn exited(&mut self, pid: i32, sink: &mut dyn Sink) -> io::Result<()> {
        match self.processes.get_mut(&pid) {
            Some(state) if state.alive => {
                state.alive = false;
                self.fds.detach(pid);
                sink.notice(&Notice::Exited { pid })
            }
            _ => Ok(()),
        }
    }

    fn unix_ns(&self, ticks: u64) -> u64 {
        self.info.anchor.unix_nanos_at(self.info.timebase, ticks)
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
    use crate::trace::procs::{Fixed, Snapshot};
    use crate::trace::synth::{Call, Synth};

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
            .handle(&Input::Records(records), &mut src, &mut sink)
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
            .handle(&Input::Records(records), &mut src, &mut sink)
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
    }

    #[test]
    fn process_exit_is_reported_once() {
        let mut src = procs();
        let mut session = Session::new(info(), Filter::ALL, &mut src);
        let mut synth = Synth::new(2_000, 10);
        let mut sink = Collect::default();
        session
            .handle(
                &Input::Records(vec![synth.proc_exit(7, PID, 0)]),
                &mut src,
                &mut sink,
            )
            .unwrap();
        session
            .handle(&Input::Exited { pid: PID }, &mut src, &mut sink)
            .unwrap();
        assert_eq!(sink.notices, [Notice::Exited { pid: PID }]);
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
            .handle(&Input::Records(synth.io(7, PID, 4, 1, 5, 5)), &mut src, &mut sink)
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
    }
}
