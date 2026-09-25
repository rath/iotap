//! Finds, in kdebug records, the processes that traced ones start and the processes that run
//! exec, so that the facility can trace a child, and trace a process again after exec, as soon
//! as a read shows them.
//!
//! The kernel records only the calls of the processes iotap flags, and a flag is not handed
//! down: a child starts without it, and exec moves a process to a new kernel proc without it.
//! Records about threads and exec, though, the kernel makes for every process, flagged or not:
//! one when a thread is created, made by the thread that creates it, and one when a process
//! runs exec. A new process shows as a thread created for another process than its creator's,
//! by a thread of a traced process inside a call that starts processes, whose start the kernel
//! recorded because that process is flagged, or by a thread of a process found this way, which
//! may not be flagged yet.

use std::collections::{HashMap, HashSet};

use super::KdBuf;
use super::codes::{self, FUNC_END, FUNC_START};
use crate::trace::call::low_i32;

/// Bound on the threads remembered, in case the records of their ends are lost.
const MAX_THREADS: usize = 1 << 16;

/// What the records of one read show.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Processes started, in order: the traced one that started it, when the records say, and
    /// the new one.
    pub started: Vec<(Option<i32>, i32)>,
    /// Processes that ran exec, in order, each once.
    pub execed: Vec<i32>,
}

/// Follows the records of threads, and of the calls that start processes, across reads.
#[derive(Debug, Default)]
pub struct Spawns {
    /// Threads inside a call that starts processes.
    starting: HashSet<u64>,
    /// Threads of the processes found started, and of the traced ones that started them, by
    /// the process they belong to.
    threads: HashMap<u64, i32>,
}

impl Spawns {
    /// Reads the records of one read, in order.
    pub fn scan(&mut self, records: &[KdBuf]) -> Found {
        let mut found = Found::default();
        // Processes found started in this read, by the thread inside the call that started
        // them, until the call's end names its process.
        let mut unnamed: HashMap<u64, usize> = HashMap::new();
        for record in records {
            let id = codes::event_id(record.debugid);
            if let Some(number) = codes::syscall_number(id)
                && codes::STARTS_PROCESSES.contains(&number)
            {
                let tid = record.arg5;
                match codes::func(record.debugid) {
                    FUNC_START => {
                        self.starting.insert(tid);
                    }
                    FUNC_END => {
                        self.starting.remove(&tid);
                        let pid = low_i32(record.arg4);
                        self.remember(tid, pid);
                        if let Some(index) = unnamed.remove(&tid) {
                            found.started[index].0 = Some(pid);
                        }
                    }
                    _ => {}
                }
            } else if id == codes::TRACE_DATA_NEWTHREAD {
                self.new_thread(record, &mut found, &mut unnamed);
            } else if id == codes::TRACE_DATA_EXEC {
                let pid = low_i32(record.arg1);
                if !found.execed.contains(&pid) {
                    found.execed.push(pid);
                }
            } else if id == codes::TRACE_DATA_THREAD_TERMINATE {
                self.threads.remove(&record.arg1);
                self.starting.remove(&record.arg1);
            } else if id == codes::TRACE_LOST_EVENTS {
                // The ends of the calls under way may be among the records lost.
                self.starting.clear();
            }
        }
        found
    }

    /// Reads the record of a thread's creation.
    fn new_thread(&mut self, record: &KdBuf, found: &mut Found, unnamed: &mut HashMap<u64, usize>) {
        let (creator, tid, pid) = (record.arg5, record.arg1, low_i32(record.arg2));
        // The thread of the new image an exec creates belongs to the process that ran it.
        let exec = record.arg3 != 0;
        if pid <= 0 {
            return;
        }
        if let Some(&owner) = self.threads.get(&creator) {
            if pid != owner && !exec {
                found.started.push((Some(owner), pid));
            }
            self.remember(tid, pid);
        } else if self.starting.contains(&creator) && !exec {
            unnamed.insert(creator, found.started.len());
            found.started.push((None, pid));
            self.remember(tid, pid);
        }
    }

    fn remember(&mut self, tid: u64, pid: i32) {
        if self.threads.len() >= MAX_THREADS && !self.threads.contains_key(&tid) {
            // Threads whose ends were lost; the processes found from now on are what matters.
            self.threads.clear();
        }
        self.threads.insert(tid, pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::kdebug::synth::Synth;

    const PARENT: i32 = 500;

    #[test]
    fn finds_a_child_started_by_a_traced_process() {
        let mut synth = Synth::new(0, 1);
        let mut spawns = Spawns::default();
        // posix_spawn by thread 7 of the traced process: the child's first thread is 70.
        let records = synth.spawn(7, PARENT, 70, 501);
        let found = spawns.scan(&records);
        assert_eq!(found.started, [(Some(PARENT), 501)]);
        assert_eq!(found.execed, [501], "posix_spawn runs exec in the child");
        // A call cut in two by a read names the parent only when it ends.
        let (first, second) = records.split_at(2);
        let mut spawns = Spawns::default();
        assert_eq!(spawns.scan(first).started, [(None, 501)]);
        assert!(spawns.scan(second).started.is_empty());
    }

    #[test]
    fn finds_the_children_of_children_not_flagged_yet() {
        let mut synth = Synth::new(0, 1);
        let mut spawns = Spawns::default();
        let mut records = synth.spawn(7, PARENT, 70, 501);
        // The child, whose calls are not recorded yet, starts a thread and then a process from
        // that thread; another process starts one too, which is not a relative.
        records.push(synth.new_thread(70, 71, 501, false));
        records.push(synth.new_thread(71, 80, 502, false));
        records.push(synth.new_thread(99, 90, 600, false));
        let found = spawns.scan(&records);
        assert_eq!(found.started, [(Some(PARENT), 501), (Some(501), 502)]);
    }

    #[test]
    fn exec_and_threads_of_the_same_process_start_nothing() {
        let mut synth = Synth::new(0, 1);
        let mut spawns = Spawns::default();
        let mut records = synth.spawn(7, PARENT, 70, 501);
        // The child runs exec, which creates the thread of its new image, and a thread of
        // its own.
        records.push(synth.new_thread(70, 72, 501, true));
        records.push(synth.exec(72, 501));
        records.push(synth.new_thread(72, 73, 501, false));
        // A thread of a traced process creates a thread outside any call that starts one.
        records.push(synth.new_thread(8, 81, PARENT, false));
        let found = spawns.scan(&records);
        assert_eq!(found.started, [(Some(PARENT), 501)]);
        assert_eq!(found.execed, [501]);
    }

    #[test]
    fn forgets_calls_whose_ends_are_lost_and_threads_that_ended() {
        let mut synth = Synth::new(0, 1);
        let mut spawns = Spawns::default();
        // A fork's end is lost; a thread the same thread creates later is no child.
        let start = synth.syscall_start(7, 2, [0; 4]);
        spawns.scan(&[start, synth.lost_events()]);
        assert!(
            spawns
                .scan(&[synth.new_thread(7, 71, PARENT, false)])
                .started
                .is_empty()
        );
        // The first thread of a child ends; a thread given its id later is someone else's.
        let records = synth.spawn(8, PARENT, 80, 501);
        spawns.scan(&records);
        let ended = synth.thread_terminate(80);
        let found = spawns.scan(&[ended, synth.new_thread(80, 81, 777, false)]);
        assert!(found.started.is_empty(), "{found:?}");
    }
}
