//! Joins syscall START and END records per thread and collects the paths looked up in between.
//!
//! A thread is inside at most one BSD syscall at a time, and the kernel merges its per-CPU
//! buffers in timestamp order, so the records of one thread arrive in order.

use std::collections::HashMap;

use super::codes::Syscall;
use super::decode::{Event, Kind, Phase, low_i32};

/// Longest path the kernel reports (`MAXPATHLEN`).
const MAX_PATH_BYTES: usize = 1024;
/// Lookups kept per call; following symlinks repeats the lookup with the resolved path.
const MAX_PATHS: usize = 4;
/// Bound on threads with an open call, so threads that die mid-call cannot grow the map.
const MAX_PENDING: usize = 1 << 16;

/// A syscall whose END record was seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    pub call: Syscall,
    pub tid: u64,
    pub pid: i32,
    /// Entry timestamp and the first four arguments; `None` when the call began before tracing
    /// did or its START record was lost.
    pub start: Option<(u64, [u64; 4])>,
    pub end_ts: u64,
    /// 0 on success.
    pub errno: i32,
    /// `uu_rval[0]` and `uu_rval[1]`.
    pub rval: [u32; 2],
    /// Paths looked up during the call, in order.
    pub paths: Vec<String>,
}

impl Completed {
    pub fn is_ok(&self) -> bool {
        self.errno == 0
    }

    /// Return value of a call that returns a descriptor or an `int`.
    pub fn ret_i32(&self) -> i32 {
        self.rval[0].cast_signed()
    }

    /// Return value of a call that returns `ssize_t`; the kernel stores it across both slots.
    pub fn ret_u64(&self) -> u64 {
        (u64::from(self.rval[1]) << 32) | u64::from(self.rval[0])
    }

    pub fn arg(&self, index: usize) -> Option<u64> {
        self.start.map(|(_, args)| args[index])
    }

    /// Argument `index` read as a C `int`, such as a descriptor.
    pub fn arg_i32(&self, index: usize) -> Option<i32> {
        self.arg(index).map(low_i32)
    }

    pub fn start_ts(&self) -> Option<u64> {
        self.start.map(|(ts, _)| ts)
    }

    pub fn latency_ticks(&self) -> Option<u64> {
        self.start_ts().map(|ts| self.end_ts.saturating_sub(ts))
    }
}

#[derive(Debug)]
struct Pending {
    call: Syscall,
    ts: u64,
    args: [u64; 4],
    paths: Vec<String>,
    partial: Option<Vec<u8>>,
}

/// Pairs START and END records per thread.
#[derive(Debug, Default)]
pub struct Pairer {
    pending: HashMap<u64, Pending>,
    orphan_starts: u64,
    orphan_ends: u64,
}

impl Pairer {
    /// Feeds one event; returns the completed call when `event` ends one.
    pub fn push(&mut self, event: &Event) -> Option<Completed> {
        match event.kind {
            Kind::Syscall(call) => match event.phase {
                Phase::Start => {
                    self.start(call, event);
                    None
                }
                Phase::End => Some(self.end(call, event)),
                Phase::StartEnd | Phase::Point => None,
            },
            Kind::Lookup => {
                self.lookup(event);
                None
            }
            Kind::ProcExit { .. } | Kind::LostEvents => None,
        }
    }

    /// Forgets every open call, after records were lost.
    pub fn clear(&mut self) {
        self.orphan_starts += self.pending.len() as u64;
        self.pending.clear();
    }

    /// Calls whose END was never seen, including those still open.
    pub fn orphan_starts(&self) -> u64 {
        self.orphan_starts + self.pending.len() as u64
    }

    /// END records whose START was never seen.
    pub fn orphan_ends(&self) -> u64 {
        self.orphan_ends
    }

    fn start(&mut self, call: Syscall, event: &Event) {
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&event.tid) {
            self.evict_oldest_half();
        }
        let pending = Pending {
            call,
            ts: event.ts,
            args: event.args,
            paths: Vec::new(),
            partial: None,
        };
        if self.pending.insert(event.tid, pending).is_some() {
            self.orphan_starts += 1;
        }
    }

    fn end(&mut self, call: Syscall, event: &Event) -> Completed {
        let (start, paths) = match self.pending.remove(&event.tid) {
            Some(open) if open.call.number == call.number => (Some((open.ts, open.args)), open.paths),
            Some(_) => {
                self.orphan_starts += 1;
                self.orphan_ends += 1;
                (None, Vec::new())
            }
            None => {
                self.orphan_ends += 1;
                (None, Vec::new())
            }
        };
        Completed {
            call,
            tid: event.tid,
            pid: low_i32(event.args[3]),
            start,
            end_ts: event.ts,
            errno: low_i32(event.args[0]),
            rval: [event.args[1] as u32, event.args[2] as u32],
            paths,
        }
    }

    fn lookup(&mut self, event: &Event) {
        let Some(open) = self.pending.get_mut(&event.tid) else {
            return;
        };
        if !open.call.role.takes_path() {
            return;
        }
        // The first record carries the vnode in arg1 and path bytes in arg2..arg4.
        let words = if event.phase.is_start() {
            open.partial = Some(Vec::with_capacity(64));
            &event.args[1..]
        } else {
            &event.args[..]
        };
        let Some(bytes) = open.partial.as_mut() else {
            return;
        };
        for word in words {
            if bytes.len() < MAX_PATH_BYTES {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        if event.phase.is_end()
            && let Some(bytes) = open.partial.take()
        {
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            if len > 0 && open.paths.len() < MAX_PATHS {
                open.paths
                    .push(String::from_utf8_lossy(&bytes[..len]).into_owned());
            }
        }
    }

    fn evict_oldest_half(&mut self) {
        let mut starts: Vec<u64> = self.pending.values().map(|p| p.ts).collect();
        starts.sort_unstable();
        let cutoff = starts[starts.len() / 2];
        let before = self.pending.len();
        self.pending.retain(|_, p| p.ts > cutoff);
        self.orphan_starts += (before - self.pending.len()) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::kdebug::KdBuf;
    use crate::trace::decode::decode;
    use crate::trace::synth::{Call, Synth};

    fn run(pairer: &mut Pairer, records: &[KdBuf]) -> Vec<Completed> {
        records
            .iter()
            .filter_map(decode)
            .filter_map(|e| pairer.push(&e))
            .collect()
    }

    #[test]
    fn pairs_a_read() {
        let mut synth = Synth::new(1_000, 10);
        let mut pairer = Pairer::default();
        let done = run(&mut pairer, &synth.io(5, 77, 3, 7, 4096, 812));
        assert_eq!(done.len(), 1);
        let read = &done[0];
        assert_eq!((read.pid, read.tid, read.errno), (77, 5, 0));
        assert_eq!(read.arg_i32(0), Some(7));
        assert_eq!(read.arg(2), Some(4096));
        assert_eq!(read.ret_u64(), 812);
        assert_eq!(read.latency_ticks(), Some(10));
        assert!(read.paths.is_empty());
    }

    #[test]
    fn reassembles_paths_of_every_length() {
        let mut pairer = Pairer::default();
        for path in [
            "/a",
            &"/x".repeat(12),
            &format!("/{}", "y".repeat(24)),
            &"/z".repeat(300),
        ] {
            let mut synth = Synth::new(0, 1);
            let done = run(&mut pairer, &synth.open(1, 2, path, 3));
            assert_eq!(done[0].paths, vec![path.to_owned()], "len {}", path.len());
            assert_eq!(done[0].ret_i32(), 3);
        }
    }

    #[test]
    fn keeps_every_lookup_of_a_symlinked_open() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        let records = synth.call(Call {
            paths: &["/tmp/link", "/private/tmp/target"],
            ret: 4,
            ..Call::new(1, 2, 5, [0; 4])
        });
        let done = run(&mut pairer, &records);
        assert_eq!(done[0].paths, ["/tmp/link", "/private/tmp/target"]);
    }

    #[test]
    fn ignores_lookups_outside_tracked_calls() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        let mut records = synth.lookup(1, "/etc/hosts");
        // A read does not take a path; its lookups (none in practice) must not leak into it.
        records.extend(synth.io(1, 2, 3, 7, 10, 10));
        let done = run(&mut pairer, &records);
        assert_eq!(done.len(), 1);
        assert!(done[0].paths.is_empty());
    }

    #[test]
    fn interleaved_threads_stay_separate() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        let records = vec![
            synth.syscall_start(1, 3, [7, 0, 100, 0]),
            synth.syscall_start(2, 4, [8, 0, 200, 0]),
            synth.syscall_end(2, 4, 50, 0, [200, 0]),
            synth.syscall_end(1, 3, 50, 0, [100, 0]),
        ];
        let done = run(&mut pairer, &records);
        assert_eq!(done.len(), 2);
        assert_eq!((done[0].tid, done[0].arg_i32(0)), (2, Some(8)));
        assert_eq!((done[1].tid, done[1].arg_i32(0)), (1, Some(7)));
    }

    #[test]
    fn reports_orphans() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        // END of a call that began before tracing.
        let done = run(&mut pairer, &[synth.syscall_end(1, 3, 9, 0, [64, 0])]);
        assert_eq!(done[0].start, None);
        assert_eq!(done[0].ret_u64(), 64);
        assert_eq!(pairer.orphan_ends(), 1);
        // A START whose END is lost, then a new START on the same thread.
        run(&mut pairer, &[synth.syscall_start(1, 3, [7, 0, 1, 0])]);
        run(&mut pairer, &[synth.syscall_start(1, 4, [7, 0, 1, 0])]);
        assert_eq!(pairer.orphan_starts(), 2, "one replaced, one still open");
        pairer.clear();
        assert_eq!(pairer.orphan_starts(), 2);
        assert!(
            run(&mut pairer, &[synth.syscall_end(1, 4, 9, 0, [1, 0])])[0]
                .start
                .is_none()
        );
    }

    #[test]
    fn combines_both_return_slots_and_errno() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        let big = run(&mut pairer, &synth.io(1, 2, 3, 7, 1 << 33, (1 << 32) + 5));
        assert_eq!(big[0].ret_u64(), (1 << 32) + 5);
        let failed = run(
            &mut pairer,
            &synth.call(Call {
                errno: libc::EAGAIN,
                ..Call::new(1, 2, 3, [7, 0, 16, 0])
            }),
        );
        assert_eq!(failed[0].errno, libc::EAGAIN);
        assert!(!failed[0].is_ok());
    }

    #[test]
    fn evicts_when_too_many_threads_are_open() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        for tid in 0..=(MAX_PENDING as u64) {
            pairer.push(&decode(&synth.syscall_start(tid, 3, [0; 4])).unwrap());
        }
        assert!(pairer.pending.len() <= MAX_PENDING / 2 + 1);
        assert_eq!(pairer.orphan_starts(), MAX_PENDING as u64 + 1);
    }
}
