//! Joins syscall START and END records per thread and collects the path looked up in between.
//!
//! A thread is inside at most one BSD syscall at a time, and the kernel merges its per-CPU
//! buffers in timestamp order, so the records of one thread arrive in order.

use std::collections::HashMap;

use super::codes::Syscall;
use super::decode::{Event, Kind, Phase, low_i32};

/// Most path bytes one lookup reports. XNU's `kdebug_lookup` copies at most `NUMPARMS` (23)
/// words and keeps the end of a longer path.
pub const KERNEL_PATH_BYTES: usize = 23 * 8;
/// Bound on the bytes gathered for one lookup, in case its END record is lost.
const MAX_PATH_BYTES: usize = 1024;
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
    /// The first path looked up during the call.
    pub lookup: Option<Lookup>,
}

/// A path as the kernel reports a name lookup: once, when the lookup is complete.
///
/// Following a symbolic link replaces the path with the link's text followed by the rest of
/// the path. So the reported path is what the process passed only when no link was followed.
/// After a link with a relative target, it is relative to the directory holding that link:
/// `/etc/hosts` is reported as `private/etc/hosts`, because `/etc` links to `private/etc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub path: String,
    /// Only the last [`KERNEL_PATH_BYTES`] bytes were reported. A path of exactly that length
    /// looks the same, so it counts as truncated too.
    pub truncated: bool,
}

impl Lookup {
    /// Absolute, and reported whole.
    pub fn is_absolute(&self) -> bool {
        !self.truncated && self.path.starts_with('/')
    }

    /// Parses the bytes of one lookup's records. The kernel pads the path to the end of its
    /// last record with NUL bytes, or with `>` when the name goes on past the part looked up.
    fn parse(bytes: &[u8]) -> Option<Self> {
        let (path, truncated) = if let Some(len) = bytes.iter().position(|&b| b == 0) {
            (&bytes[..len], false)
        } else {
            let len = bytes.iter().rposition(|&b| b != b'>').map_or(0, |last| last + 1);
            (&bytes[..len], len == KERNEL_PATH_BYTES)
        };
        (!path.is_empty()).then(|| Self {
            path: String::from_utf8_lossy(path).into_owned(),
            truncated,
        })
    }
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
    lookup: Option<Lookup>,
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
            lookup: None,
            partial: None,
        };
        if self.pending.insert(event.tid, pending).is_some() {
            self.orphan_starts += 1;
        }
    }

    fn end(&mut self, call: Syscall, event: &Event) -> Completed {
        let (start, lookup) = match self.pending.remove(&event.tid) {
            Some(open) if open.call.number == call.number => (Some((open.ts, open.args)), open.lookup),
            Some(_) => {
                self.orphan_starts += 1;
                self.orphan_ends += 1;
                (None, None)
            }
            None => {
                self.orphan_ends += 1;
                (None, None)
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
            lookup,
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
            && open.lookup.is_none()
        {
            open.lookup = Lookup::parse(&bytes);
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
        assert!(read.lookup.is_none());
    }

    fn lookup(path: &str, truncated: bool) -> Lookup {
        Lookup {
            path: path.to_owned(),
            truncated,
        }
    }

    #[test]
    fn reassembles_paths_of_every_length() {
        let mut pairer = Pairer::default();
        for len in [1, 23, 24, 25, 56, 57, 183] {
            let path = format!("/{}", "p".repeat(len - 1));
            let mut synth = Synth::new(0, 1);
            let done = run(&mut pairer, &synth.open(1, 2, &path, 3));
            assert_eq!(done[0].lookup, Some(lookup(&path, false)), "len {len}");
            assert_eq!(done[0].ret_i32(), 3);
        }
    }

    #[test]
    fn long_paths_keep_their_end_and_are_marked() {
        let mut pairer = Pairer::default();
        let mut synth = Synth::new(0, 1);
        let path = format!("/Users/me/{}/data.db", "deep/".repeat(60));
        let done = run(&mut pairer, &synth.open(1, 2, &path, 3));
        assert_eq!(
            done[0].lookup,
            Some(lookup(&path[path.len() - KERNEL_PATH_BYTES..], true))
        );
        // Exactly the limit is indistinguishable from a longer path.
        let exact = format!("/{}", "e".repeat(KERNEL_PATH_BYTES - 1));
        let done = run(&mut pairer, &synth.open(1, 2, &exact, 3));
        assert_eq!(done[0].lookup, Some(lookup(&exact, true)));
    }

    #[test]
    fn strips_padding_after_the_name() {
        let mut pairer = Pairer::default();
        let mut synth = Synth::new(0, 1);
        let mut records = vec![synth.syscall_start(1, 5, [0; 4])];
        records.extend(synth.lookup_bytes(1, b"sub", b'>'));
        records.push(synth.syscall_end(1, 5, 2, 0, [3, 0]));
        assert_eq!(run(&mut pairer, &records)[0].lookup, Some(lookup("sub", false)));
        // A path that ends on a record boundary has no padding at all.
        let aligned = "a".repeat(56);
        let done = run(&mut pairer, &synth.open(1, 2, &aligned, 3));
        assert_eq!(done[0].lookup, Some(lookup(&aligned, false)));
    }

    #[test]
    fn keeps_the_first_lookup_of_a_call() {
        let mut synth = Synth::new(0, 1);
        let mut pairer = Pairer::default();
        let records = synth.call(Call {
            paths: &["private/etc/hosts", "/elsewhere"],
            ret: 4,
            ..Call::new(1, 2, 5, [0; 4])
        });
        let done = run(&mut pairer, &records);
        assert_eq!(done[0].lookup, Some(lookup("private/etc/hosts", false)));
        assert!(!done[0].lookup.as_ref().unwrap().is_absolute());
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
        assert!(done[0].lookup.is_none());
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
