//! Builds kernel trace records exactly as XNU emits them, so tests and fixtures can exercise the
//! whole pipeline without root.

use super::KdBuf;
use super::codes::{self, FUNC_END, FUNC_START};
use super::pairing::{PathRecords, TAIL_PATH_BYTES};

/// Emits records with strictly increasing timestamps.
#[derive(Debug)]
pub struct Synth {
    ts: u64,
    step: u64,
    /// Vnode found by the most recent lookup of a new file.
    vnode: u64,
    /// Vnode the next lookup finds instead of a new one.
    same_file: Option<u64>,
    paths: PathRecords,
}

impl Synth {
    /// Records start after `start_ts` and are `step` ticks apart. Paths are laid out as a
    /// current kernel does.
    pub fn new(start_ts: u64, step: u64) -> Self {
        Self {
            ts: start_ts,
            step: step.max(1),
            vnode: 0xfeed_0000,
            same_file: None,
            paths: PathRecords::Whole,
        }
    }

    /// Lays out lookup paths as a kernel using `paths` does.
    #[must_use]
    pub fn with_path_records(mut self, paths: PathRecords) -> Self {
        self.paths = paths;
        self
    }

    /// Timestamp of the most recent record.
    pub fn now(&self) -> u64 {
        self.ts
    }

    /// Leaves a gap of `ticks` before the next record.
    pub fn advance(&mut self, ticks: u64) {
        self.ts += ticks;
    }

    /// Makes the next lookup find `vnode`, as another lookup of the same file does. Later
    /// lookups find new files again.
    pub fn find_vnode(&mut self, vnode: u64) {
        self.same_file = Some(vnode);
    }

    fn record(&mut self, tid: u64, debugid: u32, args: [u64; 4]) -> KdBuf {
        self.ts += self.step;
        KdBuf {
            timestamp: self.ts,
            arg1: args[0],
            arg2: args[1],
            arg3: args[2],
            arg4: args[3],
            arg5: tid,
            debugid,
            cpuid: 0,
            unused: 0,
        }
    }

    /// Syscall entry: the first four argument registers.
    pub fn syscall_start(&mut self, tid: u64, number: u16, args: [u64; 4]) -> KdBuf {
        self.record(tid, codes::syscall_debugid(number, FUNC_START), args)
    }

    /// Syscall exit: `error, uu_rval[0], uu_rval[1], pid`, each a C `int` widened to 64 bits.
    pub fn syscall_end(&mut self, tid: u64, number: u16, pid: i32, errno: i32, rval: [u32; 2]) -> KdBuf {
        let widen = |v: i32| i64::from(v).cast_unsigned();
        let args = [
            widen(errno),
            widen(rval[0].cast_signed()),
            widen(rval[1].cast_signed()),
            widen(pid),
        ];
        self.record(tid, codes::syscall_debugid(number, FUNC_END), args)
    }

    /// Records of one completed path lookup as `kdebug_lookup` emits them: the whole path, or
    /// in the older format its last [`TAIL_PATH_BYTES`] bytes, padded with NUL bytes.
    pub fn lookup(&mut self, tid: u64, path: &str) -> Vec<KdBuf> {
        let bytes = path.as_bytes();
        let kept = match self.paths {
            PathRecords::Whole => bytes,
            PathRecords::Tail => &bytes[bytes.len().saturating_sub(TAIL_PATH_BYTES)..],
        };
        self.lookup_bytes(tid, kept, 0)
    }

    /// Records carrying `bytes` and then `pad`, split as `kdebug_vfs_lookup` does: 24 bytes
    /// after the vnode in the first record, then 32 bytes per record, END set on the last.
    pub fn lookup_bytes(&mut self, tid: u64, bytes: &[u8], pad: u8) -> Vec<KdBuf> {
        let word = |index: usize| {
            let mut buf = [pad; 8];
            let start = (index * 8).min(bytes.len());
            let end = (index * 8 + 8).min(bytes.len());
            buf[..end - start].copy_from_slice(&bytes[start..end]);
            u64::from_le_bytes(buf)
        };
        let vnode = self.same_file.take().unwrap_or_else(|| {
            self.vnode += 0x10;
            self.vnode
        });
        let mut out = Vec::new();
        let mut func = FUNC_START;
        if bytes.len() <= 24 {
            func |= FUNC_END;
        }
        out.push(self.record(tid, codes::VFS_LOOKUP | func, [vnode, word(0), word(1), word(2)]));
        let mut index = 3;
        while index * 8 < bytes.len() {
            let func = if (index + 4) * 8 >= bytes.len() {
                FUNC_END
            } else {
                0
            };
            let args = [word(index), word(index + 1), word(index + 2), word(index + 3)];
            out.push(self.record(tid, codes::VFS_LOOKUP | func, args));
            index += 4;
        }
        out
    }

    pub fn proc_exit(&mut self, tid: u64, pid: i32, status: i32) -> KdBuf {
        let args = [
            i64::from(pid).cast_unsigned(),
            i64::from(status).cast_unsigned(),
            0,
            0,
        ];
        self.record(tid, codes::BSD_PROC_EXIT | FUNC_START, args)
    }

    pub fn lost_events(&mut self) -> KdBuf {
        self.record(0, codes::TRACE_LOST_EVENTS, [1, 0, 0, 0])
    }

    /// Thread `creator` created thread `tid` of process `pid`; `exec` marks the thread of the
    /// new image that exec creates.
    pub fn new_thread(&mut self, creator: u64, tid: u64, pid: i32, exec: bool) -> KdBuf {
        let args = [tid, i64::from(pid).cast_unsigned(), u64::from(exec), 0];
        self.record(creator, codes::TRACE_DATA_NEWTHREAD, args)
    }

    /// Process `pid` ran exec, on thread `tid`.
    pub fn exec(&mut self, tid: u64, pid: i32) -> KdBuf {
        self.record(
            tid,
            codes::TRACE_DATA_EXEC,
            [i64::from(pid).cast_unsigned(), 0, 0, 0],
        )
    }

    /// Thread `tid` ended.
    pub fn thread_terminate(&mut self, tid: u64) -> KdBuf {
        self.record(tid, codes::TRACE_DATA_THREAD_TERMINATE, [tid, 0, 0, 0])
    }

    /// Thread `tid` of process `parent` starts process `child`, whose first thread is
    /// `child_tid`, with `posix_spawn`, which runs exec in the child before it returns.
    pub fn spawn(&mut self, tid: u64, parent: i32, child_tid: u64, child: i32) -> Vec<KdBuf> {
        let number = codes::STARTS_PROCESSES[2];
        vec![
            self.syscall_start(tid, number, [0x1_6f00_0000, 0x1_0000_4000, 0, 0]),
            self.new_thread(tid, child_tid, child, false),
            self.exec(tid, child),
            self.syscall_end(tid, number, parent, 0, [0, 0]),
        ]
    }

    /// A complete syscall returning `ret`, with `paths` looked up in between.
    pub fn call(&mut self, call: Call<'_>) -> Vec<KdBuf> {
        let mut out = vec![self.syscall_start(call.tid, call.number, call.args)];
        for path in call.paths {
            out.extend(self.lookup(call.tid, path));
        }
        let rval = [call.ret as u32, (call.ret >> 32) as u32];
        out.push(self.syscall_end(call.tid, call.number, call.pid, call.errno, rval));
        out
    }

    /// `open(path)` returning `fd`.
    pub fn open(&mut self, tid: u64, pid: i32, path: &str, fd: i32) -> Vec<KdBuf> {
        self.call(Call {
            paths: &[path],
            ret: u64::from(fd.cast_unsigned()),
            ..Call::new(tid, pid, 5, [0, 0x0100_0000, 0o644, 0])
        })
    }

    /// Data transfer on `fd` through syscall `number` with the size in the third argument.
    pub fn io(&mut self, tid: u64, pid: i32, number: u16, fd: i32, len: u64, ret: u64) -> Vec<KdBuf> {
        let fd = u64::from(fd.cast_unsigned());
        self.call(Call {
            ret,
            ..Call::new(tid, pid, number, [fd, 0x1_6f00_0000, len, 0])
        })
    }

    /// `close(fd)`.
    pub fn close(&mut self, tid: u64, pid: i32, fd: i32) -> Vec<KdBuf> {
        self.call(Call::new(tid, pid, 6, [u64::from(fd.cast_unsigned()), 0, 0, 0]))
    }
}

/// Parameters of [`Synth::call`].
#[derive(Clone, Copy, Debug)]
pub struct Call<'a> {
    pub tid: u64,
    pub pid: i32,
    pub number: u16,
    pub args: [u64; 4],
    pub paths: &'a [&'a str],
    pub errno: i32,
    pub ret: u64,
}

impl Call<'_> {
    /// A successful call with no lookups and a zero return value.
    pub fn new(tid: u64, pid: i32, number: u16, args: [u64; 4]) -> Self {
        Self {
            tid,
            pid,
            number,
            args,
            paths: &[],
            errno: 0,
            ret: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_path_is_one_record_with_both_bits() {
        let mut synth = Synth::new(0, 1);
        let recs = synth.lookup(9, "/etc/hosts");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].debugid, codes::VFS_LOOKUP | FUNC_START | FUNC_END);
        assert_eq!(recs[0].arg2.to_le_bytes(), *b"/etc/hos");
    }

    #[test]
    fn long_path_splits_like_the_kernel() {
        let mut synth = Synth::new(0, 1);
        // 25 bytes: 24 in the first record, 1 in a second record that carries END.
        let recs = synth.lookup(9, "/0123456789/0123456789/ab");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].debugid, codes::VFS_LOOKUP | FUNC_START);
        assert_eq!(recs[1].debugid, codes::VFS_LOOKUP | FUNC_END);
        // 24 + 32 = 56 bytes fit in two records; 57 need three.
        assert_eq!(synth.lookup(9, &"x".repeat(56)).len(), 2);
        assert_eq!(synth.lookup(9, &"x".repeat(57)).len(), 3);
        // 400 bytes: 24 + 12 * 32.
        assert_eq!(synth.lookup(9, &"x".repeat(400)).len(), 13);
        // Before macOS 15.4 the kernel reports at most 184 bytes: six records.
        let mut old = Synth::new(0, 1).with_path_records(PathRecords::Tail);
        assert_eq!(old.lookup(9, &"x".repeat(184)).len(), 6);
        assert_eq!(old.lookup(9, &"x".repeat(1000)).len(), 6);
    }

    #[test]
    fn syscall_end_widens_ints_like_the_kernel() {
        let mut synth = Synth::new(0, 1);
        let rec = synth.syscall_end(1, 3, 77, -1, [u32::MAX, 0]);
        assert_eq!(rec.arg1, u64::MAX);
        assert_eq!(rec.arg2, u64::MAX);
        assert_eq!(rec.arg4, 77);
    }
}
