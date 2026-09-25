//! Owner handle for the kernel trace facility (`kern.kdebug` sysctl).
//!
//! Setup follows the order `fs_usage` uses: drop any stale session, size and allocate the
//! buffers, install the class filter, flag the target processes, then enable tracing. Dropping
//! the handle disables tracing and releases the facility so other tools can use it.

use std::collections::HashSet;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::time;
use crate::reader::{Read, Spawn, Tracer};
use crate::trace::Records;
use crate::trace::kdebug::KdBuf;
use crate::trace::kdebug::codes;
use crate::trace::kdebug::pairing::PathRecords;
use crate::trace::kdebug::spawns::Spawns;

/// `kbufinfo_t`: answer to `KERN_KDGETBUF`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct KbufInfo {
    nkdbufs: i32,
    nolog: i32,
    flags: u32,
    nkdthreads: i32,
    bufid: i32,
}

/// `kd_regtype`: argument of `KERN_KDPIDTR`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct KdRegType {
    kind: u32,
    value1: u32,
    value2: u32,
    value3: u32,
    value4: u32,
}

const KDBG_TYPENONE: u32 = 0x8_0000;
const KDEBUG_ENABLE_TRACE: libc::c_int = 0x1;

/// Size of the class filter bitmap: one bit per (class, subclass) pair.
pub const TYPEFILTER_BYTES: usize = 256 * 256 / 8;

/// Set of (class, subclass) pairs the kernel should record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeFilter {
    bits: Vec<u8>,
}

impl Default for TypeFilter {
    fn default() -> Self {
        Self {
            bits: vec![0; TYPEFILTER_BYTES],
        }
    }
}

impl TypeFilter {
    /// Enables every event of `class`/`subclass`.
    pub fn allow(&mut self, class: u8, subclass: u8) -> &mut Self {
        let bit = Self::bit(class, subclass);
        self.bits[bit / 8] |= 1 << (bit % 8);
        self
    }

    pub fn allows(&self, class: u8, subclass: u8) -> bool {
        let bit = Self::bit(class, subclass);
        self.bits[bit / 8] & (1 << (bit % 8)) != 0
    }

    /// Bit index used by the kernel (`ENCODE_CSC_LOW`).
    fn bit(class: u8, subclass: u8) -> usize {
        (usize::from(class) << 8) | usize::from(subclass)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KdebugError {
    #[error("the kernel trace facility requires root; re-run with sudo")]
    NotPermitted,
    #[error(
        "another tool (fs_usage, ktrace, Instruments, ...) is using the kernel trace facility; stop it and retry"
    )]
    Busy,
    #[error("no process with pid {0}")]
    NoSuchProcess(i32),
    #[error("a kdebug session is already active in this process")]
    AlreadyActive,
    #[error("{op} failed")]
    Sysctl {
        op: &'static str,
        #[source]
        source: io::Error,
    },
}

impl KdebugError {
    fn from_os(op: &'static str, err: io::Error) -> Self {
        match err.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => Self::NotPermitted,
            Some(libc::EBUSY) => Self::Busy,
            _ => Self::Sysctl { op, source: err },
        }
    }
}

/// Set while this process owns a configured kdebug session.
static OWNED: AtomicBool = AtomicBool::new(false);

/// How long iotap keeps trying to flag a child the kernel cannot find yet, as it may still be
/// being created.
const CHILD_GRACE: Duration = Duration::from_millis(50);
/// How long after a traced process runs exec iotap flags it again at every read: exec gives a
/// process a new kernel proc, without the trace flag, a moment after the kernel records it.
const EXEC_GRACE: Duration = Duration::from_millis(30);

/// The processes flagged for tracing, and those the records show are to be flagged: the
/// processes that traced ones start, which start without the flag, and traced processes that
/// ran exec, which loses it.
#[derive(Debug)]
struct Flags {
    /// Flag the processes that traced ones start.
    children: bool,
    spawns: Spawns,
    /// Processes flagged and not found gone.
    flagged: HashSet<i32>,
    /// Children to flag, each with its parent if known, until the kernel finds them or the
    /// time given passes.
    waiting: Vec<(Option<i32>, i32, Instant)>,
    /// Processes that ran exec, to flag again at every read until the time given.
    again: Vec<(i32, Instant)>,
}

impl Flags {
    fn new(children: bool) -> Self {
        Self {
            children,
            spawns: Spawns::default(),
            flagged: HashSet::new(),
            waiting: Vec::new(),
            again: Vec::new(),
        }
    }

    /// Takes up what the records of a read made at `now` show, flagging processes with `flag`,
    /// which says whether the kernel found the process. Returns the children flagged, and those
    /// the kernel did not find in time, which have ended.
    fn take_up(&mut self, records: &[KdBuf], now: Instant, mut flag: impl FnMut(i32) -> bool) -> Vec<Spawn> {
        let found = self.spawns.scan(records);
        if self.children {
            for (parent, child) in found.started {
                // One flagged already was found otherwise: the reader looks for the running
                // descendants of traced processes too.
                if !self.flagged.contains(&child) && !self.waiting.iter().any(|w| w.1 == child) {
                    self.waiting.push((parent, child, now + CHILD_GRACE));
                }
            }
        }
        let mut spawned = Vec::new();
        for (parent, child, until) in std::mem::take(&mut self.waiting) {
            let traced = flag(child);
            if traced {
                self.flagged.insert(child);
            }
            if traced || now >= until {
                spawned.push(Spawn {
                    parent,
                    child,
                    traced,
                    in_trace: false,
                });
            } else {
                self.waiting.push((parent, child, until));
            }
        }
        // After the children, which may have run exec since they started.
        for pid in found.execed {
            if self.flagged.contains(&pid) {
                self.again.push((pid, now + EXEC_GRACE));
            }
        }
        self.again.retain(|&(pid, until)| {
            // One gone meanwhile has nothing to flag.
            flag(pid);
            now < until
        });
        spawned
    }
}

/// Handle to the running trace session. Dropping it stops tracing and releases the facility.
#[derive(Debug)]
pub struct Kdebug {
    /// Number of records the kernel buffer holds; a read never returns more.
    capacity: usize,
    /// Where records are read to; sized to `capacity` on the first read.
    buf: Vec<KdBuf>,
    flags: Flags,
}

impl Kdebug {
    /// Takes ownership of the trace facility and starts tracing `pids`, recording what the
    /// kdebug decoder reads into a kernel buffer of about `buffer_events` records. With
    /// `children`, a process that a traced one starts is traced too, from when a read shows it.
    pub fn start(buffer_events: u32, pids: &[i32], children: bool) -> Result<Self, KdebugError> {
        if OWNED.load(Ordering::SeqCst) {
            return Err(KdebugError::AlreadyActive);
        }
        // Clears a stale session left by a crashed tracer; fails if a live tool owns kdebug.
        remove().map_err(|e| KdebugError::from_os("KERN_KDREMOVE", e))?;
        OWNED.store(true, Ordering::SeqCst);
        // From here on, dropping `session` tears the configuration down again.
        let mut session = Self {
            capacity: 0,
            buf: Vec::new(),
            flags: Flags::new(children),
        };

        let events = libc::c_int::try_from(buffer_events.max(1024)).unwrap_or(libc::c_int::MAX);
        set_buffer_events(events).map_err(|e| KdebugError::from_os("KERN_KDSETBUF", e))?;
        setup().map_err(|e| KdebugError::from_os("KERN_KDSETUP", e))?;
        let info = buffer_info().map_err(|e| KdebugError::from_os("KERN_KDGETBUF", e))?;
        session.capacity = usize::try_from(info.nkdbufs).unwrap_or(0).max(1);

        let mut filter = TypeFilter::default();
        for (class, subclass) in codes::TRACED_CLASSES {
            filter.allow(class, subclass);
        }
        set_typefilter(&mut filter).map_err(|e| KdebugError::from_os("KERN_KDSET_TYPEFILTER", e))?;
        for &pid in pids {
            session.add_pid(pid)?;
        }
        enable(true).map_err(|e| KdebugError::from_os("KERN_KDENABLE", e))?;
        Ok(session)
    }

    /// How this kernel lays out lookup paths in its records.
    pub fn path_records() -> PathRecords {
        os_release().map_or_else(PathRecords::default, |release| PathRecords::for_release(&release))
    }
}

impl Tracer for Kdebug {
    type Error = KdebugError;

    /// Blocks until the kernel buffer is half full or `timeout` elapses.
    fn wait(&mut self, timeout: Duration) -> Result<(), KdebugError> {
        let millis = usize::try_from(timeout.as_millis()).unwrap_or(usize::MAX).max(1);
        wait(millis).map_err(|e| KdebugError::from_os("KERN_KDBUFWAIT", e))
    }

    /// A read that finds no records has seen every record stamped before it began. The
    /// children a read shows are flagged at once, and so are traced processes that ran exec.
    fn read(&mut self) -> Result<Read, KdebugError> {
        if self.buf.len() != self.capacity {
            self.buf.resize(self.capacity, KdBuf::default());
        }
        let read_at = time::now_ticks();
        let count = read(&mut self.buf).map_err(|e| KdebugError::from_os("KERN_KDREADTR", e))?;
        let spawned = self.flags.take_up(&self.buf[..count], Instant::now(), |pid| {
            set_pid(pid, true).is_ok()
        });
        Ok(if count > 0 {
            Read {
                records: Some(Records::Kdebug(self.buf[..count].to_vec())),
                spawned,
                ..Read::default()
            }
        } else {
            Read {
                complete_to: Some(read_at),
                spawned,
                ..Read::default()
            }
        })
    }

    /// Flags `pid` for tracing. Calling it again for a flagged process is harmless, which is
    /// how a process that replaced its image with `exec` is picked up again.
    fn add_pid(&mut self, pid: i32) -> Result<(), KdebugError> {
        set_pid(pid, true).map_err(|e| match e.raw_os_error() {
            Some(libc::ESRCH | libc::EINVAL) => KdebugError::NoSuchProcess(pid),
            _ => KdebugError::from_os("KERN_KDPIDTR", e),
        })?;
        self.flags.flagged.insert(pid);
        Ok(())
    }

    /// Forgets `pid`; the kernel dropped its flag with the process.
    fn remove_pid(&mut self, pid: i32) -> Result<(), KdebugError> {
        self.flags.flagged.remove(&pid);
        Ok(())
    }
}

impl Drop for Kdebug {
    fn drop(&mut self) {
        release();
    }
}

/// Stops tracing and releases the facility if this process configured it. Safe to call from a
/// panic hook; does nothing when no session is active.
pub fn release() {
    if OWNED.swap(false, Ordering::SeqCst) {
        // Errors are ignored: this runs on shutdown paths where nothing better can be done,
        // and `KERN_KDREMOVE` also disables tracing.
        let _ = enable(false);
        let _ = remove();
    }
}

fn kd_sysctl(
    op: libc::c_int,
    value: Option<libc::c_int>,
    buf: *mut libc::c_void,
    len: &mut usize,
) -> io::Result<()> {
    let mut mib = [libc::CTL_KERN, libc::KERN_KDEBUG, op, value.unwrap_or(0)];
    let name_len: libc::c_uint = if value.is_some() { 4 } else { 3 };
    // SAFETY: `mib` holds at least `name_len` integers. `buf` is either null with `*len == 0`
    // or points to a caller-owned buffer of `*len` bytes that outlives the call.
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), name_len, buf, len, ptr::null_mut(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove() -> io::Result<()> {
    kd_sysctl(libc::KERN_KDREMOVE, None, ptr::null_mut(), &mut 0)
}

fn set_buffer_events(events: libc::c_int) -> io::Result<()> {
    kd_sysctl(libc::KERN_KDSETBUF, Some(events), ptr::null_mut(), &mut 0)
}

fn setup() -> io::Result<()> {
    kd_sysctl(libc::KERN_KDSETUP, None, ptr::null_mut(), &mut 0)
}

fn buffer_info() -> io::Result<KbufInfo> {
    let mut info = KbufInfo::default();
    let mut len = size_of::<KbufInfo>();
    kd_sysctl(libc::KERN_KDGETBUF, None, (&raw mut info).cast(), &mut len)?;
    Ok(info)
}

fn set_typefilter(filter: &mut TypeFilter) -> io::Result<()> {
    let mut len = filter.bits.len();
    kd_sysctl(
        libc::KERN_KDSET_TYPEFILTER,
        None,
        filter.bits.as_mut_ptr().cast(),
        &mut len,
    )
}

fn set_pid(pid: i32, on: bool) -> io::Result<()> {
    let mut reg = KdRegType {
        kind: KDBG_TYPENONE,
        value1: pid.cast_unsigned(),
        value2: u32::from(on),
        ..KdRegType::default()
    };
    let mut len = size_of::<KdRegType>();
    kd_sysctl(libc::KERN_KDPIDTR, None, (&raw mut reg).cast(), &mut len)
}

fn enable(on: bool) -> io::Result<()> {
    let value = if on { KDEBUG_ENABLE_TRACE } else { 0 };
    kd_sysctl(libc::KERN_KDENABLE, Some(value), ptr::null_mut(), &mut 0)
}

fn wait(timeout_ms: usize) -> io::Result<()> {
    // The timeout travels in the length word.
    let mut len = timeout_ms;
    kd_sysctl(libc::KERN_KDBUFWAIT, None, ptr::null_mut(), &mut len)
}

/// The kernel release, such as `24.4.0` (`kern.osrelease`).
fn os_release() -> Option<String> {
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    // SAFETY: the name is NUL-terminated, `buf` holds `len` writable bytes, and no new value
    // is passed.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.osrelease".as_ptr(),
            buf.as_mut_ptr().cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let text = &buf[..len.min(buf.len())];
    let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
    String::from_utf8(text[..end].to_vec()).ok()
}

fn read(buf: &mut [KdBuf]) -> io::Result<usize> {
    // The kernel reads the capacity from the length in bytes and returns a record count.
    let mut len = buf.len() * KdBuf::SIZE;
    kd_sysctl(libc::KERN_KDREADTR, None, buf.as_mut_ptr().cast(), &mut len)?;
    Ok(len.min(buf.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::kdebug::synth::Synth;

    const PARENT: i32 = 500;

    fn spawn(child: i32, traced: bool) -> Spawn {
        Spawn {
            parent: Some(PARENT),
            child,
            traced,
            in_trace: false,
        }
    }

    fn after(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn flags_children_as_soon_as_the_kernel_finds_them() {
        let mut synth = Synth::new(0, 1);
        let mut flags = Flags::new(true);
        flags.flagged.insert(PARENT);
        let start = Instant::now();
        // The kernel finds the first child; it is still creating the second.
        let mut records = synth.spawn(7, PARENT, 70, 501);
        records.extend(synth.spawn(7, PARENT, 71, 502));
        let spawned = flags.take_up(&records, start, |pid| pid == 501);
        assert_eq!(spawned, [spawn(501, true)]);
        // It finds the second a moment later.
        let spawned = flags.take_up(&[], after(start, 10), |pid| pid == 502);
        assert_eq!(spawned, [spawn(502, true)]);
        // One it never finds has ended by the time iotap gives up on it.
        let records = synth.spawn(7, PARENT, 72, 503);
        assert!(flags.take_up(&records, after(start, 20), |_| false).is_empty());
        let spawned = flags.take_up(&[], after(start, 20) + CHILD_GRACE, |_| false);
        assert_eq!(spawned, [spawn(503, false)]);
        // Nothing is left to flag.
        let mut tries = Vec::new();
        flags.take_up(&[], after(start, 200), |pid| {
            tries.push(pid);
            true
        });
        assert!(tries.is_empty(), "{tries:?}");
        assert_eq!(flags.flagged, HashSet::from([PARENT, 501, 502]));
    }

    #[test]
    fn leaves_children_to_the_reader_unless_asked_and_once_it_traces_them() {
        let mut synth = Synth::new(0, 1);
        let records = synth.spawn(7, PARENT, 70, 501);
        let mut tries = Vec::new();
        let mut flags = Flags::new(false);
        flags.flagged.insert(PARENT);
        let spawned = flags.take_up(&records, Instant::now(), |pid| {
            tries.push(pid);
            true
        });
        assert!(spawned.is_empty() && tries.is_empty(), "{spawned:?} {tries:?}");
        // The reader found and traced it as a running descendant before the read showed it.
        let mut flags = Flags::new(true);
        flags.flagged.extend([PARENT, 501]);
        let spawned = flags.take_up(&records, Instant::now(), |_| true);
        assert!(spawned.is_empty(), "{spawned:?}");
    }

    #[test]
    fn flags_a_traced_process_again_for_a_while_after_exec() {
        let mut synth = Synth::new(0, 1);
        let mut flags = Flags::new(false);
        flags.flagged.insert(PARENT);
        let start = Instant::now();
        let mut tries = Vec::new();
        let mut read = |records: &[KdBuf], at: Instant| {
            flags.take_up(records, at, |pid| {
                tries.push((pid, at));
                true
            });
        };
        // A process that is not traced runs exec too.
        read(&[synth.exec(7, PARENT), synth.exec(9, 600)], start);
        read(&[], after(start, 10));
        read(&[], start + EXEC_GRACE);
        read(&[], after(start, 100));
        let times = [start, after(start, 10), start + EXEC_GRACE];
        assert_eq!(tries, times.map(|at| (PARENT, at)));
    }

    #[test]
    fn flags_a_child_that_ran_exec_in_the_same_read_again() {
        let mut synth = Synth::new(0, 1);
        let mut flags = Flags::new(true);
        flags.flagged.insert(PARENT);
        // A fork, and then an exec in the child, which gives it a new kernel proc that may not
        // be in place when the child is flagged.
        let records = [
            synth.syscall_start(7, 2, [0; 4]),
            synth.new_thread(7, 70, 501, false),
            synth.syscall_end(7, 2, PARENT, 0, [501, 0]),
            synth.new_thread(70, 71, 501, true),
            synth.exec(71, 501),
        ];
        let start = Instant::now();
        let mut tries = Vec::new();
        let spawned = flags.take_up(&records, start, |pid| {
            tries.push(pid);
            true
        });
        assert_eq!(spawned, [spawn(501, true)]);
        assert_eq!(tries, [501, 501]);
        flags.take_up(&[], after(start, 10), |pid| {
            tries.push(pid);
            true
        });
        assert_eq!(tries, [501; 3]);
    }

    #[test]
    fn typefilter_uses_kernel_bit_order() {
        let mut filter = TypeFilter::default();
        filter.allow(4, 0x0c).allow(3, 1);
        // ENCODE_CSC_LOW(4, 0x0c) = 0x040c -> byte 0x81, bit 4.
        assert_eq!(filter.bits[0x81], 0x10);
        // ENCODE_CSC_LOW(3, 1) = 0x0301 -> byte 0x60, bit 1.
        assert_eq!(filter.bits[0x60], 0x02);
        assert!(filter.allows(4, 0x0c));
        assert!(!filter.allows(4, 0x0d));
        assert_eq!(filter.bits.iter().map(|b| b.count_ones()).sum::<u32>(), 2);
    }

    #[test]
    fn start_without_root_is_rejected() {
        if crate::sys::is_root() {
            return;
        }
        let err = Kdebug::start(1024, &[], false).expect_err("non-root must not configure kdebug");
        assert!(
            matches!(err, KdebugError::NotPermitted | KdebugError::Busy),
            "{err:?}"
        );
        assert!(!OWNED.load(Ordering::SeqCst));
    }
}
