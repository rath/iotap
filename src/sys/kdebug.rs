//! Owner handle for the kernel trace facility (`kern.kdebug` sysctl).
//!
//! Setup follows the order `fs_usage` uses: drop any stale session, size and allocate the
//! buffers, install the class filter, flag the target processes, then enable tracing. Dropping
//! the handle disables tracing and releases the facility so other tools can use it.

use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::time;
use crate::reader::{Read, Tracer};
use crate::trace::Records;
use crate::trace::kdebug::KdBuf;
use crate::trace::kdebug::codes;
use crate::trace::kdebug::pairing::PathRecords;

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

/// Handle to the running trace session. Dropping it stops tracing and releases the facility.
#[derive(Debug)]
pub struct Kdebug {
    /// Number of records the kernel buffer holds; a read never returns more.
    capacity: usize,
    /// Where records are read to; sized to `capacity` on the first read.
    buf: Vec<KdBuf>,
}

impl Kdebug {
    /// Takes ownership of the trace facility and starts tracing `pids`, recording what the
    /// kdebug decoder reads into a kernel buffer of about `buffer_events` records.
    pub fn start(buffer_events: u32, pids: &[i32]) -> Result<Self, KdebugError> {
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

    /// A read that finds no records has seen every record stamped before it began.
    fn read(&mut self) -> Result<Read, KdebugError> {
        if self.buf.len() != self.capacity {
            self.buf.resize(self.capacity, KdBuf::default());
        }
        let read_at = time::now_ticks();
        let count = read(&mut self.buf).map_err(|e| KdebugError::from_os("KERN_KDREADTR", e))?;
        Ok(if count > 0 {
            Read {
                records: Some(Records::Kdebug(self.buf[..count].to_vec())),
                ..Read::default()
            }
        } else {
            Read {
                complete_to: Some(read_at),
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
        })
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
        let err = Kdebug::start(1024, &[]).expect_err("non-root must not configure kdebug");
        assert!(
            matches!(err, KdebugError::NotPermitted | KdebugError::Busy),
            "{err:?}"
        );
        assert!(!OWNED.load(Ordering::SeqCst));
    }
}
