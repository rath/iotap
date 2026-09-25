//! Owner handle for iotap's eBPF program on Linux (`bpf/iotap.bpf.c`): loads and attaches it,
//! tells it which processes to trace, and reads its ring buffer.
//!
//! The program pairs the entry and return of each call itself and writes one record per call,
//! so reading comes down to taking records off the ring buffer and putting them in time order.
//! Dropping the handle detaches the program; so does the kernel when iotap exits, however it
//! exits.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use libbpf_rs::{ErrorKind, Link, MapCore, MapFlags, MapHandle, Object, ObjectBuilder, PrintLevel};

use super::time;
use crate::reader::{Read, Spawn, Tracer};
use crate::trace::kdebug::pairing::PathRecords;
use crate::trace::linux::order::Order;
use crate::trace::linux::{Event, Record, codes};
use crate::trace::{Records, System};

/// Keeps the program's ELF image aligned for libbpf, which reads its headers in place.
#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

/// The program, as `build.rs` compiled it.
static PROGRAM: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/iotap.bpf.o")));

/// How far behind the clock reads stay. A record reaches the ring buffer within microseconds of
/// its stamp, so once a read has taken everything written before the clock read `now`, every
/// record stamped before `now - ORDER_MARGIN_NS` is in hand.
const ORDER_MARGIN_NS: u64 = 5_000_000;
/// Most records held back while reads keep stopping at a record still being written.
const HELD_MAX: usize = 1 << 16;
/// Where the kernel describes the process exit tracepoint, wherever tracefs is mounted.
const EXIT_FORMATS: [&str; 2] = [
    "/sys/kernel/tracing/events/sched/sched_process_exit/format",
    "/sys/kernel/debug/tracing/events/sched/sched_process_exit/format",
];
/// Where the kernel describes the task creation tracepoint, wherever tracefs is mounted.
const NEWTASK_FORMATS: [&str; 2] = [
    "/sys/kernel/tracing/events/task/task_newtask/format",
    "/sys/kernel/debug/tracing/events/task/task_newtask/format",
];
/// Lines of libbpf's messages kept for an error: the end of a verifier log says what failed.
const LOG_LINES: usize = 40;

/// What libbpf said lately.
static LOG: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("tracing with eBPF requires root; re-run with sudo")]
    NotPermitted,
    /// The kernel refused the program or one of its maps; `log` has what libbpf said.
    #[error("cannot load iotap's eBPF program: {error:#}{log}")]
    Load { error: libbpf_rs::Error, log: String },
    #[error("cannot attach the eBPF program {program}")]
    Attach {
        program: &'static str,
        #[source]
        source: libbpf_rs::Error,
    },
    #[error("cannot {what}")]
    Map {
        what: &'static str,
        #[source]
        source: libbpf_rs::Error,
    },
    #[error("cannot read the eBPF ring buffer")]
    Ring(#[source] io::Error),
    #[error(
        "cannot follow child processes: this kernel's task_newtask tracepoint does not lay out the new task's pid and clone flags where iotap reads them"
    )]
    NewTaskLayout,
    #[error("the eBPF ring buffer holds a record iotap cannot read, of {len} bytes")]
    BadRecord { len: usize },
}

impl EbpfError {
    fn load(error: libbpf_rs::Error) -> Self {
        if error.kind() == ErrorKind::PermissionDenied && !super::is_root() {
            return Self::NotPermitted;
        }
        Self::Load {
            error,
            log: take_log(),
        }
    }
}

/// Handle to the loaded and attached program. Dropping it detaches the program.
#[derive(Debug)]
pub struct Ebpf {
    /// The attached programs, in the order they were attached.
    links: Vec<Link>,
    ring: Ring,
    order: Order,
    traced: MapHandle,
    inflight: MapHandle,
    dropped: MapHandle,
    stopping: MapHandle,
    /// When the program was wholly attached: calls under way that entered before then may have
    /// returned unseen.
    attached_at: u64,
    /// The ring buffer's map, whose descriptor `wait` polls.
    records: MapHandle,
    /// Owns the programs and maps as libbpf loaded them; kept until the links are gone.
    _object: Object,
}

impl Ebpf {
    /// Loads the program, attaches it and starts tracing `pids`, with a ring buffer of as many
    /// bytes as `buffer` records of 64 bytes take, rounded up to a power of two. With
    /// `children`, a process that a traced one starts is traced too, from its start.
    pub fn start(buffer: u32, pids: &[i32], children: bool) -> Result<Self, EbpfError> {
        libbpf_rs::set_print(Some((PrintLevel::Warn, keep_log)));
        let ring_bytes = ring_bytes(buffer);
        let group_dead = exit_tells_group_dead();
        if children && !newtask_read_as_laid_out() {
            return Err(EbpfError::NewTaskLayout);
        }
        let mut builder = ObjectBuilder::default();
        let mut open = builder.open_memory(&PROGRAM.0).map_err(EbpfError::load)?;
        for mut map in open.maps_mut() {
            if map.name() == "records" {
                map.set_max_entries(ring_bytes).map_err(EbpfError::load)?;
            }
        }
        for mut program in open.progs_mut() {
            if program.name() == "process_exit" {
                // Without the field, the kernel would refuse the whole program.
                program.set_autoload(group_dead);
            } else if program.name() == "task_newtask" {
                program.set_autoload(children);
            }
        }
        let object = open.load().map_err(EbpfError::load)?;
        take_log();

        let map = |name: &'static str| {
            let found = object.maps().find(|map| map.name() == name);
            let handle = found.map(|map| MapHandle::try_from(&map));
            match handle {
                Some(Ok(handle)) => Ok(handle),
                Some(Err(source)) => Err(EbpfError::Map {
                    what: "open a map of the eBPF program",
                    source,
                }),
                None => Err(EbpfError::Map {
                    what: "find a map of the eBPF program",
                    source: libbpf_rs::Error::from(io::Error::new(io::ErrorKind::NotFound, name)),
                }),
            }
        };
        let calls = map("calls")?;
        for entry in codes::table(System::HOST) {
            let number = u32::from(entry.syscall.number);
            calls
                .update(
                    &number.to_le_bytes(),
                    &entry.capture.flags().to_le_bytes(),
                    MapFlags::ANY,
                )
                .map_err(|source| EbpfError::Map {
                    what: "tell the eBPF program which calls to trace",
                    source,
                })?;
        }
        let traced = map("traced")?;
        for &pid in pids {
            trace(&traced, pid)?;
        }
        let records = map("records")?;
        let ring = Ring::new(records.as_fd(), ring_bytes as usize).map_err(EbpfError::Ring)?;
        let (inflight, dropped, stopping) = (map("inflight")?, map("dropped")?, map("stopping")?);

        // New processes first: a process a traced one starts from then on is traced from its
        // start, and the reader finds those started before among the descendants of the traced
        // processes. Then entries: a call that returns before returns are watched was over
        // before tracing began. The other way round, every call returning in between would
        // count as one under way when tracing began, which under a flood of calls is thousands.
        let mut links = Vec::new();
        for name in ["task_newtask", "sys_enter", "process_exit", "sys_exit"] {
            if (name == "process_exit" && !group_dead) || (name == "task_newtask" && !children) {
                continue;
            }
            let link = match object.progs_mut().find(|program| program.name() == name) {
                Some(program) => program.attach(),
                None => Err(libbpf_rs::Error::from(io::Error::from(io::ErrorKind::NotFound))),
            };
            links.push(link.map_err(|source| EbpfError::Attach {
                program: name,
                source,
            })?);
        }
        Ok(Self {
            links,
            ring,
            order: Order::default(),
            traced,
            inflight,
            dropped,
            stopping,
            attached_at: time::now_ticks(),
            records,
            _object: object,
        })
    }

    /// Linux records carry paths whole, so the kdebug layout of lookups does not apply.
    pub fn path_records() -> PathRecords {
        PathRecords::default()
    }

    /// Takes the records waiting in the ring buffer. Returns how far it read.
    fn take(&mut self) -> Result<u64, EbpfError> {
        let order = &mut self.order;
        self.ring.drain(|bytes| match Record::parse(bytes) {
            Some((record, len)) if len == bytes.len() => {
                order.hold(record);
                Ok(())
            }
            _ => Err(EbpfError::BadRecord { len: bytes.len() }),
        })
    }

    /// Calls that entered while the program was wholly attached and have not returned. An
    /// earlier entry may be of a call that returned before returns were watched.
    fn calls_under_way(&self) -> u64 {
        let entered = |key: &[u8]| {
            let value = self.inflight.lookup(key, MapFlags::ANY).ok().flatten()?;
            // `struct call` starts with the time of the entry.
            let ts = u64::from_le_bytes(value.get(..8)?.try_into().ok()?);
            Some(ts)
        };
        self.inflight
            .keys()
            .filter(|key| entered(key).is_some_and(|ts| ts >= self.attached_at))
            .count() as u64
    }

    /// The program's count of records the ring buffer had no room for.
    fn dropped(&self) -> Result<u64, EbpfError> {
        let value = self
            .dropped
            .lookup(&0_u32.to_le_bytes(), MapFlags::ANY)
            .map_err(|source| EbpfError::Map {
                what: "read how many records the eBPF program dropped",
                source,
            })?;
        Ok(value
            .and_then(|value| <[u8; 8]>::try_from(value.get(..8)?).ok())
            .map_or(0, u64::from_le_bytes))
    }
}

impl Tracer for Ebpf {
    type Error = EbpfError;

    /// Blocks until a quarter of the ring buffer waits, when the program wakes the reader, or
    /// `timeout` elapses.
    fn wait(&mut self, timeout: Duration) -> Result<(), EbpfError> {
        let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        poll(self.records.as_fd(), millis).map_err(EbpfError::Ring)
    }

    /// Takes what the ring buffer holds and passes on the records stamped before a mark a
    /// little behind the clock, once the read has reached everything written before the mark.
    fn read(&mut self) -> Result<Read, EbpfError> {
        let mark = time::now_ticks().saturating_sub(ORDER_MARGIN_NS);
        let written = self.ring.written();
        let complete = self.take()? >= written;
        let records = if complete {
            self.order.release(mark)
        } else {
            // A record was still being written; the next read will likely get past it.
            self.order.release_beyond(HELD_MAX)
        };
        let spawned = spawns(&records);
        Ok(Read {
            records: (!records.is_empty()).then_some(Records::Linux(records)),
            complete_to: complete.then_some(mark),
            spawned,
        })
    }

    /// Traces `pid` too. The program follows a process through exec, so tracing it again does
    /// nothing.
    fn add_pid(&mut self, pid: i32) -> Result<(), EbpfError> {
        trace(&self.traced, pid)
    }

    fn remove_pid(&mut self, pid: i32) -> Result<(), EbpfError> {
        match self.traced.delete(&pid.to_le_bytes()) {
            // The program let it go when its last thread exited.
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            result => result.map_err(|source| EbpfError::Map {
                what: "stop tracing a process",
                source,
            }),
        }
    }

    /// Detaches the program, then passes on everything the ring buffer holds, what was dropped
    /// after it, and how many calls were still under way.
    fn finish(&mut self) -> Result<Option<Records>, EbpfError> {
        // Detaching takes a while, up to a tenth of a second. Meanwhile the program starts on no
        // new call, and only returns of calls it saw enter are recorded.
        self.stopping
            .update(&0_u32.to_le_bytes(), &1_u32.to_le_bytes(), MapFlags::ANY)
            .map_err(|source| EbpfError::Map {
                what: "tell the eBPF program to stop",
                source,
            })?;
        // Entries go first, so that what is left in `inflight` below is exactly the calls that
        // had not returned when returns stopped being watched.
        for link in self.links.drain(..) {
            drop(link);
        }
        self.take()?;
        let now = time::now_ticks();
        let dropped = self.dropped()? as u32;
        let mut records = self.order.release_all(now, dropped);
        let calls = self.calls_under_way();
        records.push(Record {
            ts: now,
            dropped,
            event: Event::InProgress { calls },
        });
        Ok(Some(Records::Linux(records)))
    }
}

/// The processes that traced ones started, as `records` tell. The records tell the session too.
fn spawns(records: &[Record]) -> Vec<Spawn> {
    records
        .iter()
        .filter_map(|record| match record.event {
            Event::Fork {
                parent,
                child,
                traced,
            } => Some(Spawn {
                parent: Some(parent),
                child,
                traced,
                in_trace: true,
            }),
            _ => None,
        })
        .collect()
}

/// Adds `pid` to the program's map of processes to trace.
fn trace(traced: &MapHandle, pid: i32) -> Result<(), EbpfError> {
    traced
        .update(&pid.to_le_bytes(), &[1], MapFlags::ANY)
        .map_err(|source| EbpfError::Map {
            what: "trace a process",
            source,
        })
}

/// Bytes of ring buffer for `buffer` records of 64 bytes: a power of two, at least 64 KiB so
/// that it spans whole pages of any size Linux uses, and at most what the kernel takes.
fn ring_bytes(buffer: u32) -> u32 {
    let bytes = (u64::from(buffer.max(1024)) * 64).next_power_of_two();
    u32::try_from(bytes).unwrap_or(1 << 31).min(1 << 31)
}

/// Whether the kernel's process exit tracepoint says, where the program reads it, whether the
/// exiting thread was its process's last.
fn exit_tells_group_dead() -> bool {
    let Some(format) = EXIT_FORMATS.iter().find_map(|path| fs::read_to_string(path).ok()) else {
        return false;
    };
    format.lines().any(|line| {
        line.contains("field:bool group_dead;")
            && field(line, "offset:") == Some(32)
            && field(line, "size:") == Some(1)
    })
}

/// Whether the kernel's task creation tracepoint holds the new task's pid and its clone flags
/// where the program reads them.
fn newtask_read_as_laid_out() -> bool {
    NEWTASK_FORMATS
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .is_some_and(|format| newtask_laid_out(&format))
}

/// Whether `format`, that of the task creation tracepoint, holds the pid in four bytes at 8 and
/// the clone flags in eight bytes at 32, as `struct task_newtask_args` in the program does.
fn newtask_laid_out(format: &str) -> bool {
    let at = |declared: &str, offset: u32, size: u32| {
        format.lines().any(|line| {
            line.contains(declared)
                && field(line, "offset:") == Some(offset)
                && field(line, "size:") == Some(size)
        })
    };
    at(" pid;", 8, 4) && at(" clone_flags;", 32, 8)
}

/// The number after `name` in a line of a tracepoint format, such as `offset:32;`.
fn field(line: &str, name: &str) -> Option<u32> {
    let rest = &line[line.find(name)? + name.len()..];
    rest[..rest.find(';')?].parse().ok()
}

/// Keeps what libbpf says, for an error about loading.
#[expect(
    clippy::needless_pass_by_value,
    reason = "libbpf-rs hands its print callback the message by value"
)]
fn keep_log(_: PrintLevel, message: String) {
    let mut log = LOG.lock().unwrap_or_else(PoisonError::into_inner);
    for line in message.lines().map(str::trim_end).filter(|line| !line.is_empty()) {
        if log.len() == LOG_LINES {
            log.pop_front();
        }
        log.push_back(line.to_owned());
    }
}

/// What libbpf said since the last call, a line each.
fn take_log() -> String {
    let mut log = LOG.lock().unwrap_or_else(PoisonError::into_inner);
    let mut said = String::new();
    for line in log.drain(..) {
        said.push_str("\n  ");
        said.push_str(&line);
    }
    said
}

/// Waits until `fd` is readable or `millis` pass. A signal ends the wait early.
fn poll(fd: BorrowedFd<'_>, millis: libc::c_int) -> io::Result<()> {
    let mut entry = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `entry` is one valid, writable `pollfd` for the duration of the call.
    let rc = unsafe { libc::poll(&raw mut entry, 1, millis) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(())
}

/// Bit of a record's length word: the record is still being written.
const BUSY: u32 = 1 << 31;
/// Bit of a record's length word: the program threw the record away.
const DISCARDED: u32 = 1 << 30;
/// Bytes before each record in the ring buffer: its length word and a page offset.
const RECORD_HEADER: usize = 8;

/// The reading side of a BPF ring buffer, mapped into iotap's memory as libbpf maps it.
#[derive(Debug)]
struct Ring {
    /// The page holding the consumer position, which iotap advances.
    consumer: Mapping,
    /// The page holding the producer position, then the data pages mapped twice in a row, so
    /// that a record that wraps around the end reads as one piece.
    producer: Mapping,
    /// Where the data starts in `producer`: one page in.
    data: usize,
    /// Bytes of data, a power of two.
    size: usize,
}

impl Ring {
    fn new(fd: BorrowedFd<'_>, size: usize) -> io::Result<Self> {
        // SAFETY: `sysconf` has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page).map_err(|_| io::Error::last_os_error())?;
        if !size.is_power_of_two() || !size.is_multiple_of(page) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(Self {
            consumer: Mapping::new(fd, page, libc::PROT_READ | libc::PROT_WRITE, 0)?,
            producer: Mapping::new(fd, page + 2 * size, libc::PROT_READ, page)?,
            data: page,
            size,
        })
    }

    /// The position word a mapping starts with.
    fn position(mapping: &Mapping) -> &AtomicU64 {
        // SAFETY: each mapping starts with the kernel's position word, page aligned, and lives
        // as long as the reference. The kernel updates the word atomically, and iotap only
        // touches it through this atomic. On the processors iotap supports an atomic load is a
        // plain load, which the read-only producer page allows.
        unsafe { AtomicU64::from_ptr(mapping.ptr.as_ptr().cast()) }
    }

    /// How far the program has written, records in progress included.
    fn written(&self) -> u64 {
        Self::position(&self.producer).load(Ordering::Acquire)
    }

    /// Hands each complete record to `take`, oldest first, and frees its space once taken.
    /// Stops at a record still being written. Returns the position it reached.
    fn drain(&self, mut take: impl FnMut(&[u8]) -> Result<(), EbpfError>) -> Result<u64, EbpfError> {
        let consumer = Self::position(&self.consumer);
        let mut at = consumer.load(Ordering::Acquire);
        loop {
            let written = self.written();
            if at >= written {
                return Ok(at);
            }
            while at < written {
                // The size is a power of two, so this is the offset within the data.
                let offset = (at % self.size as u64) as usize;
                let word = self.length_word(offset).load(Ordering::Acquire);
                if word & BUSY != 0 {
                    return Ok(at);
                }
                let len = (word & !(BUSY | DISCARDED)) as usize;
                if word & DISCARDED == 0 {
                    take(self.record(offset, len)?)?;
                }
                at += (RECORD_HEADER + len).next_multiple_of(8) as u64;
                consumer.store(at, Ordering::Release);
            }
        }
    }

    /// The length word of the record at `offset` into the data.
    fn length_word(&self, offset: usize) -> &AtomicU32 {
        // SAFETY: `offset` is below the data's size and a multiple of 8, so the word lies
        // within the mapping, aligned. The kernel writes it atomically, with release ordering
        // once the record is complete.
        unsafe {
            AtomicU32::from_ptr(
                self.producer
                    .ptr
                    .as_ptr()
                    .cast::<u8>()
                    .add(self.data + offset)
                    .cast(),
            )
        }
    }

    /// The `len` bytes of the record at `offset` into the data.
    fn record(&self, offset: usize, len: usize) -> Result<&[u8], EbpfError> {
        // The kernel never writes a record longer than the ring; check rather than read past
        // the mapping if it ever did.
        if offset + RECORD_HEADER + len > 2 * self.size {
            return Err(EbpfError::BadRecord { len });
        }
        // SAFETY: the bytes lie within the two copies of the data, and the kernel leaves a
        // complete record alone until the consumer position passes it.
        Ok(unsafe {
            std::slice::from_raw_parts(
                self.producer
                    .ptr
                    .as_ptr()
                    .cast::<u8>()
                    .add(self.data + offset + RECORD_HEADER),
                len,
            )
        })
    }
}

/// Pages of a descriptor mapped into memory, unmapped when dropped.
#[derive(Debug)]
struct Mapping {
    ptr: NonNull<libc::c_void>,
    len: usize,
}

impl Mapping {
    fn new(fd: BorrowedFd<'_>, len: usize, prot: libc::c_int, offset: usize) -> io::Result<Self> {
        let offset =
            libc::off_t::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: a new shared mapping at an address the kernel picks leaves all existing
        // memory alone.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        NonNull::new(ptr)
            .map(|ptr| Self { ptr, len })
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` describe a mapping this value made and nothing else unmaps,
        // and no reference into it outlives `self`.
        unsafe { libc::munmap(self.ptr.as_ptr(), self.len) };
    }
}

// SAFETY: a mapping is shared memory this value owns alone; which thread uses it does not
// matter.
unsafe impl Send for Mapping {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::linux::synth::Synth;

    #[test]
    fn ring_sizes_are_powers_of_two_the_kernel_takes() {
        assert_eq!(ring_bytes(524_288), 32 << 20);
        assert_eq!(ring_bytes(1_000_000), 64 << 20);
        assert_eq!(ring_bytes(0), 64 << 10);
        assert_eq!(ring_bytes(u32::MAX), 1 << 31);
    }

    #[test]
    fn reads_tracepoint_formats() {
        let line = "\tfield:bool group_dead;\toffset:32;\tsize:1;\tsigned:0;";
        assert_eq!(
            (field(line, "offset:"), field(line, "size:")),
            (Some(32), Some(1))
        );
        assert_eq!(field(line, "count:"), None);
    }

    #[test]
    fn checks_where_the_task_creation_tracepoint_holds_its_fields() {
        let format = |clone_flags: &str| {
            format!(
                "name: task_newtask\nformat:\n\
                 \tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
                 \tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
                 \tfield:pid_t pid;\toffset:8;\tsize:4;\tsigned:1;\n\
                 \tfield:char comm[16];\toffset:12;\tsize:16;\tsigned:0;\n\
                 \t{clone_flags}\n\
                 \tfield:short oom_score_adj;\toffset:40;\tsize:2;\tsigned:1;\n"
            )
        };
        // Newer kernels declare the flags u64, older ones unsigned long.
        assert!(newtask_laid_out(&format(
            "field:u64 clone_flags;\toffset:32;\tsize:8;\tsigned:0;"
        )));
        assert!(newtask_laid_out(&format(
            "field:unsigned long clone_flags;\toffset:32;\tsize:8;\tsigned:0;"
        )));
        assert!(!newtask_laid_out(&format(
            "field:u64 clone_flags;\toffset:40;\tsize:8;\tsigned:0;"
        )));
        assert!(!newtask_laid_out("name: task_newtask\n"));
    }

    #[test]
    fn forks_in_the_records_are_spawns() {
        let mut synth = Synth::new(System::HOST, 1_000, 10);
        let records = [
            synth.open(7, 70, "/etc/hosts", 3),
            synth.fork(70, 71),
            synth.exit(71),
        ];
        assert_eq!(
            spawns(&records),
            [Spawn {
                parent: Some(70),
                child: 71,
                traced: true,
                in_trace: true
            }]
        );
    }

    #[test]
    fn keeps_the_last_lines_libbpf_said() {
        take_log();
        keep_log(PrintLevel::Warn, "libbpf: one\n\n".into());
        for n in 0..LOG_LINES {
            keep_log(PrintLevel::Warn, format!("libbpf: line {n}\n"));
        }
        let log = take_log();
        assert!(log.starts_with("\n  libbpf: line 0\n"), "{log}");
        assert!(log.ends_with(&format!("libbpf: line {}", LOG_LINES - 1)));
        assert_eq!(take_log(), "");
    }

    #[test]
    fn start_without_root_is_rejected() {
        if crate::sys::is_root() {
            return;
        }
        let err = Ebpf::start(1024, &[], false).expect_err("non-root must not load eBPF programs");
        assert!(matches!(err, EbpfError::NotPermitted), "{err:?}");
    }
}
