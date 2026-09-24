//! The record format of iotap's Linux eBPF program (`bpf/iotap.bpf.c`): a record for each
//! syscall of a traced process that returned, its entry and return put together in the kernel,
//! and one for each traced process that exited. Loading the program and reading its ring buffer
//! is up to `sys::ebpf`; everything here is plain data handling.

pub mod codes;
pub mod synth;

use super::call::{Completed, Lookup, PathForm, Syscall};
use super::{Decode, Step, System, Traced};

/// Bytes before a record's memory: the fixed part of `struct record` in the eBPF program.
pub const HEADER: usize = 96;
/// Most bytes the program reads from a caller's memory: a path of `PATH_MAX` bytes.
pub const MEMORY_MAX: usize = 4096;

// Kinds of records. The program writes calls and exits; the reader adds the rest.
const KIND_CALL: u16 = 1;
const KIND_EXIT: u16 = 2;
const KIND_LOST: u16 = 3;
const KIND_IN_PROGRESS: u16 = 4;

// What follows the fixed part of a call's record.
const MEMORY_NOTHING: u8 = 0;
const MEMORY_PATH: u8 = 1;
const MEMORY_SOCKADDR: u8 = 2;
const MEMORY_FDS: u8 = 3;

/// `AF_UNIX` on Linux.
const AF_UNIX: u16 = 1;
/// Largest errno a Linux call returns, negated, in place of a result.
const MAX_ERRNO: i64 = 4095;

/// One record, as the eBPF program or the reader writes it.
///
/// Layout, little-endian: `ts` at 0, the call's `start_ns` at 8, its six arguments from 16 (a
/// count in the first for lost and in-progress records), `ret` at 64, `pid` at 72, `tid` at 76,
/// the call's number at 80, the kind at 84, the memory's length at 86 and its kind at 88,
/// `dropped` at 92, then the memory itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// `CLOCK_MONOTONIC` nanoseconds when the call returned or the event happened. Records
    /// reach the reader in nearly this order, and it passes them on in exactly this order.
    pub ts: u64,
    /// Records the program had failed to write when it wrote this one, wrapping at 2^32. The
    /// reader tells from it where records were lost.
    pub dropped: u32,
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A syscall of a traced process returned.
    Call(RawCall),
    /// The last thread of process `pid` exited.
    Exit { pid: i32 },
    /// The ring buffer was full, and the program dropped `count` records before this point.
    Lost { count: u64 },
    /// Tracing stopped with `calls` calls of the traced processes still in progress.
    InProgress { calls: u64 },
}

/// A syscall that returned, as the program writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawCall {
    /// Process (thread group) that made the call.
    pub pid: i32,
    /// Thread that made it.
    pub tid: i32,
    /// Its number on the system that made the record.
    pub number: u32,
    /// When it entered the kernel; `None` when it began before tracing did.
    pub start_ns: Option<u64>,
    /// The six argument registers at entry; zero when the entry was not seen.
    pub args: [u64; 6],
    /// What it returned: a result, or an errno negated.
    pub ret: i64,
    pub memory: Memory,
}

/// What the program read from the caller's memory as the call returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Memory {
    Nothing,
    /// The path the call took, as the process passed it.
    Path(Vec<u8>),
    /// The socket address the call took.
    Sockaddr(Vec<u8>),
    /// The two descriptors the call stored.
    Fds([i32; 2]),
}

impl Memory {
    fn parse(kind: u8, bytes: &[u8]) -> Option<Self> {
        Some(match kind {
            MEMORY_NOTHING if bytes.is_empty() => Self::Nothing,
            MEMORY_PATH => Self::Path(bytes.to_vec()),
            MEMORY_SOCKADDR => Self::Sockaddr(bytes.to_vec()),
            MEMORY_FDS if bytes.len() == 8 => Self::Fds([
                i32::from_le_bytes(word(bytes, 0)),
                i32::from_le_bytes(word(bytes, 4)),
            ]),
            _ => return None,
        })
    }

    /// Its kind and bytes as the program writes them, at most [`MEMORY_MAX`] of them.
    fn bytes(&self) -> (u8, Vec<u8>) {
        let (kind, mut bytes) = match self {
            Self::Nothing => (MEMORY_NOTHING, Vec::new()),
            Self::Path(path) => (MEMORY_PATH, path.clone()),
            Self::Sockaddr(addr) => (MEMORY_SOCKADDR, addr.clone()),
            Self::Fds(fds) => (MEMORY_FDS, fds.iter().flat_map(|fd| fd.to_le_bytes()).collect()),
        };
        bytes.truncate(MEMORY_MAX);
        (kind, bytes)
    }
}

impl Record {
    /// Reads the record at the start of `bytes`. Returns it and its length in bytes, or `None`
    /// when `bytes` does not start with a whole record of a known kind.
    pub fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let header = bytes.get(..HEADER)?;
        let u64_at = |at| u64::from_le_bytes(word(header, at));
        let u32_at = |at| u32::from_le_bytes(word(header, at));
        let u16_at = |at| u16::from_le_bytes(word(header, at));
        let len = HEADER + usize::from(u16_at(86));
        let memory = bytes.get(HEADER..len)?;
        let event = match u16_at(84) {
            KIND_CALL => Event::Call(RawCall {
                pid: u32_at(72).cast_signed(),
                tid: u32_at(76).cast_signed(),
                number: u32_at(80),
                start_ns: Some(u64_at(8)).filter(|&ts| ts != 0),
                args: std::array::from_fn(|i| u64_at(16 + 8 * i)),
                ret: u64_at(64).cast_signed(),
                memory: Memory::parse(header[88], memory)?,
            }),
            KIND_EXIT if memory.is_empty() => Event::Exit {
                pid: u32_at(72).cast_signed(),
            },
            KIND_LOST if memory.is_empty() => Event::Lost { count: u64_at(16) },
            KIND_IN_PROGRESS if memory.is_empty() => Event::InProgress { calls: u64_at(16) },
            _ => return None,
        };
        let record = Self {
            ts: u64_at(0),
            dropped: u32_at(92),
            event,
        };
        Some((record, len))
    }

    /// Appends the record, laid out as the program writes it.
    pub fn write(&self, out: &mut Vec<u8>) {
        let mut header = [0u8; HEADER];
        let mut put = |at: usize, bytes: &[u8]| header[at..at + bytes.len()].copy_from_slice(bytes);
        put(0, &self.ts.to_le_bytes());
        put(92, &self.dropped.to_le_bytes());
        let (kind, (memory_kind, memory)) = match &self.event {
            Event::Call(call) => {
                put(8, &call.start_ns.unwrap_or(0).to_le_bytes());
                for (i, arg) in call.args.iter().enumerate() {
                    put(16 + 8 * i, &arg.to_le_bytes());
                }
                put(64, &call.ret.to_le_bytes());
                put(72, &call.pid.to_le_bytes());
                put(76, &call.tid.to_le_bytes());
                put(80, &call.number.to_le_bytes());
                (KIND_CALL, call.memory.bytes())
            }
            Event::Exit { pid } => {
                put(72, &pid.to_le_bytes());
                (KIND_EXIT, Memory::Nothing.bytes())
            }
            Event::Lost { count } => {
                put(16, &count.to_le_bytes());
                (KIND_LOST, Memory::Nothing.bytes())
            }
            Event::InProgress { calls } => {
                put(16, &calls.to_le_bytes());
                (KIND_IN_PROGRESS, Memory::Nothing.bytes())
            }
        };
        put(84, &kind.to_le_bytes());
        put(86, &(memory.len() as u16).to_le_bytes());
        put(88, &[memory_kind]);
        out.extend_from_slice(&header);
        out.extend_from_slice(&memory);
    }
}

/// The `N` bytes of `bytes` from `at`.
fn word<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// Puts the program's records into what they tell. The program pairs the entry and return of
/// each call itself, so every record stands alone.
#[derive(Debug)]
pub struct Decoder {
    /// Traced calls by number.
    calls: Vec<Option<Syscall>>,
    before_trace: u64,
    in_progress: u64,
}

impl Decoder {
    /// A decoder for records made on `system`.
    pub fn new(system: System) -> Self {
        let table = codes::table(system);
        let len = table
            .iter()
            .map(|entry| usize::from(entry.syscall.number) + 1)
            .max()
            .unwrap_or(0);
        let mut calls = vec![None; len];
        for entry in table {
            calls[usize::from(entry.syscall.number)] = Some(entry.syscall);
        }
        Self {
            calls,
            before_trace: 0,
            in_progress: 0,
        }
    }

    fn completed(&mut self, call: &RawCall, end_ts: u64) -> Option<Completed> {
        let syscall = usize::try_from(call.number)
            .ok()
            .and_then(|number| self.calls.get(number).copied().flatten())?;
        let failed = (-MAX_ERRNO..0).contains(&call.ret);
        let (errno, rval) = if failed {
            ((-call.ret) as i32, [0, 0])
        } else if let Memory::Fds(fds) = call.memory {
            // Calls such as pipe2 store their descriptors in memory, where kdebug's calls return
            // them in the two return slots.
            (0, fds.map(i32::cast_unsigned))
        } else {
            let ret = call.ret.cast_unsigned();
            (0, [ret as u32, (ret >> 32) as u32])
        };
        let start = call
            .start_ns
            .map(|ts| (ts, [call.args[0], call.args[1], call.args[2], call.args[3]]));
        if start.is_none() {
            self.before_trace += 1;
        }
        Some(Completed {
            call: syscall,
            tid: u64::from(call.tid.cast_unsigned()),
            pid: call.pid,
            start,
            end_ts,
            errno,
            rval,
            lookup: lookup(&call.memory),
        })
    }
}

impl Decode for Decoder {
    type Record = Record;

    fn decode(&mut self, record: &Record) -> Option<Step> {
        let traced = match &record.event {
            Event::Call(call) => Some(Traced::Call(self.completed(call, record.ts)?)),
            Event::Exit { pid } => Some(Traced::ProcExit { pid: *pid }),
            Event::Lost { .. } => Some(Traced::LostEvents),
            Event::InProgress { calls } => {
                self.in_progress = *calls;
                None
            }
        };
        Some(Step {
            ts: record.ts,
            traced,
        })
    }

    fn unfinished_calls(&self) -> u64 {
        self.in_progress
    }

    fn calls_started_before_trace(&self) -> u64 {
        self.before_trace
    }
}

/// The path a call's memory names, as a lookup.
fn lookup(memory: &Memory) -> Option<Lookup> {
    let (path, form) = match memory {
        Memory::Path(path) => (String::from_utf8_lossy(path).into_owned(), PathForm::Passed),
        Memory::Sockaddr(addr) => unix_path(addr)?,
        Memory::Nothing | Memory::Fds(_) => return None,
    };
    (!path.is_empty()).then_some(Lookup {
        path,
        truncated: false,
        vnode: 0,
        form,
    })
}

/// The path in a Unix-domain socket address: a file, or `@` and a name in the abstract
/// namespace, in which NUL bytes are shown as `@` too, as the kernel shows them.
fn unix_path(addr: &[u8]) -> Option<(String, PathForm)> {
    let (family, name) = addr.split_at_checked(2)?;
    if u16::from_le_bytes(word(family, 0)) != AF_UNIX {
        return None;
    }
    if let Some((0, abstract_name)) = name.split_first() {
        let shown: Vec<u8> = abstract_name
            .iter()
            .map(|&b| if b == 0 { b'@' } else { b })
            .collect();
        return Some((
            format!("@{}", String::from_utf8_lossy(&shown)),
            PathForm::Abstract,
        ));
    }
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    Some((
        String::from_utf8_lossy(&name[..end]).into_owned(),
        PathForm::Passed,
    ))
}

#[cfg(test)]
mod tests {
    use super::synth::{Call, Synth, abstract_addr, unix_addr};
    use super::*;

    const SYSTEM: System = System::LinuxAarch64;

    fn call_of(record: &Record) -> &RawCall {
        match &record.event {
            Event::Call(call) => call,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn records_round_trip_through_their_bytes() {
        let mut synth = Synth::new(SYSTEM, 1_000, 10);
        let records = vec![
            synth.open(7, 70, "/etc/hosts", 3),
            synth.call(Call {
                memory: Memory::Fds([4, 5]),
                ..Call::new(7, 70, "pipe2", [0xffff_f000, 0, 0, 0, 0, 0])
            }),
            synth.call(Call {
                memory: Memory::Sockaddr(unix_addr("/run/x.sock")),
                ..Call::new(8, 70, "connect", [6, 0xffff_e000, 14, 0, 0, 0])
            }),
            synth.call(Call {
                entered: false,
                ret: -11,
                ..Call::new(8, 70, "read", [0; 6])
            }),
            synth.exit(70),
            synth.lost(12),
            Record {
                ts: 9_999,
                dropped: 12,
                event: Event::InProgress { calls: 2 },
            },
        ];
        let mut bytes = Vec::new();
        for record in &records {
            record.write(&mut bytes);
        }
        let mut parsed = Vec::new();
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            let (record, len) = Record::parse(rest).unwrap();
            parsed.push(record);
            rest = &rest[len..];
        }
        assert_eq!(parsed, records);
        // The fixed part, then the path without its terminator.
        let mut one = Vec::new();
        records[0].write(&mut one);
        assert_eq!(one.len(), HEADER + "/etc/hosts".len());
        assert_eq!(&one[84..86], &KIND_CALL.to_le_bytes());
        assert_eq!(&one[80..84], &56_u32.to_le_bytes(), "openat on aarch64");
    }

    #[test]
    fn parse_refuses_what_is_not_a_whole_record() {
        let mut bytes = Vec::new();
        Synth::new(SYSTEM, 0, 1).open(1, 1, "/x", 3).write(&mut bytes);
        assert!(Record::parse(&bytes[..HEADER - 1]).is_none());
        assert!(Record::parse(&bytes[..bytes.len() - 1]).is_none());
        let mut unknown = bytes.clone();
        unknown[84] = 9;
        assert!(Record::parse(&unknown).is_none());
        let mut fds = bytes.clone();
        fds[88] = MEMORY_FDS;
        assert!(Record::parse(&fds).is_none(), "two descriptors take 8 bytes");
    }

    #[test]
    fn decodes_calls_with_their_errors_results_and_paths() {
        let mut synth = Synth::new(SYSTEM, 1_000, 10);
        let mut decoder = Decoder::new(SYSTEM);
        let open = synth.open(7, 70, "data.txt", 3);
        let step = decoder.decode(&open).unwrap();
        let Some(Traced::Call(done)) = step.traced else {
            panic!("{step:?}")
        };
        assert_eq!(step.ts, open.ts);
        assert_eq!((done.call.name, done.pid, done.tid), ("openat", 70, 7));
        assert_eq!((done.errno, done.ret_i32(), done.end_ts), (0, 3, open.ts));
        assert_eq!(done.latency_ticks(), Some(10));
        let lookup = done.lookup.unwrap();
        assert_eq!(
            (lookup.path.as_str(), lookup.form),
            ("data.txt", PathForm::Passed)
        );
        assert!(!lookup.is_absolute());

        // A read that failed with EAGAIN, 11 on Linux, and a large one whose count needs both
        // return slots.
        let failed = synth.call(Call {
            ret: -11,
            ..Call::new(7, 70, "read", [3, 0, 10, 0, 0, 0])
        });
        let Some(Traced::Call(done)) = decoder.decode(&failed).unwrap().traced else {
            panic!()
        };
        assert_eq!((done.errno, done.is_ok()), (11, false));
        let big = synth.io(7, 70, "read", 3, 1 << 33, (1 << 32) + 5);
        let Some(Traced::Call(done)) = decoder.decode(&big).unwrap().traced else {
            panic!()
        };
        assert_eq!(done.ret_u64(), (1 << 32) + 5);

        // pipe2 returns its descriptors through memory.
        let pipe = synth.call(Call {
            memory: Memory::Fds([4, 5]),
            ..Call::new(7, 70, "pipe2", [0xffff_f000, 0, 0, 0, 0, 0])
        });
        let Some(Traced::Call(done)) = decoder.decode(&pipe).unwrap().traced else {
            panic!()
        };
        assert_eq!(done.rval, [4, 5]);
        assert_eq!(decoder.calls_started_before_trace(), 0);
    }

    #[test]
    fn socket_addresses_give_unix_paths_only() {
        let lookup_of = |addr: Vec<u8>| lookup(&Memory::Sockaddr(addr));
        let file = lookup_of(unix_addr("/run/dbus/system_bus_socket")).unwrap();
        assert_eq!(
            (file.path.as_str(), file.form),
            ("/run/dbus/system_bus_socket", PathForm::Passed)
        );
        let named = lookup_of(abstract_addr(b"bus\0x")).unwrap();
        assert_eq!((named.path.as_str(), named.form), ("@bus@x", PathForm::Abstract));
        assert!(named.is_absolute());
        // An unnamed socket, and an Internet address.
        assert_eq!(lookup_of(vec![1, 0]), None);
        assert_eq!(lookup_of(vec![2, 0, 0, 80, 127, 0, 0, 1]), None);
        assert_eq!(lookup(&Memory::Path(Vec::new())), None);
    }

    #[test]
    fn decodes_exits_losses_and_what_was_left_running() {
        let mut synth = Synth::new(SYSTEM, 1_000, 10);
        let mut decoder = Decoder::new(SYSTEM);
        assert_eq!(
            decoder.decode(&synth.exit(70)).unwrap().traced,
            Some(Traced::ProcExit { pid: 70 })
        );
        assert_eq!(
            decoder.decode(&synth.lost(3)).unwrap().traced,
            Some(Traced::LostEvents)
        );
        let orphan = synth.call(Call {
            entered: false,
            ..Call::new(7, 70, "read", [0; 6])
        });
        let Some(Traced::Call(done)) = decoder.decode(&orphan).unwrap().traced else {
            panic!()
        };
        assert_eq!((done.start, done.arg(0)), (None, None));
        let left = Record {
            ts: synth.now(),
            dropped: 0,
            event: Event::InProgress { calls: 4 },
        };
        assert_eq!(decoder.decode(&left).unwrap().traced, None);
        assert_eq!(
            (decoder.unfinished_calls(), decoder.calls_started_before_trace()),
            (4, 1)
        );
        // A number iotap does not trace, such as execve's.
        let mut exec = synth.call(Call::new(7, 70, "read", [0; 6]));
        if let Event::Call(call) = &mut exec.event {
            call.number = 221;
        }
        assert_eq!(decoder.decode(&exec), None);
        assert_eq!(call_of(&exec).number, 221);
    }
}
