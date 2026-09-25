//! Builds records exactly as iotap's eBPF program writes them, so tests and fixtures can
//! exercise the whole pipeline without root.

use std::net::SocketAddr;

use super::{Event, Memory, RawCall, Record, codes};
use crate::trace::System;

/// `AT_FDCWD` on Linux, as a call's argument holds it.
pub const AT_FDCWD: u64 = (-100_i64).cast_unsigned();

/// Emits records `step` nanoseconds apart; each call takes one step from entry to return.
#[derive(Debug)]
pub struct Synth {
    system: System,
    ts: u64,
    step: u64,
}

impl Synth {
    /// Records of `system`, starting after `start_ts`.
    pub fn new(system: System, start_ts: u64, step: u64) -> Self {
        Self {
            system,
            ts: start_ts,
            step: step.max(1),
        }
    }

    /// Time of the most recent record.
    pub fn now(&self) -> u64 {
        self.ts
    }

    /// Leaves a gap of `nanos` before the next record.
    pub fn advance(&mut self, nanos: u64) {
        self.ts += nanos;
    }

    fn next(&mut self) -> u64 {
        self.ts += self.step;
        self.ts
    }

    /// The number of the traced call `name` on the synthesizer's system.
    pub fn number(&self, name: &str) -> u32 {
        match codes::table(self.system).iter().find(|e| e.syscall.name == name) {
            Some(entry) => u32::from(entry.syscall.number),
            None => panic!("{name} is not traced on {:?}", self.system),
        }
    }

    /// A call that returned.
    pub fn call(&mut self, call: Call<'_>) -> Record {
        let start = self.next();
        let end = self.next();
        let entered = call.entered;
        Record {
            ts: end,
            dropped: 0,
            event: Event::Call(RawCall {
                pid: call.pid,
                tid: call.tid,
                number: self.number(call.name),
                start_ns: entered.then_some(start),
                args: if entered { call.args } else { [0; 6] },
                ret: call.ret,
                memory: call.memory,
            }),
        }
    }

    /// `openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC)` returning `fd`.
    pub fn open(&mut self, tid: i32, pid: i32, path: &str, fd: i32) -> Record {
        self.call(Call {
            ret: i64::from(fd),
            memory: Memory::Path(path.as_bytes().to_vec()),
            ..Call::new(tid, pid, "openat", [AT_FDCWD, 0xffff_0000, 0o2_000_000, 0, 0, 0])
        })
    }

    /// Data transfer on `fd` through the call `name`, with the size in the third argument.
    pub fn io(&mut self, tid: i32, pid: i32, name: &str, fd: i32, len: u64, ret: i64) -> Record {
        let fd = u64::from(fd.cast_unsigned());
        self.call(Call {
            ret,
            ..Call::new(tid, pid, name, [fd, 0xffff_8000, len, 0, 0, 0])
        })
    }

    /// `close(fd)`.
    pub fn close(&mut self, tid: i32, pid: i32, fd: i32) -> Record {
        self.call(Call::new(
            tid,
            pid,
            "close",
            [u64::from(fd.cast_unsigned()), 0, 0, 0, 0, 0],
        ))
    }

    /// The last thread of `pid` exited.
    pub fn exit(&mut self, pid: i32) -> Record {
        Record {
            ts: self.next(),
            dropped: 0,
            event: Event::Exit { pid },
        }
    }

    /// The reader's mark that `count` records were lost before the next one.
    pub fn lost(&mut self, count: u64) -> Record {
        Record {
            ts: self.next(),
            dropped: 0,
            event: Event::Lost { count },
        }
    }
}

/// Parameters of [`Synth::call`].
#[derive(Clone, Debug)]
pub struct Call<'a> {
    pub tid: i32,
    pub pid: i32,
    pub name: &'a str,
    pub args: [u64; 6],
    pub ret: i64,
    pub memory: Memory,
    /// The entry was seen; false for a call that began before tracing did.
    pub entered: bool,
}

impl<'a> Call<'a> {
    /// A call that returned 0, with nothing read from memory.
    pub fn new(tid: i32, pid: i32, name: &'a str, args: [u64; 6]) -> Self {
        Self {
            tid,
            pid,
            name,
            args,
            ret: 0,
            memory: Memory::Nothing,
            entered: true,
        }
    }
}

/// A Unix-domain socket address holding `path`, as a process passes it.
pub fn unix_addr(path: &str) -> Vec<u8> {
    let mut addr = vec![1, 0];
    addr.extend_from_slice(path.as_bytes());
    addr.push(0);
    addr
}

/// A Unix-domain socket address naming `name` in the abstract namespace.
pub fn abstract_addr(name: &[u8]) -> Vec<u8> {
    let mut addr = vec![1, 0, 0];
    addr.extend_from_slice(name);
    addr
}

/// An Internet socket address as a process passes it: a `sockaddr_in` or a `sockaddr_in6`.
pub fn inet_addr(addr: SocketAddr) -> Vec<u8> {
    let [port_high, port_low] = addr.port().to_be_bytes();
    let mut out = Vec::new();
    match addr {
        SocketAddr::V4(v4) => {
            out.extend_from_slice(&[2, 0, port_high, port_low]);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&[0; 8]);
        }
        SocketAddr::V6(v6) => {
            out.extend_from_slice(&[10, 0, port_high, port_low]);
            out.extend_from_slice(&v6.flowinfo().to_be_bytes());
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.scope_id().to_le_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_calls_as_the_system_does() {
        let aarch64 = Synth::new(System::LinuxAarch64, 0, 1);
        let x86_64 = Synth::new(System::LinuxX86_64, 0, 1);
        assert_eq!((aarch64.number("openat"), x86_64.number("openat")), (56, 257));
    }

    #[test]
    fn calls_take_a_step_and_leave_out_unseen_entries() {
        let mut synth = Synth::new(System::LinuxAarch64, 100, 10);
        let read = synth.io(1, 2, "read", 3, 64, 64);
        assert_eq!(read.ts, 120);
        let Event::Call(call) = &read.event else { panic!() };
        assert_eq!((call.start_ns, call.args[2]), (Some(110), 64));
        let orphan = synth.call(Call {
            entered: false,
            ..Call::new(1, 2, "read", [3, 0, 64, 0, 0, 0])
        });
        let Event::Call(call) = &orphan.event else {
            panic!()
        };
        assert_eq!((call.start_ns, call.args), (None, [0; 6]));
    }
}
