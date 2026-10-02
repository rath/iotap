//! Optional macOS network measurements. Native callbacks never block the kernel reader.

use std::collections::HashMap;
use std::ffi::{CStr, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::NonNull;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};

use super::time::{self, ClockAnchor, Timebase};
use crate::model::{Endpoint, Proto, Via};
use crate::target::Tracked;
use crate::traffic::{Input, Observation, State, Status};

#[repr(C)]
#[derive(Debug)]
struct NativeSample {
    source: u64,
    started: u64,
    process: u64,
    received: u64,
    sent: u64,
    pid: i32,
    interface: u32,
    protocol: u32,
    flags: u32,
    local: [u8; 28],
    remote: [u8; 28],
}

unsafe extern "C" {
    fn iotap_network_start(
        callback: extern "C" fn(*mut c_void, *const NativeSample),
        context: *mut c_void,
    ) -> *mut c_void;
    fn iotap_network_stop(handle: *mut c_void) -> i32;
    fn iotap_network_process(pid: i32) -> u64;
    #[cfg(test)]
    safe fn iotap_network_sample_size() -> usize;
}

#[derive(Debug)]
struct Context {
    send: SyncSender<Input>,
    targets: Mutex<HashMap<i32, (u64, u64)>>,
    anchor: ClockAnchor,
    timebase: Timebase,
    lost: AtomicBool,
    heartbeat: AtomicU64,
}

extern "C" fn observe(context: *mut c_void, sample: *const NativeSample) {
    // SAFETY: the boxed context stays at a fixed address until stop has drained the native
    // callback queue; the C adapter lends a fully initialized sample for this invocation.
    let (context, sample) = unsafe { (&*context.cast::<Context>(), &*sample) };
    let ticks = time::now_ticks();
    if sample.flags & 2 != 0 {
        context.heartbeat.store(ticks, Ordering::Relaxed);
        return;
    }
    let Ok(targets) = context.targets.lock() else {
        return;
    };
    let Some(&(identity, since_ns)) = targets.get(&sample.pid) else {
        return;
    };
    if identity == 0 || identity != sample.process {
        return;
    }
    drop(targets);
    let mut name = [0; libc::IF_NAMESIZE];
    // SAFETY: name is IF_NAMESIZE writable bytes and if_indextoname only writes within it.
    let found = unsafe { libc::if_indextoname(sample.interface, name.as_mut_ptr()) };
    let interface = if found.is_null() {
        Via::Unknown
    } else {
        // SAFETY: a successful if_indextoname NUL-terminates the name buffer.
        Via::Interface(
            unsafe { CStr::from_ptr(name.as_ptr()) }
                .to_string_lossy()
                .into_owned()
                .into(),
        )
    };
    let input = Input::Observation(Observation {
        time_ns: context.anchor.unix_nanos_at(context.timebase, ticks),
        since_ns,
        started_ns: (sample.started != 0 && sample.started <= ticks)
            .then(|| context.anchor.unix_nanos_at(context.timebase, sample.started)),
        source: sample.source,
        process_id: sample.process,
        pid: sample.pid,
        target: Endpoint {
            proto: if sample.protocol == 6 {
                Proto::Tcp
            } else {
                Proto::Udp
            },
            local: address(&sample.local),
            remote: address(&sample.remote),
            path: None,
        },
        interface,
        received: sample.received,
        sent: sample.sent,
        closed: sample.flags & 1 != 0,
    });
    if context.send.try_send(input).is_err() {
        context.lost.store(true, Ordering::Relaxed);
    }
}

fn address(bytes: &[u8; 28]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = match i32::from(bytes[1]) {
        libc::AF_INET if bytes[0] == 16 => IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
        libc::AF_INET6 if bytes[0] == 28 => {
            let mut address = [0; 16];
            address.copy_from_slice(&bytes[8..24]);
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => return None,
    };
    (port != 0 || !ip.is_unspecified()).then(|| SocketAddr::new(ip, port))
}

#[derive(Debug)]
pub struct Collector {
    handle: Option<NonNull<c_void>>,
    context: Box<Context>,
    receive: Receiver<Input>,
    announced: bool,
    stalled: bool,
    shutdown_incomplete: bool,
}

impl Collector {
    pub fn start(targets: &[Tracked], anchor: ClockAnchor, timebase: Timebase) -> Self {
        let (send, receive) = mpsc::sync_channel(4096);
        let context = Box::new(Context {
            send,
            targets: Mutex::default(),
            anchor,
            timebase,
            lost: AtomicBool::new(false),
            heartbeat: AtomicU64::new(time::now_ticks()),
        });
        let mut collector = Self {
            handle: None,
            context,
            receive,
            announced: false,
            stalled: false,
            shutdown_incomplete: false,
        };
        for target in targets {
            collector.add_pid(target.pid, anchor.unix_nanos);
        }
        let ptr = (&raw mut *collector.context).cast();
        // SAFETY: the context's allocation outlives the native handle and all its callbacks.
        collector.handle = NonNull::new(unsafe { iotap_network_start(observe, ptr) });
        collector
    }

    pub fn add_pid(&self, pid: i32, since_ns: u64) {
        // SAFETY: the shim validates proc_pidinfo's result before returning the identity.
        let identity = unsafe { iotap_network_process(pid) };
        if let Ok(mut targets) = self.context.targets.lock()
            && targets.get(&pid).is_none_or(|&(old, _)| old != identity)
        {
            targets.insert(pid, (identity, since_ns));
        }
    }

    pub fn drain(&mut self) -> Vec<Input> {
        let ticks = time::now_ticks();
        let time_ns = self.context.anchor.unix_nanos_at(self.context.timebase, ticks);
        let mut inputs = Vec::new();
        if !self.announced {
            self.announced = true;
            inputs.push(Input::Status(Status {
                time_ns: self.context.anchor.unix_nanos,
                state: if self.handle.is_some() {
                    State::Active
                } else {
                    State::Unavailable
                },
                reason: self
                    .handle
                    .is_none()
                    .then(|| "macOS network statistics are unavailable; syscall tracing continues".into()),
            }));
            if self.handle.is_none() {
                self.receive.try_iter().for_each(drop);
            }
        }
        if std::mem::take(&mut self.shutdown_incomplete) {
            inputs.push(Input::Status(Status {
                time_ns,
                state: State::Partial,
                reason: Some("the final network statistics query timed out; totals may be incomplete".into()),
            }));
        }
        if self.context.lost.swap(false, Ordering::Relaxed) {
            inputs.push(Input::Status(Status {
                time_ns,
                state: State::Partial,
                reason: Some("network statistics queue overflowed; totals may be incomplete".into()),
            }));
        }
        let since = ticks.saturating_sub(self.context.heartbeat.load(Ordering::Relaxed));
        if self.handle.is_some()
            && !self.stalled
            && self.context.timebase.ticks_to_nanos(since) > 5_000_000_000
        {
            self.stalled = true;
            inputs.push(Input::Status(Status {
                time_ns,
                state: State::Partial,
                reason: Some("macOS network statistics stopped responding; syscall tracing continues".into()),
            }));
        }
        inputs.extend(self.receive.try_iter());
        inputs
    }

    pub fn finish(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: this is the sole owner; stop drains callbacks before returning.
            self.shutdown_incomplete = unsafe { iotap_network_stop(handle.as_ptr()) } != 0;
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_layout_and_process_identity() {
        assert_eq!(std::mem::size_of::<NativeSample>(), iotap_network_sample_size());
        // SAFETY: reading this process's identifier requires no privileges.
        assert_ne!(
            unsafe { iotap_network_process(std::process::id().cast_signed()) },
            0
        );
    }

    #[test]
    fn decodes_only_complete_sockaddrs() {
        let mut bytes = [0; 28];
        assert_eq!(address(&bytes), None);
        bytes[..8].copy_from_slice(&[16, 2, 1, 187, 192, 0, 2, 1]);
        assert_eq!(address(&bytes), Some("192.0.2.1:443".parse().unwrap()));
        bytes[0] = 2;
        assert_eq!(address(&bytes), None);
    }
}
