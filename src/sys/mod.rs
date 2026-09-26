//! Safe wrappers over the kernel and system interfaces iotap needs: on macOS the `kern.kdebug`
//! and `kern.procargs2` sysctls, mach time, libproc and a small C shim; on Linux iotap's eBPF
//! program, the ring buffer it writes, and `/proc`; on both the system's resolver for host names
//! and the list of network interfaces. This is the only module where `unsafe` is allowed; every
//! block states the invariant it relies on.
#![allow(unsafe_code)]

pub mod dns;
#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "macos")]
pub mod kdebug;
pub mod net;
pub mod proc;
pub mod time;
pub mod user;

/// The kernel trace facility of this system, the same to use on each: `start` and
/// `path_records`, the [`Tracer`](crate::reader::Tracer) methods, and a `NotPermitted` error.
#[cfg(target_os = "linux")]
pub use ebpf::{Ebpf as Facility, EbpfError as FacilityError};
#[cfg(target_os = "macos")]
pub use kdebug::{Kdebug as Facility, KdebugError as FacilityError};

/// Returns true when the effective user is root.
pub fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Gives the trace facility back if this process holds it, for exits that skip destructors.
/// Safe to call from signal and panic hooks.
pub fn release() {
    #[cfg(target_os = "macos")]
    kdebug::release();
    // On Linux the kernel detaches iotap's programs as its descriptors close, which any exit
    // does.
}
