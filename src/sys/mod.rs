//! Safe wrappers over the kernel and libSystem interfaces iotap needs: the `kern.kdebug`
//! sysctl, mach time, libproc and the small C shim. This is the only module where `unsafe` is
//! allowed; every block states the invariant it relies on.
#![allow(unsafe_code)]

pub mod kdebug;
pub mod time;

/// Returns true when the effective user is root.
pub fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
