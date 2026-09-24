//! Safe wrappers over the kernel and libSystem interfaces iotap needs: the `kern.kdebug`
//! sysctl, mach time, libproc and the small C shim. This is the only module where `unsafe` is
//! allowed; every block states the invariant it relies on.
#![allow(unsafe_code)]

pub mod kdebug;
pub mod proc;
pub mod time;
pub mod user;

/// Returns true when the effective user is root.
pub fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The kernel release, such as `24.4.0` (`kern.osrelease`).
pub fn os_release() -> Option<String> {
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
