//! User accounts.

use std::ffi::{CStr, OsStr, c_char};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Largest buffer offered to `getpwuid_r`; directory services never need this much.
const MAX_BUFFER: usize = 1 << 20;

/// A user account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    /// Primary group.
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Looks up the account of `uid`.
pub fn by_uid(uid: u32) -> Option<User> {
    let mut buf = vec![0_u8; 4096];
    loop {
        // SAFETY: `passwd` is plain data (integers and nullable pointers); all-zero is a valid
        // value.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry` and `found` are live locals, and `buf` holds `buf.len()` writable
        // bytes for the strings the entry points into.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut entry,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &raw mut found,
            )
        };
        if rc == libc::ERANGE && buf.len() < MAX_BUFFER {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() {
            return None;
        }
        return Some(User {
            uid,
            gid: entry.pw_gid,
            // SAFETY: on success the entry's strings are null or NUL-terminated within `buf`,
            // which is alive and unchanged here.
            name: String::from_utf8_lossy(unsafe { c_bytes(entry.pw_name) }).into_owned(),
            // SAFETY: as above.
            home: PathBuf::from(OsStr::from_bytes(unsafe { c_bytes(entry.pw_dir) })),
        });
    }
}

/// The user who started iotap: the one sudo ran it for, else the real user.
pub fn invoking() -> Option<User> {
    let sudo = if super::is_root() {
        std::env::var("SUDO_UID").ok().and_then(|uid| uid.parse().ok())
    } else {
        None
    };
    // SAFETY: `getuid` has no preconditions and cannot fail.
    by_uid(sudo.unwrap_or_else(|| unsafe { libc::getuid() }))
}

/// The bytes of a C string, or none for a null pointer.
///
/// # Safety
///
/// `ptr` must be null or point to a NUL-terminated string that outlives the result.
unsafe fn c_bytes<'a>(ptr: *const c_char) -> &'a [u8] {
    if ptr.is_null() {
        return &[];
    }
    // SAFETY: the caller guarantees a NUL-terminated string that outlives the result.
    unsafe { CStr::from_ptr(ptr) }.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_accounts() {
        let root = by_uid(0).unwrap();
        assert_eq!((root.name.as_str(), root.gid), ("root", 0));
        // SAFETY: `getuid` has no preconditions and cannot fail.
        let me = by_uid(unsafe { libc::getuid() }).unwrap();
        assert!(!me.name.is_empty());
        if let Ok(home) = std::env::var("HOME") {
            assert_eq!(me.home, PathBuf::from(home));
        }
        if !crate::sys::is_root() {
            assert_eq!(invoking(), Some(me));
        }
        assert_eq!(by_uid(3_999_999_999), None);
    }
}
