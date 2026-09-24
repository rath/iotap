//! The record format of the macOS kernel trace facility (kdebug): the `kd_buf` record, its event
//! IDs and syscall table, and how records are put together into calls. Reading the facility is
//! up to `sys::kdebug`; everything here is plain data handling.

pub mod codes;
pub mod decode;
pub mod pairing;
pub mod synth;

use std::mem::size_of;

/// One trace record as the kernel lays it out (`kd_buf` in `sys/kdebug_private.h`, LP64 layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KdBuf {
    /// `mach_absolute_time` ticks.
    pub timestamp: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    /// ID of the thread that emitted the record.
    pub arg5: u64,
    pub debugid: u32,
    pub cpuid: u32,
    pub unused: u64,
}

const _: () = assert!(size_of::<KdBuf>() == KdBuf::SIZE);

impl KdBuf {
    /// Size of one record in bytes.
    pub const SIZE: usize = 64;

    /// Encodes the record in the little-endian layout used by recordings.
    pub fn to_le_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let words = [
            self.timestamp,
            self.arg1,
            self.arg2,
            self.arg3,
            self.arg4,
            self.arg5,
        ];
        for (i, word) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out[48..52].copy_from_slice(&self.debugid.to_le_bytes());
        out[52..56].copy_from_slice(&self.cpuid.to_le_bytes());
        out[56..64].copy_from_slice(&self.unused.to_le_bytes());
        out
    }

    /// Decodes a record produced by [`KdBuf::to_le_bytes`].
    pub fn from_le_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let u64_at = |offset: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(word)
        };
        let u32_at = |offset: usize| {
            let mut word = [0u8; 4];
            word.copy_from_slice(&bytes[offset..offset + 4]);
            u32::from_le_bytes(word)
        };
        Self {
            timestamp: u64_at(0),
            arg1: u64_at(8),
            arg2: u64_at(16),
            arg3: u64_at(24),
            arg4: u64_at(32),
            arg5: u64_at(40),
            debugid: u32_at(48),
            cpuid: u32_at(52),
            unused: u64_at(56),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_bytes_round_trip() {
        let rec = KdBuf {
            timestamp: 0x0102_0304_0506_0708,
            arg1: 1,
            arg2: u64::MAX,
            arg3: 3,
            arg4: 4,
            arg5: 0xdead_beef,
            debugid: 0x040c_000d,
            cpuid: 7,
            unused: 9,
        };
        let bytes = rec.to_le_bytes();
        assert_eq!(bytes[0], 0x08);
        assert_eq!(&bytes[48..52], &0x040c_000d_u32.to_le_bytes());
        assert_eq!(KdBuf::from_le_bytes(&bytes), rec);
    }
}
