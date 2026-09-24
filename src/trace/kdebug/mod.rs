//! The record format of the macOS kernel trace facility (kdebug): the `kd_buf` record, its event
//! IDs and syscall table, and how records are put together into calls. Reading the facility is
//! up to `sys::kdebug`; everything here is plain data handling.

pub mod codes;
pub mod decode;
pub mod pairing;
pub mod synth;

use std::mem::size_of;

use self::decode::Kind;
use self::pairing::{Pairer, PathRecords};
use super::{Decode, Step, Traced};

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

/// Puts kdebug records together: classifies each record and pairs the entry and return of every
/// syscall, with the path looked up in between.
#[derive(Debug)]
pub struct Decoder {
    pairer: Pairer,
}

impl Decoder {
    /// A decoder for a kernel that lays out lookup paths as `paths` says.
    pub fn new(paths: PathRecords) -> Self {
        Self {
            pairer: Pairer::new(paths),
        }
    }
}

impl Decode for Decoder {
    type Record = KdBuf;

    fn decode(&mut self, record: &KdBuf) -> Option<Step> {
        let event = decode::decode(record)?;
        let traced = match event.kind {
            Kind::LostEvents => {
                // The calls in progress lost their ends with the dropped records.
                self.pairer.clear();
                Some(Traced::LostEvents)
            }
            Kind::ProcExit { pid } => Some(Traced::ProcExit { pid }),
            Kind::Syscall(_) | Kind::Lookup => self.pairer.push(&event).map(Traced::Call),
        };
        Some(Step { ts: event.ts, traced })
    }

    fn unfinished_calls(&self) -> u64 {
        self.pairer.orphan_starts()
    }

    fn calls_started_before_trace(&self) -> u64 {
        self.pairer.orphan_ends()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::kdebug::synth::Synth;

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

    #[test]
    fn decoder_reports_calls_exits_and_losses_with_their_times() {
        let mut synth = Synth::new(100, 10);
        let mut decoder = Decoder::new(PathRecords::Whole);
        let read = synth.io(1, 7, 3, 4, 10, 10);
        let start = decoder.decode(&read[0]).unwrap();
        assert_eq!(
            start,
            Step {
                ts: 110,
                traced: None
            }
        );
        let end = decoder.decode(&read[1]).unwrap();
        assert_eq!(end.ts, 120);
        assert!(
            matches!(&end.traced, Some(Traced::Call(done)) if done.pid == 7 && done.ret_u64() == 10),
            "{end:?}"
        );
        let exit = decoder.decode(&synth.proc_exit(1, 7, 0)).unwrap();
        assert_eq!(exit.traced, Some(Traced::ProcExit { pid: 7 }));

        // A call whose return is lost with the dropped records.
        decoder.decode(&synth.syscall_start(2, 3, [4, 0, 10, 0]));
        let lost = decoder.decode(&synth.lost_events()).unwrap();
        assert_eq!(lost.traced, Some(Traced::LostEvents));
        let orphan = decoder.decode(&synth.syscall_end(2, 3, 7, 0, [10, 0])).unwrap();
        assert!(matches!(&orphan.traced, Some(Traced::Call(done)) if done.start.is_none()));
        assert_eq!(
            (decoder.unfinished_calls(), decoder.calls_started_before_trace()),
            (1, 1)
        );
        // A record of a class iotap does not use.
        assert_eq!(decoder.decode(&KdBuf::default()), None);
    }
}
