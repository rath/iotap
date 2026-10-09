//! Trace time conversion and local wall-clock formatting.
//!
//! Trace time is the clock the kernel stamps records with: `mach_absolute_time` ticks on
//! macOS, `CLOCK_MONOTONIC` nanoseconds on Linux.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Ratio that converts trace time ticks to nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timebase {
    pub numer: u32,
    pub denom: u32,
}

impl Timebase {
    /// The timebase of this machine.
    pub fn host() -> Self {
        let (numer, denom) = clock::timebase();
        if numer == 0 || denom == 0 {
            return Self { numer: 1, denom: 1 };
        }
        Self { numer, denom }
    }

    pub fn ticks_to_nanos(self, ticks: u64) -> u64 {
        let nanos = u128::from(ticks) * u128::from(self.numer) / u128::from(self.denom.max(1));
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    pub fn nanos_to_ticks(self, nanos: u64) -> u64 {
        let ticks = u128::from(nanos) * u128::from(self.denom) / u128::from(self.numer.max(1));
        u64::try_from(ticks).unwrap_or(u64::MAX)
    }
}

#[cfg(target_os = "macos")]
mod clock {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    // Declared here because the `libc` crate deprecates its mach bindings.
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
        safe fn mach_absolute_time() -> u64;
        safe fn mach_continuous_time() -> u64;
    }

    /// The mach timebase; zeros if it cannot be read.
    pub(super) fn timebase() -> (u32, u32) {
        let mut info = MachTimebaseInfo::default();
        // SAFETY: `info` is a valid, writable `mach_timebase_info` structure.
        let rc = unsafe { mach_timebase_info(&raw mut info) };
        if rc == 0 { (info.numer, info.denom) } else { (0, 0) }
    }

    pub(super) fn now() -> u64 {
        mach_absolute_time()
    }

    /// Trace time of a `mach_continuous_time` reading. That clock runs on while the machine
    /// sleeps, where trace time stands still, so it is ahead of trace time by the time slept
    /// since boot. Trace time is read first: read after, the continuous clock can only be
    /// further ahead, so the result never comes after a trace time read afterwards.
    pub(super) fn from_continuous(continuous: u64) -> u64 {
        let absolute = mach_absolute_time();
        let ahead = mach_continuous_time().saturating_sub(absolute);
        continuous.saturating_sub(ahead)
    }

    #[cfg(test)]
    pub(super) fn continuous_now() -> u64 {
        mach_continuous_time()
    }
}

#[cfg(target_os = "linux")]
mod clock {
    /// Ticks are nanoseconds.
    pub(super) fn timebase() -> (u32, u32) {
        (1, 1)
    }

    /// `CLOCK_MONOTONIC`, the clock `bpf_ktime_get_ns` reads.
    pub(super) fn now() -> u64 {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `now` is a valid, writable `timespec`. The monotonic clock always exists, so
        // the call cannot fail.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
        let secs = u64::try_from(now.tv_sec).unwrap_or(0);
        let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
        secs.saturating_mul(1_000_000_000).saturating_add(nanos)
    }
}

/// A trace time and the wall-clock time read at the same moment, used to place trace
/// timestamps on the wall clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockAnchor {
    pub ticks: u64,
    pub unix_nanos: u64,
}

impl ClockAnchor {
    pub fn now() -> Self {
        let ticks = clock::now();
        let unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        Self { ticks, unix_nanos }
    }

    /// Wall-clock time, in nanoseconds since the Unix epoch, of a trace timestamp.
    pub fn unix_nanos_at(self, timebase: Timebase, ticks: u64) -> u64 {
        if ticks >= self.ticks {
            self.unix_nanos
                .saturating_add(timebase.ticks_to_nanos(ticks - self.ticks))
        } else {
            self.unix_nanos
                .saturating_sub(timebase.ticks_to_nanos(self.ticks - ticks))
        }
    }
}

/// The trace time now.
pub fn now_ticks() -> u64 {
    clock::now()
}

/// The trace time of a `mach_continuous_time` reading, such as the connection start times the
/// kernel's network statistics give; never after a [`now_ticks`] taken afterwards.
#[cfg(target_os = "macos")]
pub fn ticks_from_continuous(continuous: u64) -> u64 {
    clock::from_continuous(continuous)
}

/// Formats Unix timestamps as local `HH:MM:SS.uuuuuu`, caching the conversion per second.
#[derive(Debug, Default)]
pub struct LocalClock {
    cached: Option<(u64, String)>,
}

impl LocalClock {
    pub fn format(&mut self, unix_nanos: u64) -> String {
        let secs = unix_nanos / 1_000_000_000;
        let micros = (unix_nanos % 1_000_000_000) / 1_000;
        let hms = match &self.cached {
            Some((cached_secs, hms)) if *cached_secs == secs => hms.clone(),
            _ => {
                let hms = local_hms(secs);
                self.cached = Some((secs, hms.clone()));
                hms
            }
        };
        format!("{hms}.{micros:06}")
    }
}

fn local_hms(secs: u64) -> String {
    let Ok(time) = libc::time_t::try_from(secs) else {
        return "??:??:??".to_owned();
    };
    // SAFETY: `tm` is plain data (integers and a nullable pointer); all-zero is a valid value.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers refer to live locals for the duration of the call.
    let converted = unsafe { !libc::localtime_r(&raw const time, &raw mut tm).is_null() };
    if converted {
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    } else {
        let day = secs % 86_400;
        format!("{:02}:{:02}:{:02}", day / 3_600, day / 60 % 60, day % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn continuous_time_maps_onto_trace_time() {
        let converted = ticks_from_continuous(clock::continuous_now());
        let now = now_ticks();
        assert!(converted <= now, "{converted} is after {now}");
        let tolerance = Timebase::host().nanos_to_ticks(100_000_000);
        assert!(now - converted < tolerance, "{now} - {converted} >= {tolerance}");
    }

    #[test]
    fn converts_apple_silicon_ticks() {
        let tb = Timebase { numer: 125, denom: 3 };
        assert_eq!(tb.ticks_to_nanos(24_000_000), 1_000_000_000);
        assert_eq!(tb.nanos_to_ticks(1_000_000_000), 24_000_000);
    }

    #[test]
    fn anchor_places_earlier_and_later_ticks() {
        let tb = Timebase { numer: 1, denom: 1 };
        let anchor = ClockAnchor {
            ticks: 1_000,
            unix_nanos: 5_000,
        };
        assert_eq!(anchor.unix_nanos_at(tb, 1_500), 5_500);
        assert_eq!(anchor.unix_nanos_at(tb, 400), 4_400);
    }

    #[test]
    fn local_clock_has_fixed_width() {
        let mut clock = LocalClock::default();
        let text = clock.format(1_790_000_000_123_456_789);
        assert_eq!(text.len(), 15, "{text}");
        assert!(text.ends_with(".123456"), "{text}");
        assert_eq!(clock.format(1_790_000_000_999_999_999).len(), 15);
    }

    #[test]
    fn host_timebase_is_sane() {
        let tb = Timebase::host();
        assert!(tb.numer > 0 && tb.denom > 0);
        assert!(now_ticks() > 0);
    }
}
