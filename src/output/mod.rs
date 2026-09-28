//! Output formats and the formatting helpers they share.

use std::borrow::Cow;

pub mod json;
pub mod text;

/// `text` with each control character written as `?`. Names and paths come from the traced
/// programs, which choose them freely, and are printed on a terminal, where an escape sequence
/// in one would act on it and a line feed would forge a line of output. JSON keeps them whole:
/// it escapes them.
pub fn printable(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_control) {
        Cow::Owned(
            text.chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

/// Human-readable size with binary units rounded to one decimal, e.g. `4.0 MiB`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut unit: u128 = 1024;
    let mut index = 0;
    loop {
        let tenths = (u128::from(n) * 10 + unit / 2) / unit;
        // Rounding may carry into the next unit, e.g. 1023.99 KiB is shown as 1.0 MiB.
        if tenths < 10_240 || index + 1 == UNITS.len() {
            return format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[index]);
        }
        unit *= 1024;
        index += 1;
    }
}

/// Duration with one decimal of seconds, e.g. `12.4 s`.
pub fn duration(ns: u64) -> String {
    let tenths = ns / 100_000_000;
    format!("{}.{} s", tenths / 10, tenths % 10)
}

/// Syscall latency in milliseconds with microsecond precision, e.g. `0.052 ms`.
pub fn latency(ns: u64) -> String {
    let micros = ns / 1_000;
    format!("{}.{:03} ms", micros / 1_000, micros % 1_000)
}

/// Plural-aware count, e.g. `1 call`, `3 calls`.
pub fn count(n: u64, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_written_as_question_marks() {
        assert!(matches!(
            printable("/tmp/page.html"),
            Cow::Borrowed("/tmp/page.html")
        ));
        assert!(matches!(printable("Übersicht 한글 ❤️"), Cow::Borrowed(_)));
        assert_eq!(printable("/tmp/a\nFORGED"), "/tmp/a?FORGED");
        assert_eq!(printable("x\x1b[31m\x1b]0;title\x07y"), "x?[31m?]0;title?y");
        // Both ends of the C0 range, DEL, and the C1 range, where 0x9b is CSI.
        assert_eq!(printable("\0\x1f\x7f\u{80}\u{9b}\u{9f}"), "??????");
        assert_eq!(printable("tab\there\r"), "tab?here?");
    }

    #[test]
    fn formats_sizes_and_times() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(1535), "1.5 KiB");
        assert_eq!(bytes(1_048_575), "1.0 MiB");
        assert_eq!(bytes(4 * 1024 * 1024), "4.0 MiB");
        assert_eq!(bytes(u64::MAX), "16384.0 PiB");
        assert_eq!(duration(12_449_000_000), "12.4 s");
        assert_eq!(latency(52_345), "0.052 ms");
        assert_eq!(latency(1_234_567_890), "1234.567 ms");
        assert_eq!(count(1, "call"), "1 call");
        assert_eq!(count(2, "call"), "2 calls");
    }
}
