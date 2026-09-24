//! The details panel: everything known about the target of the selected row.

use std::collections::HashMap;
use std::fs::{self, FileType};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::SystemTime;

use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::draw::{BOLD, DIM, FAILED, idle, short_latency};
use super::state::{Shown, Tab, View};
use crate::model::{Category, IoEvent};
use crate::output::{bytes, count, text};
use crate::stats::{Counter, Key, Peer, Row};
use crate::sys::user;

/// Columns taken by the labels.
const LABEL: usize = 10;
/// Most recent events shown for the target.
const RECENT: usize = 5;

/// The panel's lines for `key`, whose row is `row`, in `width` columns.
pub(super) fn lines(
    key: &Key,
    row: &Row,
    width: usize,
    view: &mut View,
    shown: &Shown<'_>,
) -> Vec<Line<'static>> {
    let value_width = width.saturating_sub(LABEL);
    let mut lines: Vec<Line<'static>> = wrap_path(&key.to_string(), width)
        .into_iter()
        .map(|piece| Line::styled(piece, BOLD))
        .collect();

    let [read, written] = if key.category() == Category::Network {
        ["received", "sent"]
    } else {
        ["read", "written"]
    };
    let moved = |counter: Counter| format!("{} in {}", bytes(counter.bytes), count(counter.calls, "call"));
    let mut totals = vec![
        Span::raw(moved(row.read)),
        Span::styled(format!("   {written} "), DIM),
        Span::raw(moved(row.write)),
        Span::styled("   failed ", DIM),
        Span::raw(row.errors.to_string()),
    ];
    if row.messages > 0 {
        totals.push(Span::raw(format!("   {}", count(row.messages, "message"))));
    }
    if row.unsized_calls > 0 {
        totals.push(Span::raw(format!(
            "   {} of unknown size",
            count(row.unsized_calls, "call")
        )));
    }
    lines.push(field(read, totals));

    let latency = match row.latency.mean_ns() {
        Some(mean) => format!(
            "{} on average, {} at most",
            short_latency(mean),
            short_latency(row.latency.max_ns)
        ),
        None => "not timed".to_owned(),
    };
    lines.push(field("latency", vec![Span::raw(latency)]));

    let mut first = view.clock.format(row.first_ns);
    first.truncate(8);
    let last = idle(shown.now_ns.saturating_sub(row.last_ns));
    lines.push(field(
        "used",
        vec![Span::raw(format!("first at {first}, last {last} ago"))],
    ));

    let processes: Vec<String> = row
        .pids()
        .iter()
        .map(
            |&pid| match shown.processes.binary_search_by_key(&pid, |process| process.pid) {
                Ok(i) => format!("{pid} {}", shown.processes[i].name),
                Err(_) => pid.to_string(),
            },
        )
        .collect();
    lines.push(field(
        "processes",
        vec![Span::raw(fit_list(&processes, value_width))],
    ));

    if let Some(path) = path_of(key).filter(|path| path.starts_with('/')) {
        let now = describe_file(Path::new(path), SystemTime::now(), &mut view.owners);
        lines.push(field("file", vec![Span::raw(now)]));
    }
    if let Key::Socket {
        peer: Peer::Remote(_),
        ..
    } = key
        && !row.locals().is_empty()
    {
        let locals: Vec<String> = row.locals().iter().map(ToString::to_string).collect();
        lines.push(field("local", vec![Span::raw(fit_list(&locals, value_width))]));
    }

    if view.tabs.contains(&Tab::Events) {
        let ring = shown.events;
        let mut recent: Vec<&IoEvent> = ring
            .range(ring.first(), ring.end())
            .rev()
            .filter(|event| key.matches(&event.target))
            .take(RECENT)
            .collect();
        recent.reverse();
        if recent.is_empty() {
            lines.push(field(
                "recent",
                vec![Span::styled("none among the events kept", DIM)],
            ));
        }
        for (i, event) in recent.into_iter().enumerate() {
            let label = if i == 0 { "recent" } else { "" };
            lines.push(field(label, event_spans(event, view)));
        }
    }
    lines
}

/// The path a key names, for files and Unix-domain sockets.
fn path_of(key: &Key) -> Option<&str> {
    match key {
        Key::File(path)
        | Key::Socket {
            peer: Peer::Path(path),
            ..
        } => Some(path),
        _ => None,
    }
}

fn field(label: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let width = LABEL;
    let mut spans = vec![Span::styled(format!("{label:<width$}"), DIM)];
    spans.extend(value);
    Line::from(spans)
}

/// One recent event: time, process, call, result and latency.
fn event_spans(event: &IoEvent, view: &mut View) -> Vec<Span<'static>> {
    let [mut time, pid, op, _, _, result, _, _] = text::event_fields(event, &mut view.clock);
    time.truncate(12);
    let latency = event.latency_ns.map_or_else(|| "-".to_owned(), short_latency);
    let result = Span::raw(format!("{result:>11}"));
    vec![
        Span::raw(format!("{time}  {pid:>5}  {op:<13} ")),
        if event.is_ok() {
            result
        } else {
            result.style(FAILED)
        },
        Span::raw(format!("  {latency:>7}")),
    ]
}

/// What `path` is at `now` as `lstat` sees it: kind, size, age, permissions and owner. Only
/// metadata is read, never the contents.
fn describe_file(path: &Path, now: SystemTime, owners: &mut HashMap<u32, Option<String>>) -> String {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return "no longer exists".to_owned(),
        Err(err) => return format!("cannot be examined: {err}"),
    };
    let file_type = meta.file_type();
    let mut parts = vec![if file_type.is_symlink() {
        match fs::read_link(path) {
            Ok(to) => format!("symbolic link to {}", to.display()),
            Err(_) => "symbolic link".to_owned(),
        }
    } else {
        kind(file_type).to_owned()
    }];
    if file_type.is_file() {
        parts.push(bytes(meta.len()));
    }
    if let Ok(modified) = meta.modified() {
        let age = now.duration_since(modified).unwrap_or_default();
        let age = u64::try_from(age.as_nanos()).unwrap_or(u64::MAX);
        parts.push(format!("modified {} ago", idle(age)));
    }
    let uid = meta.uid();
    let owner = owners
        .entry(uid)
        .or_insert_with(|| user::by_uid(uid).map(|account| account.name))
        .clone()
        .unwrap_or_else(|| uid.to_string());
    parts.push(format!("{} {owner}", permissions(meta.mode(), file_type)));
    parts.join(", ")
}

fn kind(file_type: FileType) -> &'static str {
    if file_type.is_file() {
        "regular file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symbolic link"
    } else if file_type.is_char_device() {
        "character device"
    } else if file_type.is_block_device() {
        "block device"
    } else if file_type.is_fifo() {
        "named pipe"
    } else if file_type.is_socket() {
        "socket"
    } else {
        "file of an unknown kind"
    }
}

/// Permissions as `ls -l` shows them, e.g. `-rw-r--r--`.
fn permissions(mode: u32, file_type: FileType) -> String {
    let mut out = String::with_capacity(10);
    out.push(if file_type.is_dir() {
        'd'
    } else if file_type.is_symlink() {
        'l'
    } else if file_type.is_char_device() {
        'c'
    } else if file_type.is_block_device() {
        'b'
    } else if file_type.is_fifo() {
        'p'
    } else if file_type.is_socket() {
        's'
    } else {
        '-'
    });
    // Owner, group and others, each with the bit that changes how its execute bit shows.
    for (shift, special, set) in [(6, 0o4000, 's'), (3, 0o2000, 's'), (0, 0o1000, 't')] {
        let bits = (mode >> shift) & 0o7;
        out.push(if bits & 0o4 == 0 { '-' } else { 'r' });
        out.push(if bits & 0o2 == 0 { '-' } else { 'w' });
        out.push(match (mode & special != 0, bits & 0o1 != 0) {
            (true, true) => set,
            (true, false) => set.to_ascii_uppercase(),
            (false, true) => 'x',
            (false, false) => '-',
        });
    }
    out
}

/// `path` in lines of at most `width` columns, broken after a slash where one falls; a name
/// longer than a line is broken where the line is full.
fn wrap_path(path: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if width == 0 {
        return lines;
    }
    let mut line = String::new();
    let mut used = 0;
    for piece in path.split_inclusive('/') {
        let piece_width = piece.width();
        if used + piece_width <= width {
            line.push_str(piece);
            used += piece_width;
            continue;
        }
        if piece_width <= width {
            lines.push(std::mem::replace(&mut line, piece.to_owned()));
            used = piece_width;
            continue;
        }
        for c in piece.chars() {
            let char_width = c.width().unwrap_or(0);
            if used + char_width > width && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                used = 0;
            }
            line.push(c);
            used += char_width;
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// `items` separated by commas, as many as fit in `width` columns, then how many did not.
fn fit_list(items: &[String], width: usize) -> String {
    let mut out = String::new();
    for (i, item) in items.iter().enumerate() {
        let joined = if i == 0 {
            item.clone()
        } else {
            format!("{out}, {item}")
        };
        let left = items.len() - i - 1;
        let more = if left > 0 {
            format!(", and {left} more")
        } else {
            String::new()
        };
        if i > 0 && joined.width() + more.width() > width {
            return format!("{out}, and {} more", items.len() - i);
        }
        out = joined;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn wraps_paths_after_slashes() {
        assert_eq!(wrap_path("/a/bb/ccc", 5), ["/a/", "bb/", "ccc"]);
        assert_eq!(wrap_path("/a/bb/ccc", 9), ["/a/bb/ccc"]);
        assert_eq!(wrap_path("/abcdefgh", 4), ["/abc", "defg", "h"]);
        assert_eq!(wrap_path("/데이터/파일", 6), ["/데이", "터/", "파일"]);
        assert_eq!(wrap_path("", 4), [""]);
        assert!(wrap_path("/a", 0).is_empty());
    }

    #[test]
    fn lists_what_fits_and_counts_the_rest() {
        let items: Vec<String> = ["1 a", "2 bb", "3 cccccccccccccccc"].map(String::from).to_vec();
        assert_eq!(fit_list(&items, 40), "1 a, 2 bb, 3 cccccccccccccccc");
        assert_eq!(fit_list(&items, 20), "1 a, and 2 more");
        assert_eq!(fit_list(&items, 25), "1 a, 2 bb, and 1 more");
        assert_eq!(
            fit_list(&items, 2),
            "1 a, and 2 more",
            "the first item always shows"
        );
        assert_eq!(fit_list(&[], 10), "");
    }

    #[test]
    fn shows_permissions_as_ls_does() {
        let dir = fs::symlink_metadata("/").unwrap().file_type();
        assert_eq!(permissions(0o755, dir), "drwxr-xr-x");
        let file = fs::symlink_metadata("/private/etc/hosts").unwrap().file_type();
        assert_eq!(permissions(0o644, file), "-rw-r--r--");
        assert_eq!(permissions(0o4755, file), "-rwsr-xr-x");
        assert_eq!(permissions(0o2744, file), "-rwxr-Sr--");
        assert_eq!(permissions(0o1777, file), "-rwxrwxrwt");
        assert_eq!(permissions(0o1776, file), "-rwxrwxrwT");
    }

    #[test]
    fn describes_files_as_they_are_now() {
        let dir = std::env::temp_dir().join(format!("iotap-details-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        fs::write(&path, [0_u8; 2048]).unwrap();
        let two_hours = Duration::from_hours(2);
        let modified = SystemTime::now() - two_hours;
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        let mut owners = HashMap::new();
        let now = modified + two_hours + Duration::from_secs(30);
        let described = describe_file(&path, now, &mut owners);
        let me = user::by_uid(fs::metadata(&path).unwrap().uid()).unwrap().name;
        assert!(
            described.starts_with("regular file, 2.0 KiB, modified 2h ago, -rw")
                && described.ends_with(&format!(" {me}")),
            "{described}"
        );
        assert_eq!(owners.len(), 1, "owner names are cached");

        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let described = describe_file(&link, now, &mut owners);
        assert!(
            described.starts_with(&format!("symbolic link to {}, modified", path.display())),
            "{described}"
        );
        assert!(describe_file(Path::new("/dev/null"), now, &mut owners).starts_with("character device, "));
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(describe_file(&path, now, &mut owners), "no longer exists");
    }
}
