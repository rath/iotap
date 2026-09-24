//! Draws one frame of the terminal UI.

use std::borrow::Cow;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Tabs};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::state::{Drawn, Shown, Tab, View};
use crate::output::{bytes, count, text};
use crate::stats::{self, Key, Second, SortBy};

const BOLD: Style = Style::new().add_modifier(Modifier::BOLD);
const DIM: Style = Style::new().fg(Color::DarkGray);
const FAILED: Style = Style::new().fg(Color::Red);
const SORTED: Style = Style::new()
    .fg(Color::Cyan)
    .add_modifier(Modifier::BOLD)
    .add_modifier(Modifier::UNDERLINED);
const TITLE: Style = Style::new()
    .add_modifier(Modifier::BOLD)
    .add_modifier(Modifier::REVERSED);
const SELECTED_TAB: Style = TITLE;
const SELECTED_ROW: Style = Style::new().add_modifier(Modifier::REVERSED);
const WARNING: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
const BANNER: Style = Style::new().fg(Color::Black).bg(Color::Yellow);
const BADGE: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Yellow)
    .add_modifier(Modifier::BOLD);

/// Space between table columns, and on screens narrower than [`NARROW`].
const SPACING: u16 = 2;
const NARROW_SPACING: u16 = 1;
/// Tables narrower than this pack their columns tighter.
const NARROW: u16 = 99;
/// Events tables at least this wide also show the requested size.
const WIDE: u16 = 119;
/// Processes named in the title line; the rest are only counted.
const TITLE_PROCESSES: usize = 32;

pub fn draw(frame: &mut Frame<'_>, view: &mut View, shown: &Shown<'_>) {
    let alerts = alerts(shown);
    let [title, rates, alert_area, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(u16::try_from(alerts.len()).unwrap_or(u16::MAX)),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_title(frame, title, shown);
    draw_rates(frame, rates, shown);
    frame.render_widget(Paragraph::new(alerts), alert_area);
    // Tables start one column in, like the lines above them.
    let [_, body] = Layout::horizontal([Constraint::Length(1), Constraint::Fill(1)]).areas(body);
    let position = match view.tab {
        Tab::Files | Tab::Network => draw_targets(frame, body, view, shown),
        Tab::Events => draw_events(frame, body, view, shown),
    };
    draw_tabs(frame, tabs, view, shown, position);
    draw_footer(frame, footer, view, shown);
}

fn draw_title(frame: &mut Frame<'_>, area: Rect, shown: &Shown<'_>) {
    let mut elapsed = clock(shown.now_ns.saturating_sub(shown.start_ns));
    if shown.reset {
        elapsed.push_str(" since reset");
    }
    let [left, right] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(width(&elapsed) + 1)]).areas(area);
    let mut spans = vec![Span::styled(" iotap ", TITLE), Span::raw(" ")];
    let processes = &shown.processes;
    if processes.len() > 1 {
        let running = processes.iter().filter(|p| p.alive).count();
        spans.push(Span::raw(format!(
            "{} processes, {running} running: ",
            processes.len()
        )));
    }
    let ordered = processes
        .iter()
        .filter(|p| p.alive)
        .chain(processes.iter().filter(|p| !p.alive));
    for (i, process) in ordered.take(TITLE_PROCESSES).enumerate() {
        if i > 0 {
            spans.push(Span::raw(", "));
        }
        let label = format!("{} {}", process.pid, process.name);
        spans.push(if process.alive {
            Span::raw(label)
        } else {
            Span::styled(format!("{label} (exited)"), DIM)
        });
    }
    if processes.len() > TITLE_PROCESSES {
        spans.push(Span::raw(", …"));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), left);
    frame.render_widget(Paragraph::new(Line::from(elapsed).right_aligned()), right);
}

/// Bytes per second over the last complete second, and totals so far.
fn draw_rates(frame: &mut Frame<'_>, area: Rect, shown: &Shown<'_>) {
    let second = last_second(shown);
    let totals = shown.stats.totals();
    let filter = shown.filter;
    let value = |traced: bool, n: u64| {
        if traced {
            right(bytes(n))
        } else {
            right("–".to_owned()).style(DIM)
        }
    };
    let header = Row::new([
        Cell::from(""),
        right("FILE READ".to_owned()),
        right("FILE WRITTEN".to_owned()),
        right("NET RECEIVED".to_owned()),
        right("NET SENT".to_owned()),
    ])
    .style(BOLD);
    let rows = [
        Row::new([
            Cell::from(" per second"),
            value(filter.files, second.file_read),
            value(filter.files, second.file_write),
            value(filter.network, second.net_read),
            value(filter.network, second.net_write),
        ]),
        Row::new([
            Cell::from(" total"),
            value(filter.files, totals.file_read.bytes),
            value(filter.files, totals.file_write.bytes),
            value(filter.network, totals.net_read.bytes),
            value(filter.network, totals.net_write.bytes),
        ]),
    ];
    let widths = [
        Constraint::Length(11),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    frame.render_widget(
        Table::new(rows, widths).header(header).column_spacing(SPACING),
        area,
    );
}

fn alerts(shown: &Shown<'_>) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(reason) = shown.ended {
        lines.push(Line::styled(
            format!(" {reason} Press q for the summary. "),
            BANNER,
        ));
    }
    if shown.lost_events > 0 {
        lines.push(Line::styled(
            format!(
                " The kernel dropped records {}; totals are incomplete (raise --buffer).",
                count(shown.lost_events, "time")
            ),
            WARNING,
        ));
    }
    lines
}

fn draw_tabs(frame: &mut Frame<'_>, area: Rect, view: &View, shown: &Shown<'_>, position: String) {
    let stats = shown.stats;
    let titles = view.tabs.iter().enumerate().map(|(i, &tab)| {
        let (name, count) = match tab {
            Tab::Files => ("Files", tab.rows(stats) as u64),
            Tab::Network => ("Network", tab.rows(stats) as u64),
            Tab::Events => ("Events", shown.events.end()),
        };
        format!("{} {name} ({})", i + 1, grouped(count))
    });
    let mut spans = Vec::new();
    if !position.is_empty() {
        spans.push(Span::styled(position, DIM));
        spans.push(Span::raw("  "));
    }
    if view.tab != Tab::Events {
        spans.push(Span::raw(format!("sort: {} ", view.sort.label())));
    }
    if shown.paused {
        spans.push(Span::styled(" PAUSED ", BADGE));
    }
    let indicators = Line::from(spans).right_aligned();
    let [left, right] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width_of_line(&indicators)),
    ])
    .areas(area);
    let tabs = Tabs::new(titles)
        .select(view.position())
        .highlight_style(SELECTED_TAB)
        .divider(" ");
    frame.render_widget(tabs, left);
    frame.render_widget(Paragraph::new(indicators), right);
}

/// Draws the Files or Network table, scrolled so the selected row shows; returns which rows
/// are visible, when not all fit.
fn draw_targets(frame: &mut Frame<'_>, area: Rect, view: &mut View, shown: &Shown<'_>) -> String {
    let tab = view.tab;
    let files = tab == Tab::Files;
    let stats = shown.stats;
    let total = tab.rows(stats);
    let (traced, words) = if files {
        (shown.filter.files || shown.filter.other, ["READ", "WRITTEN"])
    } else {
        (shown.filter.network, ["RECEIVED", "SENT"])
    };
    let page = usize::from(area.height.saturating_sub(1));
    let index = tab.index();
    let selected = view.selected_rank(stats);
    let mut offset = view.offsets[index].min(total.saturating_sub(page));
    if selected < offset {
        offset = selected;
    } else if page > 0 && selected >= offset + page {
        offset = selected + 1 - page;
    }
    view.offsets[index] = offset;
    view.drawn = Drawn {
        page,
        ..Drawn::default()
    };
    if total == 0 {
        let message = match (files, traced) {
            (true, true) => "No file I/O yet.",
            (true, false) => "File I/O is not traced.",
            (false, true) => "No network I/O yet.",
            (false, false) => "Network I/O is not traced.",
        };
        frame.render_widget(Paragraph::new(Line::styled(format!(" {message}"), DIM)), area);
        return String::new();
    }
    let rows = stats.page(|category| tab.lists(category), view.sort, offset, page);

    let widths = [
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(4),
        Constraint::Fill(1),
    ];
    let spacing = spacing(area.width);
    let target_width = usize::from(area.width).saturating_sub(fixed_width(&widths, spacing));
    let sort = view.sort;
    let highlight = |label: &str, sorted: bool| {
        let cell = right(label.to_owned());
        if sorted { cell.style(SORTED) } else { cell }
    };
    let header = Row::new([
        highlight(words[0], matches!(sort, SortBy::Bytes | SortBy::Read)),
        highlight("CALLS", sort == SortBy::Calls),
        highlight(words[1], matches!(sort, SortBy::Bytes | SortBy::Write)),
        highlight("CALLS", sort == SortBy::Calls),
        right("FAILED".to_owned()),
        highlight("IDLE", sort == SortBy::Recent),
        Cell::from("TARGET"),
    ])
    .style(BOLD);
    let body = rows.iter().enumerate().map(|(i, (key, row))| {
        let drawn = target_row(key, row, shown.now_ns, target_width);
        if offset + i == selected {
            drawn.style(SELECTED_ROW)
        } else {
            drawn
        }
    });
    frame.render_widget(
        Table::new(body, widths).header(header).column_spacing(spacing),
        area,
    );
    if total > page {
        format!(
            "{}-{} of {}",
            offset + 1,
            offset + rows.len(),
            grouped(total as u64)
        )
    } else {
        String::new()
    }
}

fn target_row(key: &Key, row: &stats::Row, now_ns: u64, width: usize) -> Row<'static> {
    let note = match row.connections() {
        n if n > 1 => format!("  {n} connections"),
        _ => String::new(),
    };
    let name = key.to_string();
    // The note goes first when space runs out; the target itself matters more.
    let target = if name.width() + note.width() <= width {
        let mut spans = vec![Span::raw(name)];
        if !note.is_empty() {
            spans.push(Span::styled(note, DIM));
        }
        spans
    } else {
        vec![Span::raw(fit_start(&name, width).into_owned())]
    };
    let failed = right(row.errors.to_string());
    Row::new([
        right(bytes(row.read.bytes)),
        right(row.read.calls.to_string()),
        right(bytes(row.write.bytes)),
        right(row.write.calls.to_string()),
        if row.errors > 0 {
            failed.style(FAILED)
        } else {
            failed
        },
        right(idle(now_ns.saturating_sub(row.last_ns))),
        Cell::from(Line::from(target)),
    ])
}

/// Draws the newest events, or older ones when scrolled back; returns how many newer events
/// are out of view.
fn draw_events(frame: &mut Frame<'_>, area: Rect, view: &mut View, shown: &Shown<'_>) -> String {
    let ring = shown.events;
    let page = usize::from(area.height.saturating_sub(1));
    view.drawn = Drawn {
        page,
        first: ring.first(),
        end: ring.end(),
    };
    if ring.is_empty() {
        frame.render_widget(Paragraph::new(Line::styled(" No events yet.", DIM)), area);
        return String::new();
    }
    let full = ring.first() + page.min(ring.len()) as u64;
    let end = view
        .bottom
        .map_or(ring.end(), |bottom| (bottom + 1).clamp(full, ring.end()));
    let start = end.saturating_sub(page as u64).max(ring.first());

    // Narrow screens give up the requested size, then the descriptor, so the target keeps
    // some room.
    let narrow = area.width < NARROW;
    let wide = area.width >= WIDE;
    let mut labels = vec!["TIME", "PID", "OP"];
    let mut widths = vec![
        Constraint::Length(12),
        // macOS pids have at most five digits.
        Constraint::Length(5),
        // Only `getdirentries` needs more than 9 columns.
        Constraint::Length(if narrow { 9 } else { 13 }),
    ];
    if !narrow {
        labels.push("FD");
        widths.push(Constraint::Length(4));
    }
    if wide {
        labels.push("REQUESTED");
        widths.push(Constraint::Length(10));
    }
    labels.extend(["RESULT", "LATENCY", "TARGET"]);
    widths.extend([
        // Fits every errno name but EJUSTRETURN, which never reaches user space.
        Constraint::Length(if narrow { 10 } else { 11 }),
        Constraint::Length(8),
        Constraint::Fill(1),
    ]);
    let spacing = spacing(area.width);
    let target_width = usize::from(area.width).saturating_sub(fixed_width(&widths, spacing));
    let numeric = |label: &str| !matches!(label, "TIME" | "OP" | "TARGET");
    let header = Row::new(labels.iter().map(|&label| {
        if numeric(label) {
            right(label.to_owned())
        } else {
            Cell::from(label)
        }
    }))
    .style(BOLD);

    let clock = &mut view.clock;
    let body: Vec<Row<'static>> = ring
        .range(start, end)
        .map(|event| {
            let [mut time, pid, op, fd, requested, result, _, target] = text::event_fields(event, clock);
            // Milliseconds are enough on screen.
            time.truncate(12);
            let mut cells = vec![Cell::from(time), right(pid), Cell::from(op)];
            if !narrow {
                cells.push(right(fd));
            }
            if wide {
                cells.push(right(requested));
            }
            let result = right(result);
            cells.push(if event.is_ok() {
                result
            } else {
                result.style(FAILED)
            });
            cells.push(right(
                event.latency_ns.map_or_else(|| "-".to_owned(), short_latency),
            ));
            cells.push(Cell::from(fit_start(&target, target_width).into_owned()));
            Row::new(cells)
        })
        .collect();
    frame.render_widget(
        Table::new(body, widths).header(header).column_spacing(spacing),
        area,
    );
    let newer = ring.end() - end;
    if newer > 0 {
        format!("{} newer below", grouped(newer))
    } else {
        String::new()
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, view: &View, shown: &Shown<'_>) {
    let pause = if shown.paused { "p resume" } else { "p pause" };
    let tabs = view.tabs.len();
    let hints = Line::styled(
        format!("q quit  1-{tabs} tabs  s sort  {pause}  r reset  ↑↓ PgUp PgDn scroll "),
        DIM,
    )
    .right_aligned();
    let [left, right] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(width_of_line(&hints))]).areas(area);
    if let Some(status) = shown.status {
        frame.render_widget(Paragraph::new(format!(" {status}")), left);
    }
    frame.render_widget(Paragraph::new(hints), right);
}

/// Bytes moved during the last complete second before `now_ns`.
fn last_second(shown: &Shown<'_>) -> Second {
    let wanted = (shown.now_ns / 1_000_000_000).saturating_sub(1);
    shown
        .stats
        .history()
        .iter()
        .rev()
        .take_while(|second| second.unix_sec >= wanted)
        .find(|second| second.unix_sec == wanted)
        .copied()
        .unwrap_or_default()
}

fn right(text: String) -> Cell<'static> {
    Cell::from(Line::from(text).right_aligned())
}

fn spacing(width: u16) -> u16 {
    if width < NARROW { NARROW_SPACING } else { SPACING }
}

/// Columns taken by the fixed-width columns and the spacing between all of them.
fn fixed_width(widths: &[Constraint], spacing: u16) -> usize {
    let fixed: usize = widths
        .iter()
        .map(|constraint| match constraint {
            Constraint::Length(n) => usize::from(*n),
            _ => 0,
        })
        .sum();
    fixed + usize::from(spacing) * widths.len().saturating_sub(1)
}

fn width(text: &str) -> u16 {
    u16::try_from(text.width()).unwrap_or(u16::MAX)
}

fn width_of_line(line: &Line<'_>) -> u16 {
    u16::try_from(line.width()).unwrap_or(u16::MAX)
}

/// Elapsed time as `H:MM:SS`.
fn clock(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    format!("{}:{:02}:{:02}", secs / 3_600, secs / 60 % 60, secs % 60)
}

/// Syscall latency in at most 7 columns, e.g. `850µs`, `12.3ms`, `1.24s`.
fn short_latency(ns: u64) -> String {
    const MS: u64 = 1_000_000;
    const S: u64 = 1_000_000_000;
    match ns {
        0..MS => format!("{}µs", ns / 1_000),
        MS..S => format!("{}.{}ms", ns / MS, ns / 100_000 % 10),
        _ if ns < 100 * S => format!("{}.{:02}s", ns / S, ns / 10_000_000 % 100),
        _ if ns < 1_000 * S => format!("{}.{}s", ns / S, ns / 100_000_000 % 10),
        _ => format!("{}s", ns / S),
    }
}

/// Time since the latest I/O on a target, coarsely.
fn idle(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    match secs {
        0 => "<1s".to_owned(),
        1..=59 => format!("{secs}s"),
        60..=3_599 => format!("{}m", secs / 60),
        3_600..=86_399 => format!("{}h", secs / 3_600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// `n` with thousands separators, e.g. `12,345`.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `text` shortened from the left to fit `width` columns, marked with an ellipsis; the end of a
/// path or address says the most.
fn fit_start(text: &str, width: usize) -> Cow<'_, str> {
    if text.width() <= width {
        return Cow::Borrowed(text);
    }
    if width == 0 {
        return Cow::Borrowed("");
    }
    let mut kept = 0;
    let mut start = text.len();
    for (index, c) in text.char_indices().rev() {
        let w = c.width().unwrap_or(0);
        if kept + w > width - 1 {
            break;
        }
        kept += w;
        start = index;
    }
    Cow::Owned(format!("…{}", &text[start..]))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    use super::*;
    use crate::model::{Endpoint, Proto, Target};
    use crate::session::{Filter, Input, Process, Session, SessionInfo};
    use crate::sys::time::{ClockAnchor, Timebase};
    use crate::trace::pairing::PathRecords;
    use crate::trace::procs::{Fixed, Snapshot};
    use crate::trace::synth::{Call, Synth};
    use crate::tui::state::App;

    const PID: i32 = 4242;
    /// 2026-09-24 00:00:00 UTC.
    const START_NS: u64 = 1_790_208_000_000_000_000;

    /// A curl-like process: writes a file, talks to a server, fails one receive.
    fn traced() -> (Session, App) {
        let info = SessionInfo {
            timebase: Timebase { numer: 1, denom: 1 },
            anchor: ClockAnchor {
                ticks: 1_000,
                unix_nanos: START_NS,
            },
            processes: vec![Process {
                pid: PID,
                name: "curl".into(),
            }],
            path_records: PathRecords::Whole,
        };
        let mut src = Fixed::default();
        src.snapshots.insert(
            PID,
            Snapshot {
                fds: vec![(
                    1,
                    Target::File {
                        path: "/dev/ttys004".into(),
                    },
                )],
                cwd: Some("/Users/me".into()),
            },
        );
        src.targets.insert(
            (PID, 5),
            Target::Socket(Endpoint {
                proto: Proto::Tcp,
                local: Some("192.168.1.20:61000".parse().unwrap()),
                remote: Some("93.184.216.34:443".parse().unwrap()),
                path: None,
            }),
        );
        let mut session = Session::new(info, Filter::ALL, &mut src);
        let mut app = App::default();
        // One second after the start, so the rates show the second before.
        let mut synth = Synth::new(1_000 + 1_000_000_000, 1_000);
        let mut records = synth.open(1, PID, "page.html", 4);
        records.extend(synth.call(Call {
            ret: 5,
            ..Call::new(2, PID, 97, [2, 1, 6, 0])
        }));
        records.extend(synth.call(Call {
            errno: libc::EINPROGRESS,
            ..Call::new(2, PID, 98, [5, 0, 16, 0])
        }));
        records.extend(synth.io(2, PID, 133, 5, 517, 517));
        records.extend(synth.io(2, PID, 29, 5, 16_384, 4_096));
        records.extend(synth.call(Call {
            errno: libc::EAGAIN,
            ..Call::new(2, PID, 29, [5, 0, 16_384, 0])
        }));
        records.extend(synth.io(1, PID, 4, 4, 4_096, 4_096));
        records.extend(synth.io(1, PID, 397, 1, 20, 20));
        session
            .handle(&Input::Records(records), &mut src, &mut app)
            .unwrap();
        (session, app)
    }

    fn render_buffer(session: &Session, app: &mut App, width: u16, height: u16, now_ns: u64) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                let shown = app.model.shown(session, now_ns);
                draw(frame, &mut app.view, &shown);
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn line(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>()
            .trim_end()
            .to_owned()
    }

    fn render(session: &Session, app: &mut App, width: u16, height: u16, now_ns: u64) -> Vec<String> {
        let buffer = render_buffer(session, app, width, height, now_ns);
        (0..buffer.area.height).map(|y| line(&buffer, y)).collect()
    }

    /// Lines highlighted from the tables' left edge to the right edge of the screen.
    fn highlighted(buffer: &Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .filter(|&y| (1..buffer.area.width).all(|x| buffer[(x, y)].modifier.contains(Modifier::REVERSED)))
            .map(|y| line(buffer, y))
            .collect()
    }

    fn find<'a>(lines: &'a [String], needle: &str) -> &'a str {
        lines
            .iter()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line contains {needle:?} in\n{}", lines.join("\n")))
    }

    fn press(app: &mut App, session: &Session, code: ratatui::crossterm::event::KeyCode) {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        app.key(KeyEvent::new(code, KeyModifiers::NONE), session, 0);
    }

    #[test]
    fn header_shows_processes_rates_and_totals() {
        let (session, mut app) = traced();
        let lines = render(&session, &mut app, 100, 20, START_NS + 2_500_000_000);
        assert!(lines[0].starts_with(" iotap  4242 curl"), "{}", lines[0]);
        assert!(lines[0].ends_with("0:00:02"), "{}", lines[0]);
        assert!(find(&lines, "FILE READ").contains("NET SENT"));
        let per_second: Vec<&str> = find(&lines, "per second").split_whitespace().collect();
        assert_eq!(
            per_second,
            ["per", "second", "0", "B", "4.0", "KiB", "4.0", "KiB", "517", "B"]
        );
        let total: Vec<&str> = find(&lines, " total").split_whitespace().collect();
        assert_eq!(total, ["total", "0", "B", "4.0", "KiB", "4.0", "KiB", "517", "B"]);
        assert!(find(&lines, "1 Files (2)").contains("2 Network (1)"));
        assert!(find(&lines, "3 Events (5)").contains("sort: bytes"));
        assert!(lines.last().unwrap().contains("q quit"));
    }

    #[test]
    fn tabs_list_targets_and_events() {
        let (session, mut app) = traced();
        let now = START_NS + 2_500_000_000;
        let lines = render(&session, &mut app, 100, 20, now);
        let row: Vec<&str> = find(&lines, "/Users/me/page.html").split_whitespace().collect();
        assert_eq!(
            row,
            ["0", "B", "0", "4.0", "KiB", "1", "0", "1s", "/Users/me/page.html"]
        );
        assert!(find(&lines, "IDLE").contains("TARGET"));

        press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char('2'));
        let lines = render(&session, &mut app, 100, 20, now);
        let row: Vec<&str> = find(&lines, "tcp 93.184.216.34:443").split_whitespace().collect();
        assert_eq!(row[..7], ["4.0", "KiB", "2", "517", "B", "1", "1"]);
        assert!(find(&lines, "RECEIVED").contains("SENT"));

        press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char('3'));
        let lines = render(&session, &mut app, 100, 20, now);
        assert!(find(&lines, "EAGAIN").contains("recvfrom"));
        let sendto = find(&lines, "sendto");
        assert!(
            sendto.contains("  …") && sendto.ends_with(":61000 -> 93.184.216.34:443"),
            "long targets keep their end: {sendto}"
        );
        assert!(
            !find(&lines, "LATENCY").contains("REQUESTED"),
            "narrow screens drop a column"
        );
        let lines = render(&session, &mut app, 130, 20, now);
        assert!(find(&lines, "LATENCY").contains("REQUESTED"));
        assert!(find(&lines, "sendto").ends_with("  tcp 192.168.1.20:61000 -> 93.184.216.34:443"));
    }

    #[test]
    fn events_scroll_back_and_report_what_is_below() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        press(&mut app, &session, KeyCode::Char('3'));
        // Two event rows fit below the table header.
        let lines = render(&session, &mut app, 100, 10, START_NS);
        assert!(find(&lines, "write").contains("/Users/me/page.html"));
        press(&mut app, &session, KeyCode::Up);
        press(&mut app, &session, KeyCode::Up);
        let lines = render(&session, &mut app, 100, 10, START_NS);
        assert!(find(&lines, "3 Events (5)").contains("2 newer below"));
        press(&mut app, &session, KeyCode::End);
        let lines = render(&session, &mut app, 100, 10, START_NS);
        assert!(!find(&lines, "3 Events (5)").contains("newer below"));
    }

    #[test]
    fn the_selected_row_is_highlighted_and_kept_in_view() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        let buffer = render_buffer(&session, &mut app, 100, 20, START_NS);
        let rows = highlighted(&buffer);
        assert!(
            rows.len() == 1 && rows[0].ends_with(" /Users/me/page.html"),
            "the top row is selected at first: {rows:?}"
        );
        press(&mut app, &session, KeyCode::Down);
        // One table row fits below the header.
        let buffer = render_buffer(&session, &mut app, 100, 8, START_NS);
        let rows = highlighted(&buffer);
        assert!(rows.len() == 1 && rows[0].ends_with(" /dev/ttys004"), "{rows:?}");
        let lines: Vec<String> = (0..buffer.area.height).map(|y| line(&buffer, y)).collect();
        assert!(
            find(&lines, "1 Files (2)").contains("2-2 of 2"),
            "{}",
            lines.join("\n")
        );
        press(&mut app, &session, KeyCode::Char('2'));
        let rows = highlighted(&render_buffer(&session, &mut app, 100, 20, START_NS));
        assert!(
            rows.len() == 1 && rows[0].ends_with(" tcp 93.184.216.34:443"),
            "each table has its own selection: {rows:?}"
        );
        press(&mut app, &session, KeyCode::Char('3'));
        let rows = highlighted(&render_buffer(&session, &mut app, 100, 20, START_NS));
        assert!(rows.is_empty(), "events are not selected: {rows:?}");
    }

    #[test]
    fn alerts_and_pause_are_visible() {
        let (session, mut app) = traced();
        app.end("Tracing stopped: every traced process has exited.".into());
        press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char('p'));
        let lines = render(&session, &mut app, 100, 20, START_NS);
        assert!(find(&lines, "every traced process has exited.").contains("Press q for the summary."));
        assert!(find(&lines, "sort: bytes").ends_with("PAUSED"));
        assert!(lines.last().unwrap().contains("p resume"));
    }

    #[test]
    fn quiet_leaves_out_the_events_tab() {
        use crate::tui::state::Tab;
        let (session, traced_app) = traced();
        let mut app = App::new(&Tab::TARGETS);
        app.model = traced_app.model;
        press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char('2'));
        let lines = render(&session, &mut app, 100, 20, START_NS);
        let tabs = find(&lines, "1 Files (2)");
        assert!(
            tabs.contains("2 Network (1)") && !tabs.contains("Events"),
            "{tabs}"
        );
        assert!(find(&lines, "tcp 93.184.216.34:443").contains("517 B"));
        assert!(lines.last().unwrap().contains("q quit  1-2 tabs"));
    }

    #[test]
    fn reset_shows_an_empty_view_timed_from_the_reset() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let (session, mut app) = traced();
        app.key(
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
            &session,
            START_NS + 2_000_000_000,
        );
        let lines = render(&session, &mut app, 100, 20, START_NS + 5_500_000_000);
        assert!(lines[0].ends_with("0:00:03 since reset"), "{}", lines[0]);
        let total: Vec<&str> = find(&lines, " total").split_whitespace().collect();
        assert_eq!(total, ["total", "0", "B", "0", "B", "0", "B", "0", "B"]);
        assert!(find(&lines, "1 Files (0)").contains("3 Events (0)"));
        assert!(find(&lines, "No file I/O yet.").starts_with(' '));
        let footer = lines.last().unwrap();
        assert!(footer.starts_with(" view reset at "), "{footer}");
        assert!(footer.contains("r reset"), "{footer}");
    }

    #[test]
    fn narrow_screens_keep_room_for_the_target() {
        let (session, mut app) = traced();
        press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char('3'));
        let lines = render(&session, &mut app, 80, 20, START_NS);
        let header = find(&lines, "LATENCY");
        assert!(
            !header.contains("FD") && !header.contains("REQUESTED"),
            "{header}"
        );
        // 79 columns after the margin, minus 44 for the other columns and 5 for spacing.
        let row = find(&lines, "EAGAIN");
        assert!(row.ends_with(" …20:61000 -> 93.184.216.34:443"), "{row}");
        assert!(find(&lines, "write").ends_with(" /Users/me/page.html"));
    }

    #[test]
    fn tiny_screens_do_not_panic() {
        let (session, mut app) = traced();
        for tab in ['1', '2', '3'] {
            press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char(tab));
            for (width, height) in [(1, 1), (20, 5), (40, 8), (80, 3)] {
                render(&session, &mut app, width, height, START_NS);
            }
        }
    }

    #[test]
    fn formats_compact_values() {
        assert_eq!(clock(3_723_000_000_000), "1:02:03");
        assert_eq!(idle(999_999_999), "<1s");
        assert_eq!(idle(59_000_000_000), "59s");
        assert_eq!(idle(3_599_000_000_000), "59m");
        assert_eq!(idle(90_000_000_000_000), "1d");
        assert_eq!(short_latency(999), "0µs");
        assert_eq!(short_latency(850_000), "850µs");
        assert_eq!(short_latency(12_345_678), "12.3ms");
        assert_eq!(short_latency(1_240_000_000), "1.24s");
        assert_eq!(short_latency(123_450_000_000), "123.4s");
        assert_eq!(short_latency(10_800_000_000_000), "10800s");
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(1_234), "1,234");
        assert_eq!(grouped(123_456_789), "123,456,789");
        assert_eq!(fit_start("/Users/me/page.html", 30), "/Users/me/page.html");
        assert_eq!(fit_start("/Users/me/page.html", 10), "…page.html");
        assert_eq!(fit_start("/데이터/파일", 7), "…/파일");
        assert_eq!(fit_start("abc", 0), "");
    }
}
