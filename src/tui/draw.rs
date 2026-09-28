//! Draws one frame of the terminal UI.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs};
use unicode_width::UnicodeWidthStr;

use super::state::{Drawn, Shown, Tab, View};
use super::{details, fit};
use crate::hosts::Hosts;
use crate::model::{Endpoint, IoEvent, Target};
use crate::output::{bytes, count, text};
use crate::stats::{self, Key, Peer, Second, SortBy, Traffic};

pub(super) const BOLD: Style = Style::new().add_modifier(Modifier::BOLD);
pub(super) const DIM: Style = Style::new().fg(Color::DarkGray);
pub(super) const FAILED: Style = Style::new().fg(Color::Red);
const SORTED: Style = Style::new()
    .fg(Color::Cyan)
    .add_modifier(Modifier::BOLD)
    .add_modifier(Modifier::UNDERLINED);
const TITLE: Style = Style::new()
    .add_modifier(Modifier::BOLD)
    .add_modifier(Modifier::REVERSED);
const SELECTED_TAB: Style = TITLE;
/// The selected row: bold, with a mark in the gutter to its left.
const SELECTED_ROW: Style = BOLD;
const SELECTED_MARK: &str = "▌";
const SELECTED_MARK_STYLE: Style = Style::new().fg(Color::Cyan);
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
/// Width of the first column of the rates and interface tables, which a long interface name
/// widens.
const RATE_LABEL: u16 = 11;
/// Most rows of the interface table below its header; beyond them, the last row sums the rest.
const INTERFACE_ROWS: usize = 8;
/// Fewest lines the interface table leaves the tabs and what they show.
const BODY_LINES: u16 = 5;

pub fn draw(frame: &mut Frame<'_>, view: &mut View, shown: &Shown<'_>) {
    let alerts = alerts(shown);
    let alert_lines = u16::try_from(alerts.len()).unwrap_or(u16::MAX);
    // What the title, the rates, the alerts and the footer leave for the interface table.
    let room = frame
        .area()
        .height
        .saturating_sub(1 + 3 + alert_lines + 1 + BODY_LINES);
    let interfaces = if view.interfaces && shown.filter.network {
        interface_rows(shown, usize::from(room))
    } else {
        None
    };
    let interface_lines = interfaces
        .as_ref()
        .map_or(0, |rows| 1 + u16::try_from(rows.len().max(1)).unwrap_or(u16::MAX));
    let label = interfaces
        .iter()
        .flatten()
        .map(|row| width(&row.label))
        .fold(RATE_LABEL, u16::max);
    let [title, rates, interface_area, alert_area, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(interface_lines),
        Constraint::Length(alert_lines),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_title(frame, title, shown);
    draw_rates(frame, rates, shown, label);
    if let Some(rows) = &interfaces {
        draw_interfaces(frame, interface_area, rows, label);
    }
    frame.render_widget(Paragraph::new(alerts), alert_area);
    // Tables start one column in, like the lines above them; that gutter marks the selected
    // row.
    let [gutter, body] = Layout::horizontal([Constraint::Length(1), Constraint::Fill(1)]).areas(body);
    let position = match view.tab {
        Tab::Files | Tab::Network => draw_table_tab(frame, gutter, body, view, shown),
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

/// Bytes per second over the last complete second, and totals so far, after a first column
/// `label` wide.
fn draw_rates(frame: &mut Frame<'_>, area: Rect, shown: &Shown<'_>, label: u16) {
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
    frame.render_widget(
        Table::new(rows, rate_widths(label))
            .header(header)
            .column_spacing(SPACING),
        area,
    );
}

/// Widths of the columns of the rates and interface tables, which line up.
fn rate_widths(label: u16) -> [Constraint; 5] {
    [
        Constraint::Length(label),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ]
}

/// One row of the interface table: bytes received and sent over the last complete second and
/// in total.
struct InterfaceRow {
    label: String,
    per_second: (u64, u64),
    total: (u64, u64),
    /// True for the row that sums the interfaces left out.
    rest: bool,
}

/// The rows of the interface table that fit with its header in `room` lines, in the order of
/// [`stats::Stats::interfaces`]: `None` when not even one fits, and none before any network I/O.
/// When not all fit, the last row sums those left out.
fn interface_rows(shown: &Shown<'_>, room: usize) -> Option<Vec<InterfaceRow>> {
    let fit = room.saturating_sub(1).min(INTERFACE_ROWS);
    if fit == 0 {
        return None;
    }
    let second = (shown.now_ns / 1_000_000_000).saturating_sub(1);
    let traffic = shown.stats.interfaces();
    let shown_rows = if traffic.len() > fit { fit - 1 } else { fit };
    let row = |label: String, traffic: &Traffic| InterfaceRow {
        label,
        per_second: traffic.during(second),
        total: (traffic.read.bytes, traffic.write.bytes),
        rest: false,
    };
    let mut rows: Vec<InterfaceRow> = traffic
        .iter()
        .take(shown_rows)
        .map(|(via, traffic)| row(format!(" {via}"), traffic))
        .collect();
    let rest = &traffic[shown_rows.min(traffic.len())..];
    if !rest.is_empty() {
        let mut sum = InterfaceRow {
            rest: true,
            ..row(format!(" {} more", rest.len()), &Traffic::default())
        };
        for (_, traffic) in rest {
            let (read, write) = traffic.during(second);
            sum.per_second = (
                sum.per_second.0.saturating_add(read),
                sum.per_second.1.saturating_add(write),
            );
            sum.total = (
                sum.total.0.saturating_add(traffic.read.bytes),
                sum.total.1.saturating_add(traffic.write.bytes),
            );
        }
        rows.push(sum);
    }
    Some(rows)
}

/// Network I/O by interface, with a first column `label` wide as the rates table has.
fn draw_interfaces(frame: &mut Frame<'_>, area: Rect, rows: &[InterfaceRow], label: u16) {
    let header = Row::new([
        Cell::from(" INTERFACE"),
        right("RECEIVED/S".to_owned()),
        right("SENT/S".to_owned()),
        right("RECEIVED".to_owned()),
        right("SENT".to_owned()),
    ])
    .style(BOLD);
    if rows.is_empty() {
        let [header_area, rest] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Table::new(Vec::<Row<'_>>::new(), rate_widths(label))
                .header(header)
                .column_spacing(SPACING),
            header_area,
        );
        frame.render_widget(Paragraph::new(" No network I/O yet.").style(DIM), rest);
        return;
    }
    let body = rows.iter().map(|row| {
        let cells = [
            Cell::from(row.label.clone()),
            right(bytes(row.per_second.0)),
            right(bytes(row.per_second.1)),
            right(bytes(row.total.0)),
            right(bytes(row.total.1)),
        ];
        if row.rest {
            Row::new(cells).style(DIM)
        } else {
            Row::new(cells)
        }
    });
    frame.render_widget(
        Table::new(body, rate_widths(label))
            .header(header)
            .column_spacing(SPACING),
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

/// Draws the Files or Network table and, when asked for, the details of its selected row
/// below it; returns which rows are visible, when not all fit.
fn draw_table_tab(
    frame: &mut Frame<'_>,
    gutter: Rect,
    area: Rect,
    view: &mut View,
    shown: &Shown<'_>,
) -> String {
    let tab = view.tab;
    let stats = shown.stats;
    let selected = view.selected_rank(stats);
    let lines = match selected {
        Some(rank) if view.details => {
            let row = stats.page(|category| tab.lists(category), view.sort, rank, 1);
            row.first()
                .map(|&(key, row)| details::lines(key, row, usize::from(area.width), view, shown))
        }
        _ => None,
    };
    let Some(lines) = lines else {
        return draw_targets(frame, gutter, area, view, shown, selected);
    };
    // The table keeps its header and a few rows; the panel gives up its last lines first.
    let height = u16::try_from(lines.len() + 1).unwrap_or(u16::MAX);
    let [table, panel] = Layout::vertical([Constraint::Min(4), Constraint::Length(height)]).areas(area);
    let position = draw_targets(frame, gutter, table, view, shown, selected);
    let block = Block::new()
        .borders(Borders::TOP)
        .border_style(DIM)
        .title(Span::styled(" details ", BOLD));
    frame.render_widget(Paragraph::new(lines).block(block), panel);
    position
}

/// Draws the Files or Network table, scrolled so the row ranked `selected` shows and marked in
/// `gutter`, or showing the top rows when none is selected; returns which rows are visible,
/// when not all fit.
fn draw_targets(
    frame: &mut Frame<'_>,
    gutter: Rect,
    area: Rect,
    view: &mut View,
    shown: &Shown<'_>,
    selected: Option<usize>,
) -> String {
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
    let mut offset = view.offsets[index].min(total.saturating_sub(page));
    match selected {
        Some(rank) if rank < offset => offset = rank,
        Some(rank) if page > 0 && rank >= offset + page => offset = rank + 1 - page,
        Some(_) => {}
        None => offset = 0,
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

    let numbers: Vec<[String; 6]> = rows
        .iter()
        .map(|(_, row)| row_numbers(row, shown.now_ns))
        .collect();
    let widths = target_columns(&numbers);
    let spacing = spacing(area.width);
    let target_width = usize::from(area.width).saturating_sub(fixed_width(&widths, spacing));
    let sort = view.sort;
    let home = view.home.as_deref();
    let names = view.names;
    let hosts = &mut view.hosts;
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
    let body = rows
        .iter()
        .zip(&numbers)
        .enumerate()
        .map(|(i, ((key, row), numbers))| {
            let host = match key.remote() {
                Some(addr) if names => hosts.name(addr.ip()),
                _ => None,
            };
            let drawn = target_row(key, row, numbers, target_width, home, host);
            if selected == Some(offset + i) {
                drawn.style(SELECTED_ROW)
            } else {
                drawn
            }
        });
    frame.render_widget(
        Table::new(body, widths).header(header).column_spacing(spacing),
        area,
    );
    // The mark goes in the gutter beside the selected row; rows start below the header.
    let visible = selected
        .and_then(|rank| rank.checked_sub(offset))
        .filter(|&i| i < rows.len());
    if let Some(i) = visible.and_then(|i| u16::try_from(i).ok()) {
        let y = area.y.saturating_add(1).saturating_add(i);
        if y < area.bottom() {
            let mark = Paragraph::new(Span::styled(SELECTED_MARK, SELECTED_MARK_STYLE));
            frame.render_widget(mark, Rect::new(gutter.x, y, gutter.width.min(1), 1));
        }
    }
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

/// The columns of the Files and Network tables for rows with these `numbers`: the numbers
/// take what they need, which is normally what they have, and the target the rest.
fn target_columns(numbers: &[[String; 6]]) -> [Constraint; 7] {
    let least = [10, 7, 10, 7, 6, 4];
    let [read, read_calls, written, written_calls, failed, idle] = std::array::from_fn(|i| {
        Constraint::Length(column_width(
            least[i],
            numbers.iter().map(|cells| cells[i].as_str()),
        ))
    });
    [
        read,
        read_calls,
        written,
        written_calls,
        failed,
        idle,
        Constraint::Fill(1),
    ]
}

/// The numbers of a row of the Files or Network table, as its columns show them: what was
/// read, the calls that read it, what was written, the calls that wrote it, the calls that
/// failed, and how long ago the target was last used.
fn row_numbers(row: &stats::Row, now_ns: u64) -> [String; 6] {
    [
        bytes(row.read.bytes),
        row.read.calls.to_string(),
        bytes(row.write.bytes),
        row.write.calls.to_string(),
        row.errors.to_string(),
        idle(now_ns.saturating_sub(row.last_ns)),
    ]
}

/// One row of the Files or Network table, with its `numbers`; a socket's remote address shows
/// as `host`, when given.
fn target_row(
    key: &Key,
    row: &stats::Row,
    numbers: &[String; 6],
    width: usize,
    home: Option<&str>,
    host: Option<&str>,
) -> Row<'static> {
    let note = match row.connections() {
        n if n > 1 => format!("  {n} connections"),
        _ => String::new(),
    };
    let path = key_path(key);
    let name = match path {
        Some((proto, path)) => show_path(proto, path, home, usize::MAX),
        None => key.named(host).to_string(),
    };
    // The note goes first when space runs out; the target itself matters more.
    let target = if name.width() + note.width() <= width {
        let mut spans = vec![Span::raw(name)];
        if !note.is_empty() {
            spans.push(Span::styled(note, DIM));
        }
        spans
    } else {
        let fitted = match path {
            Some((proto, path)) => show_path(proto, path, home, width),
            None => fit::start(&name, width).into_owned(),
        };
        vec![Span::raw(fitted)]
    };
    let [read, read_calls, written, written_calls, failed, idle] = numbers.clone().map(right);
    Row::new([
        read,
        read_calls,
        written,
        written_calls,
        if row.errors > 0 {
            failed.style(FAILED)
        } else {
            failed
        },
        idle,
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
    let home = view.home.as_deref();
    let names = view.names;
    let hosts = &mut view.hosts;
    let clock = &mut view.clock;
    let fields: Vec<(&IoEvent, [String; 8])> = ring
        .range(start, end)
        .map(|event| (event, text::event_fields(event, clock)))
        .collect();
    // The numbers take what they need: macOS pids have at most five digits, and Linux ones seven,
    // descriptors and requested sizes are open ended, and an errno name can be longer than 11.
    let column =
        |index: usize, least: u16| column_width(least, fields.iter().map(|(_, cells)| cells[index].as_str()));
    let mut labels = vec!["TIME", "PID", "OP"];
    let mut widths = vec![
        Constraint::Length(12),
        Constraint::Length(column(1, 5)),
        // Only `getdirentries` needs more than 9 columns.
        Constraint::Length(if narrow { 9 } else { 13 }),
    ];
    if !narrow {
        labels.push("FD");
        widths.push(Constraint::Length(column(3, 4)));
    }
    if wide {
        labels.push("REQUESTED");
        widths.push(Constraint::Length(column(4, 10)));
    }
    labels.extend(["RESULT", "LATENCY", "TARGET"]);
    widths.extend([
        Constraint::Length(column(5, if narrow { 10 } else { 11 })),
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

    let body: Vec<Row<'static>> = fields
        .into_iter()
        .map(|(event, cells)| {
            let [mut time, pid, op, fd, requested, result, _, target] = cells;
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
            let target = if let Some((proto, path)) = target_path(&event.target) {
                show_path(proto, path, home, target_width)
            } else {
                let with_host = if names { named(&event.target, hosts) } else { None };
                fit::start(with_host.as_deref().unwrap_or(&target), target_width).into_owned()
            };
            cells.push(Cell::from(target));
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
    let table = view.tab != Tab::Events;
    let mut hints = vec!["q quit"];
    if table {
        hints.push("s sort");
    }
    hints.push(if shown.paused { "p resume" } else { "p pause" });
    let interfaces = shown.filter.network.then_some(hints.len());
    if interfaces.is_some() {
        hints.push("i interfaces");
    }
    hints.push("r reset");
    if view.tab != Tab::Files && shown.filter.network {
        hints.push(if view.names { "n addresses" } else { "n names" });
    }
    hints.extend(match (table, view.has_selection(), view.details) {
        (false, ..) => ["↑↓ scroll"].as_slice(),
        (true, false, _) => &["↑↓ select", "enter details"],
        (true, true, false) => &["enter details", "y copy", "esc deselect"],
        (true, true, true) => &["y copy", "esc close"],
    });
    // The hint for the interface table gives way to the status and the other hints.
    let status = shown.status.map_or(0, |status| usize::from(width(status)) + 1);
    if let Some(at) = interfaces
        && status + usize::from(width(&hints.join("  "))) + 1 > usize::from(area.width)
    {
        hints.remove(at);
    }
    let hints = Line::styled(format!("{} ", hints.join("  ")), DIM).right_aligned();
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

/// The width of a column of numbers: `least`, or more where a cell needs it. A right-aligned
/// cell wider than its column loses its leading digits, and a number with the front cut off
/// is another number.
fn column_width<'a>(least: u16, cells: impl IntoIterator<Item = &'a str>) -> u16 {
    cells.into_iter().map(width).fold(least, u16::max)
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
pub(super) fn short_latency(ns: u64) -> String {
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
pub(super) fn idle(ns: u64) -> String {
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

/// The path in a key's name and the protocol before it, for files and Unix-domain sockets.
fn key_path(key: &Key) -> Option<(&'static str, &str)> {
    match key {
        Key::File(path) if !path.is_empty() => Some(("", path)),
        Key::Socket {
            proto,
            peer: Peer::Path(path),
        } => Some((proto.name(), path)),
        _ => None,
    }
}

/// The path in a target's name and the protocol before it, for files and Unix-domain sockets.
fn target_path(target: &Target) -> Option<(&'static str, &str)> {
    match target {
        Target::File { path } if !path.is_empty() => Some(("", path)),
        Target::Socket(Endpoint {
            proto,
            path: Some(path),
            ..
        }) => Some((proto.name(), path)),
        _ => None,
    }
}

/// A socket target with the host name of its remote address in place of the address, once
/// `hosts` has found the name.
fn named(target: &Target, hosts: &mut Hosts) -> Option<String> {
    let Target::Socket(endpoint) = target else {
        return None;
    };
    let host = hosts.name(endpoint.remote?.ip())?;
    Some(endpoint.named(Some(host)).to_string())
}

/// A path, after its protocol if it has one, in at most `width` columns: the home directory
/// shows as `~`, and directory names are cut from the left when the path is too long.
fn show_path(proto: &str, path: &str, home: Option<&str>, width: usize) -> String {
    let path = fit::tilde(path, home);
    if proto.is_empty() {
        return fit::path(&path, width).into_owned();
    }
    let room = width.saturating_sub(proto.width() + 1);
    format!("{proto} {}", fit::path(&path, room))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    use super::*;
    use crate::interfaces::{Interface, Listing};
    use crate::model::{Endpoint, Proto, Target, Via};
    use crate::session::{Filter, Input, Process, Session, SessionInfo};
    use crate::sys::time::{ClockAnchor, Timebase};
    use crate::trace::kdebug::pairing::PathRecords;
    use crate::trace::kdebug::synth::{Call, Synth};
    use crate::trace::procs::{Fixed, Snapshot};
    use crate::trace::{Records, System};
    use crate::tui::state::App;

    const PID: i32 = 4242;
    /// 2026-09-24 00:00:00 UTC.
    const START_NS: u64 = 1_790_208_000_000_000_000;

    /// A curl-like process: writes a file, talks to a server over en0, fails one receive.
    fn traced() -> (Session, App) {
        traced_over("en0")
    }

    /// The same, with the interface that holds its local address named `interface`.
    fn traced_over(interface: &str) -> (Session, App) {
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
            system: System::Macos,
        };
        let listed = |name: &str, loopback, addr: &str| Interface {
            name: name.into(),
            index: 0,
            loopback,
            addrs: vec![addr.parse().unwrap()],
        };
        let mut src = Fixed {
            interfaces: vec![Listing {
                interfaces: vec![
                    listed("lo0", true, "127.0.0.1"),
                    listed(interface, false, "192.168.1.20"),
                ],
                netns: None,
            }],
            ..Fixed::default()
        };
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
                netns: None,
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
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
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

    /// Lines marked as selected in the gutter; each must also be bold across the table.
    fn marked(buffer: &Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .filter(|&y| buffer[(0, y)].symbol() == SELECTED_MARK)
            .inspect(|&y| {
                let bold = (1..buffer.area.width).all(|x| buffer[(x, y)].modifier.contains(Modifier::BOLD));
                assert!(bold, "a marked row is bold: {}", line(buffer, y));
            })
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

    /// A process with a pid of seven digits, as Linux gives, that writes to a descriptor of six
    /// digits, asks for the most a `size_t` holds, and fails with long errno names.
    fn traced_with_big_numbers() -> (Session, App) {
        const BIG_PID: i32 = 4_194_304;
        let info = SessionInfo {
            timebase: Timebase { numer: 1, denom: 1 },
            anchor: ClockAnchor {
                ticks: 1_000,
                unix_nanos: START_NS,
            },
            processes: vec![Process {
                pid: BIG_PID,
                name: "busy".into(),
            }],
            path_records: PathRecords::Whole,
            system: System::Macos,
        };
        let mut src = Fixed::default();
        let mut session = Session::new(info, Filter::ALL, &mut src);
        let mut app = App::default();
        let mut synth = Synth::new(1_000 + 1_000_000_000, 1_000);
        let mut records = synth.io(1, BIG_PID, 4, 123_456, u64::MAX, 4_096);
        records.extend(synth.call(Call {
            errno: libc::ECONNREFUSED,
            ..Call::new(2, BIG_PID, 29, [123_456, 0, 16_384, 0])
        }));
        records.extend(synth.call(Call {
            errno: libc::EADDRNOTAVAIL,
            ..Call::new(2, BIG_PID, 133, [123_456, 0, 16, 0])
        }));
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        (session, app)
    }

    #[test]
    fn numbers_and_errno_names_are_not_cut_short_in_the_events_tab() {
        let (session, mut app) = traced_with_big_numbers();
        press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char('3'));
        let now = START_NS + 2_500_000_000;
        for width in [120, 140, 200] {
            let lines = render(&session, &mut app, width, 10, now);
            let text = lines.join("\n");
            for whole in [
                "4194304",
                "123456",
                "18446744073709551615",
                "ECONNREFUSED",
                "EADDRNOTAVAIL",
            ] {
                assert!(
                    text.contains(&format!(" {whole} ")) || text.contains(&format!(" {whole}\n")),
                    "{whole} is whole at {width} columns:\n{text}"
                );
            }
            // The columns keep their headers: each value ends where its header does.
            let header = find(&lines, "PID");
            let row = find(&lines, "recvfrom");
            assert_eq!(
                header.find("PID").unwrap() + 3,
                row.find("4194304").unwrap() + 7,
                "the pid ends under its header at {width} columns:\n{text}"
            );
        }
    }

    #[test]
    fn a_sum_of_bytes_at_the_top_of_a_u64_is_whole_in_the_files_tab() {
        let (mut session, mut app) = traced_with_big_numbers();
        let mut src = Fixed::default();
        let mut synth = Synth::new(1_000 + 2_000_000_000, 1_000);
        let records = synth.io(1, 4_194_304, 4, 123_456, 100, u64::MAX);
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        let lines = render(&session, &mut app, 100, 12, START_NS + 3_500_000_000);
        let row = find(&lines, "<unknown>");
        assert!(row.contains(" 16384.0 PiB "), "not cut to 6384.0 PiB: {row}");
        let header = find(&lines, "CALLS");
        assert_eq!(
            header.find("WRITTEN").unwrap() + 7,
            row.find("16384.0 PiB").unwrap() + 11,
            "the sum ends under its header:\n{}",
            lines.join("\n")
        );
    }

    #[test]
    fn the_columns_grow_only_when_a_value_needs_it() {
        assert_eq!(column_width(5, ["1", "42", "4242"]), 5);
        assert_eq!(column_width(5, ["1", "4194304"]), 7);
        assert_eq!(column_width(4, []), 4);
        // A sum of bytes at the top of what a u64 counts, in the Files table.
        assert_eq!(column_width(10, ["0 B", "16384.0 PiB"]), 11);
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
    fn n_shows_remote_addresses_as_host_names() {
        use std::net::IpAddr;
        use std::time::{Duration, Instant};

        use ratatui::crossterm::event::KeyCode;

        use crate::hosts::{HostName, Hosts};
        let (session, mut app) = traced();
        let server: IpAddr = "93.184.216.34".parse().unwrap();
        app.view.hosts = Hosts::with_lookup(move |addr| {
            if addr == server {
                HostName::Found("www.example.com".into())
            } else {
                HostName::None
            }
        });
        let answered = |app: &mut App| {
            app.view
                .hosts
                .look_up(&[server], Instant::now() + Duration::from_secs(10));
        };
        press(&mut app, &session, KeyCode::Char('2'));
        let lines = render(&session, &mut app, 100, 20, START_NS);
        assert!(find(&lines, "tcp 93.184.216.34:443").contains("517 B"));
        assert!(
            lines
                .last()
                .unwrap()
                .ends_with("r reset  n names  ↑↓ select  enter details")
        );
        assert_eq!(
            app.view.hosts.asked(),
            0,
            "nothing is looked up before names are asked for"
        );

        press(&mut app, &session, KeyCode::Char('n'));
        let lines = render(&session, &mut app, 100, 20, START_NS);
        assert!(
            find(&lines, "tcp 93.184.216.34:443").contains("517 B"),
            "the address shows until the name is in"
        );
        let footer = lines.last().unwrap();
        assert!(
            footer.starts_with(" showing host names") && footer.contains("n addresses"),
            "{footer}"
        );
        answered(&mut app);
        let lines = render(&session, &mut app, 100, 20, START_NS);
        let row: Vec<&str> = find(&lines, "tcp www.example.com:443")
            .split_whitespace()
            .collect();
        assert_eq!(row[..7], ["4.0", "KiB", "2", "517", "B", "1", "1"]);

        press(&mut app, &session, KeyCode::Enter);
        let lines = render(&session, &mut app, 100, 30, START_NS);
        assert!(
            lines.iter().any(|line| line == " tcp 93.184.216.34:443"),
            "the details keep the address: {}",
            lines.join("\n")
        );
        assert!(find(&lines, " host ").ends_with(" www.example.com"));

        press(&mut app, &session, KeyCode::Char('3'));
        let lines = render(&session, &mut app, 130, 20, START_NS);
        assert!(find(&lines, "sendto").ends_with("  tcp 192.168.1.20:61000 -> www.example.com:443"));
        press(&mut app, &session, KeyCode::Char('n'));
        let lines = render(&session, &mut app, 130, 20, START_NS);
        assert!(find(&lines, "sendto").ends_with("  tcp 192.168.1.20:61000 -> 93.184.216.34:443"));
        assert!(lines.last().unwrap().contains("n names"));
        assert_eq!(app.view.hosts.asked(), 1, "only the server was looked up");
    }

    #[test]
    fn the_details_say_while_a_host_name_is_looked_up() {
        use ratatui::crossterm::event::KeyCode;

        use crate::hosts::{HostName, Hosts};
        let (session, mut app) = traced();
        app.view.hosts = Hosts::with_lookup(|_| HostName::None);
        press(&mut app, &session, KeyCode::Char('2'));
        press(&mut app, &session, KeyCode::Enter);
        let lines = render(&session, &mut app, 100, 30, START_NS);
        assert!(
            !lines.iter().any(|line| line.starts_with(" host ")),
            "names are off"
        );
        press(&mut app, &session, KeyCode::Char('n'));
        let lines = render(&session, &mut app, 100, 30, START_NS);
        assert!(find(&lines, " host ").ends_with(" looking up…"));
        // The files have no host line.
        press(&mut app, &session, KeyCode::Char('1'));
        press(&mut app, &session, KeyCode::Enter);
        let lines = render(&session, &mut app, 100, 30, START_NS);
        assert!(!lines.iter().any(|line| line.starts_with(" host ")));
        assert!(!lines.last().unwrap().contains("n names"));
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
    fn the_selected_row_is_marked_and_kept_in_view() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        let buffer = render_buffer(&session, &mut app, 100, 20, START_NS);
        let rows = marked(&buffer);
        assert!(rows.is_empty(), "nothing is selected at first: {rows:?}");
        let lines: Vec<String> = (0..buffer.area.height).map(|y| line(&buffer, y)).collect();
        assert!(lines.last().unwrap().ends_with("↑↓ select  enter details"));
        press(&mut app, &session, KeyCode::Down);
        let buffer = render_buffer(&session, &mut app, 100, 20, START_NS);
        let rows = marked(&buffer);
        assert!(
            rows.len() == 1 && rows[0].ends_with(" /Users/me/page.html"),
            "the first key selects the top row: {rows:?}"
        );
        let lines: Vec<String> = (0..buffer.area.height).map(|y| line(&buffer, y)).collect();
        assert!(
            lines
                .last()
                .unwrap()
                .ends_with("enter details  y copy  esc deselect")
        );
        press(&mut app, &session, KeyCode::Down);
        // One table row fits below the header.
        let buffer = render_buffer(&session, &mut app, 100, 8, START_NS);
        let rows = marked(&buffer);
        assert!(rows.len() == 1 && rows[0].ends_with(" /dev/ttys004"), "{rows:?}");
        let lines: Vec<String> = (0..buffer.area.height).map(|y| line(&buffer, y)).collect();
        assert!(
            find(&lines, "1 Files (2)").contains("2-2 of 2"),
            "{}",
            lines.join("\n")
        );
        press(&mut app, &session, KeyCode::Char('2'));
        let rows = marked(&render_buffer(&session, &mut app, 100, 20, START_NS));
        assert!(rows.is_empty(), "each table has its own selection: {rows:?}");
        press(&mut app, &session, KeyCode::End);
        let rows = marked(&render_buffer(&session, &mut app, 100, 20, START_NS));
        assert!(
            rows.len() == 1 && rows[0].ends_with(" tcp 93.184.216.34:443"),
            "{rows:?}"
        );
        press(&mut app, &session, KeyCode::Char('3'));
        let rows = marked(&render_buffer(&session, &mut app, 100, 20, START_NS));
        assert!(rows.is_empty(), "events are not selected: {rows:?}");
        press(&mut app, &session, KeyCode::Char('1'));
        press(&mut app, &session, KeyCode::Esc);
        let buffer = render_buffer(&session, &mut app, 100, 20, START_NS);
        assert!(marked(&buffer).is_empty(), "Esc lets go of the selection");
        assert!(!app.wants_quit());
    }

    #[test]
    fn details_describe_the_selected_target() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        let now = START_NS + 2_500_000_000;
        press(&mut app, &session, KeyCode::Enter);
        let lines = render(&session, &mut app, 100, 30, now);
        assert!(find(&lines, " details ").starts_with("  details ───"));
        assert!(lines.iter().any(|line| line == " /Users/me/page.html"));
        let totals: Vec<&str> = find(&lines, " written ").split_whitespace().collect();
        assert_eq!(
            totals,
            [
                "read", "0", "B", "in", "0", "calls", "written", "4.0", "KiB", "in", "1", "call", "failed",
                "0"
            ]
        );
        assert!(find(&lines, " latency ").contains(" on average, "));
        assert!(find(&lines, " used ").ends_with(", last 1s ago"));
        assert!(find(&lines, " processes ").ends_with(" 4242 curl"));
        assert!(find(&lines, " file ").ends_with(" no longer exists"));
        let recent = find(&lines, " recent ");
        assert!(
            recent.contains(" 4242  write ") && recent.contains(" 4096 "),
            "{recent}"
        );
        assert!(lines.last().unwrap().contains("esc close"));

        press(&mut app, &session, KeyCode::Char('2'));
        let lines = render(&session, &mut app, 100, 30, now);
        assert!(
            !lines.iter().any(|line| line.contains("details ─")),
            "no row is selected there yet"
        );
        press(&mut app, &session, KeyCode::Down);
        let lines = render(&session, &mut app, 100, 30, now);
        assert!(lines.iter().any(|line| line == " tcp 93.184.216.34:443"));
        assert!(find(&lines, " received ").contains(" sent 517 B in 1 call   failed 1"));
        assert!(find(&lines, " local ").ends_with(" 192.168.1.20:61000"));
        assert!(find(&lines, " interface ").ends_with(" en0"));
        assert!(
            !lines.iter().any(|line| line.starts_with(" file ")),
            "sockets have no file line"
        );
        // The panel ends above the footer.
        let start = lines
            .iter()
            .position(|line| line.starts_with(" recent "))
            .unwrap();
        let recent = &lines[start..lines.len() - 1];
        assert_eq!(recent.len(), 3, "three calls on the socket: {recent:?}");
        assert!(recent[2].contains("EAGAIN"));

        press(&mut app, &session, KeyCode::Char('3'));
        let lines = render(&session, &mut app, 100, 30, now);
        assert!(
            !lines.iter().any(|line| line.contains(" details ")),
            "the Events tab has no panel"
        );
    }

    #[test]
    fn esc_backs_out_before_quitting() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        press(&mut app, &session, KeyCode::Char('3'));
        press(&mut app, &session, KeyCode::Enter);
        assert!(!app.view.details, "Enter does nothing in the Events tab");
        press(&mut app, &session, KeyCode::Char('1'));
        press(&mut app, &session, KeyCode::Enter);
        assert!(
            app.view.details && app.view.has_selection(),
            "Enter selects the top row"
        );
        press(&mut app, &session, KeyCode::Esc);
        assert!(!app.view.details && app.view.has_selection() && !app.wants_quit());
        press(&mut app, &session, KeyCode::Enter);
        assert!(
            app.view.details,
            "Enter on a selected row shows its details again"
        );
        press(&mut app, &session, KeyCode::Enter);
        assert!(!app.view.details, "and hides them");
        press(&mut app, &session, KeyCode::Esc);
        assert!(!app.view.has_selection() && !app.wants_quit());
        press(&mut app, &session, KeyCode::Esc);
        assert!(app.wants_quit());
    }

    #[test]
    fn details_give_way_to_the_table_on_small_screens() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        press(&mut app, &session, KeyCode::Enter);
        // 14 lines leave the body 8: the table keeps a header and three rows, and the panel
        // shows its first three lines.
        let lines = render(&session, &mut app, 100, 14, START_NS);
        let header = lines.iter().position(|line| line.contains(" CALLS ")).unwrap();
        let panel = lines.iter().position(|line| line.contains(" details ")).unwrap();
        assert_eq!(panel - header, 4, "{}", lines.join("\n"));
        assert_eq!(lines[panel + 1], " /Users/me/page.html");
        assert!(lines[panel + 3].starts_with(" latency "));
        assert!(lines.last().unwrap().contains("esc close"));
        for (width, height) in [(1, 1), (20, 5), (40, 8), (80, 3), (100, 12)] {
            render(&session, &mut app, width, height, START_NS);
        }
    }

    #[test]
    fn paths_show_home_as_a_tilde_and_shorten_directory_by_directory() {
        use std::sync::Arc;

        use ratatui::crossterm::event::KeyCode;

        use crate::model::{IoEvent, Op, Provenance};
        use crate::session::Sink;
        let (session, mut app) = traced();
        app.view.home = Some("/Users/me".into());
        let long = "/Users/me/Library/Application Support/Google/Chrome/Default/Cache/Cache_Data/data_1";
        app.event(&IoEvent {
            time_ns: START_NS + 1_500_000_000,
            pid: PID,
            tid: 1,
            op: Op::Read,
            syscall: "read",
            fd: Some(9),
            requested: Some(1 << 20),
            bytes: Some(1 << 20),
            messages: None,
            errno: 0,
            latency_ns: Some(1_000),
            target: Arc::new(Target::File { path: long.into() }),
            provenance: Provenance::Traced,
            interface: Via::NoInterface,
        })
        .unwrap();
        let lines = render(&session, &mut app, 100, 20, START_NS);
        assert!(find(&lines, "~/page.html").ends_with("  ~/page.html"));
        // 100 columns leave the target 99 - 44 - 6 * 2 = 43 columns.
        let row = find(&lines, "data_1");
        assert!(
            row.ends_with("  ~/L/A/G/C/Default/Cache/Cache_Data/data_1"),
            "{row}"
        );

        press(&mut app, &session, KeyCode::Enter);
        let lines = render(&session, &mut app, 100, 30, START_NS);
        assert!(
            lines
                .iter()
                .any(|line| line.ends_with("/Cache/Cache_Data/data_1") && line.starts_with(" /Users/me/")),
            "the details keep the path whole: {}",
            lines.join("\n")
        );

        press(&mut app, &session, KeyCode::Char('3'));
        let lines = render(&session, &mut app, 130, 20, START_NS);
        assert!(find(&lines, " write ").ends_with("  ~/page.html"));
        assert!(find(&lines, " read ").ends_with("/Cache/Cache_Data/data_1"));
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
        assert!(lines.last().unwrap().contains("q quit  s sort  p pause"));
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
        for interfaces in [false, true] {
            app.view.interfaces = interfaces;
            for tab in ['1', '2', '3'] {
                press(&mut app, &session, ratatui::crossterm::event::KeyCode::Char(tab));
                for (width, height) in [(1, 1), (20, 5), (40, 8), (80, 3), (80, 12)] {
                    render(&session, &mut app, width, height, START_NS);
                }
            }
        }
    }

    /// Sends `bytes` from `peer` over `via` into the terminal UI.
    fn sent_over(app: &mut App, via: Via, peer: Target, bytes: u64) {
        use std::sync::Arc;

        use crate::model::{IoEvent, Op, Provenance};
        use crate::session::Sink;
        app.event(&IoEvent {
            time_ns: START_NS + 1_500_000_000,
            pid: PID,
            tid: 1,
            op: Op::Sendto,
            syscall: "sendto",
            fd: Some(9),
            requested: Some(bytes),
            bytes: Some(bytes),
            messages: None,
            errno: 0,
            latency_ns: Some(1_000),
            target: Arc::new(peer),
            provenance: Provenance::Traced,
            interface: via,
        })
        .unwrap();
    }

    #[test]
    fn i_shows_the_traffic_of_each_interface() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        let now = START_NS + 2_500_000_000;
        let lines = render(&session, &mut app, 100, 20, now);
        assert!(!lines.iter().any(|line| line.contains("INTERFACE")));
        assert!(lines.last().unwrap().contains("p pause  i interfaces  r reset"));
        press(&mut app, &session, KeyCode::Char('i'));
        let lines = render(&session, &mut app, 100, 20, now);
        let header: Vec<&str> = find(&lines, "INTERFACE").split_whitespace().collect();
        assert_eq!(header, ["INTERFACE", "RECEIVED/S", "SENT/S", "RECEIVED", "SENT"]);
        let en0: Vec<&str> = find(&lines, " en0 ").split_whitespace().collect();
        assert_eq!(en0, ["en0", "4.0", "KiB", "517", "B", "4.0", "KiB", "517", "B"]);
        // The columns line up with the rates above.
        assert_eq!(find(&lines, "INTERFACE").len(), find(&lines, "FILE READ").len());
        assert_eq!(find(&lines, " en0 ").len(), find(&lines, " total ").len());
        assert!(find(&lines, "1 Files (2)").starts_with(' '));

        // Before any network I/O, the table says so.
        press(&mut app, &session, KeyCode::Char('r'));
        let lines = render(&session, &mut app, 100, 20, now);
        assert!(find(&lines, "INTERFACE").contains("SENT"));
        assert!(find(&lines, "No network I/O yet.").starts_with(' '));
    }

    #[test]
    fn long_interface_names_widen_both_tables() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced_over("br-4f2a8c9d1e3b");
        press(&mut app, &session, KeyCode::Char('i'));
        let lines = render(&session, &mut app, 100, 20, START_NS);
        let bridge = find(&lines, " br-4f2a8c9d1e3b ");
        assert!(bridge.starts_with(" br-4f2a8c9d1e3b "), "{bridge}");
        // 16 columns for the name, then four of 12 with 2 between each.
        assert_eq!(bridge.len(), 16 + 4 * (2 + 12));
        assert_eq!(find(&lines, "FILE READ").len(), bridge.len());
        assert_eq!(find(&lines, " per second ").len(), bridge.len());
    }

    #[test]
    fn the_interface_table_folds_what_does_not_fit() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        let peer = || {
            Target::Socket(Endpoint {
                remote: Some("10.8.0.1:22".parse().unwrap()),
                ..Endpoint::unresolved(Proto::Tcp)
            })
        };
        sent_over(&mut app, Via::Interface("utun4".into()), peer(), 100);
        sent_over(&mut app, Via::Unknown, peer(), 40);
        let unix = Target::Socket(Endpoint {
            path: Some("/tmp/s".into()),
            ..Endpoint::unresolved(Proto::Unix)
        });
        sent_over(&mut app, Via::NoInterface, unix, 120);
        press(&mut app, &session, KeyCode::Char('i'));
        let now = START_NS + 2_500_000_000;
        let lines = render(&session, &mut app, 100, 20, now);
        let labels: Vec<&str> = lines
            .iter()
            .skip_while(|line| !line.contains("INTERFACE"))
            .skip(1)
            .take(4)
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        assert_eq!(labels, ["en0", "utun4", "?", "none"]);
        // 13 lines leave room for the header and two rows above the tabs and their body.
        let lines = render(&session, &mut app, 100, 13, now);
        assert!(find(&lines, " en0 ").contains("4.0 KiB"));
        let more: Vec<&str> = find(&lines, " 3 more ").split_whitespace().collect();
        assert_eq!(more, ["3", "more", "0", "B", "260", "B", "0", "B", "260", "B"]);
        assert!(find(&lines, "1 Files (2)").starts_with(' '));
        // Without room for a row, no table.
        let lines = render(&session, &mut app, 100, 11, now);
        assert!(!lines.iter().any(|line| line.contains("INTERFACE")));
    }

    #[test]
    fn the_interface_hint_gives_way_on_narrow_screens() {
        use ratatui::crossterm::event::KeyCode;
        let (session, mut app) = traced();
        press(&mut app, &session, KeyCode::Char('2'));
        let wide = render(&session, &mut app, 100, 20, START_NS);
        let footer = wide.last().unwrap();
        assert!(
            footer.ends_with("p pause  i interfaces  r reset  n names  ↑↓ select  enter details"),
            "{footer}"
        );
        let narrow = render(&session, &mut app, 80, 20, START_NS);
        let footer = narrow.last().unwrap();
        assert!(
            footer.ends_with("q quit  s sort  p pause  r reset  n names  ↑↓ select  enter details"),
            "{footer}"
        );
        // Files only: nothing to show by interface.
        let mut src = Fixed::default();
        let files_only = Filter {
            network: false,
            ..Filter::ALL
        };
        let session = Session::new(session.info().clone(), files_only, &mut src);
        let lines = render(&session, &mut app, 100, 20, START_NS);
        assert!(!lines.last().unwrap().contains("i interfaces"));
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
    }
}
