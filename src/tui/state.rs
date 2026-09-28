//! What the terminal UI keeps between frames, and how keys change it.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::io;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use unicode_width::UnicodeWidthStr;

use super::clipboard::Copied;
use crate::hosts::Hosts;
use crate::model::{Category, IoEvent};
use crate::output::text;
use crate::session::{Filter, Notice, ProcessStatus, Session, Sink};
use crate::stats::{Key, Peer, Row, SortBy, Stats};
use crate::sys::time::LocalClock;

/// Events kept for the Events tab.
pub const EVENT_CAPACITY: usize = 10_000;
/// Longest copied text the status line repeats whole; longer paths show their last name.
const BRIEF: usize = 40;

/// The latest events, numbered in arrival order from zero.
#[derive(Clone, Debug)]
pub struct Ring {
    events: VecDeque<IoEvent>,
    /// Sequence number of `events[0]`.
    first: u64,
    capacity: usize,
}

impl Ring {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            events: VecDeque::with_capacity(capacity.min(1024)),
            first: 0,
            capacity,
        }
    }

    pub fn push(&mut self, event: IoEvent) {
        if self.events.len() == self.capacity {
            self.events.pop_front();
            self.first += 1;
        }
        self.events.push_back(event);
    }

    /// Sequence number of the oldest event kept.
    pub fn first(&self) -> u64 {
        self.first
    }

    /// Sequence number of the next event, which is also the number of events so far.
    pub fn end(&self) -> u64 {
        self.first + self.events.len() as u64
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The kept events numbered `from..to`.
    pub fn range(&self, from: u64, to: u64) -> impl DoubleEndedIterator<Item = &IoEvent> {
        let index = |seq: u64| {
            usize::try_from(seq.saturating_sub(self.first))
                .map_or(self.events.len(), |i| i.min(self.events.len()))
        };
        let (start, end) = (index(from), index(to));
        self.events.range(start..end.max(start))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Files,
    Network,
    Events,
}

impl Tab {
    pub const ALL: [Self; 3] = [Self::Files, Self::Network, Self::Events];
    /// The tabs that list targets, for `--quiet`, which leaves out individual events.
    pub const TARGETS: [Self; 2] = [Self::Files, Self::Network];

    pub fn index(self) -> usize {
        match self {
            Self::Files => 0,
            Self::Network => 1,
            Self::Events => 2,
        }
    }

    /// True when the tab's table lists targets of `category`.
    pub fn lists(self, category: Category) -> bool {
        match self {
            Self::Files => category != Category::Network,
            Self::Network => category == Category::Network,
            Self::Events => false,
        }
    }

    /// Rows of the tab's table.
    pub fn rows(self, stats: &Stats) -> usize {
        [Category::File, Category::Network, Category::Other]
            .into_iter()
            .filter(|&category| self.lists(category))
            .map(|category| stats.targets(category))
            .sum()
    }
}

/// What the last frame drew, so keys can scroll by pages and stop at the ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drawn {
    /// Table rows that fit on screen.
    pub page: usize,
    /// Sequence numbers of the oldest kept event and of the next event.
    pub first: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Motion {
    Up(usize),
    Down(usize),
    Top,
    Bottom,
}

/// Navigation: the tab, the sort order, the selected rows and where each table is scrolled to.
#[derive(Debug)]
pub struct View {
    /// The tabs shown, in order; the first is shown first.
    pub tabs: &'static [Tab],
    pub tab: Tab,
    pub sort: SortBy,
    /// First visible row of the Files and Network tables.
    pub offsets: [usize; 2],
    /// Selected target of the Files and Network tables, which stays with its target as the
    /// order changes. Without one, a table shows its top rows as they change.
    pub selected: [Option<Key>; 2],
    /// True while the details of the selected row show below the Files and Network tables.
    pub details: bool,
    /// Sequence number of the lowest visible event; `None` follows the newest.
    pub bottom: Option<u64>,
    pub drawn: Drawn,
    /// Formats event times; a cache, not state.
    pub clock: LocalClock,
    /// Account names by uid, for file owners; a cache, not state.
    pub owners: HashMap<u32, Option<String>>,
    /// Home directory of the user who started iotap, which the tables write as `~`.
    pub home: Option<String>,
    /// True while remote addresses show as host names, which are looked up as they are shown.
    pub names: bool,
    /// Host names of remote addresses; a cache, not state.
    pub hosts: Hosts,
    /// True while network I/O shows by interface above the tabs.
    pub interfaces: bool,
}

impl Default for View {
    fn default() -> Self {
        Self::new(&Tab::ALL)
    }
}

impl View {
    pub fn new(tabs: &'static [Tab]) -> Self {
        Self {
            tabs,
            tab: tabs.first().copied().unwrap_or_default(),
            sort: SortBy::default(),
            offsets: [0; 2],
            selected: [None, None],
            details: false,
            bottom: None,
            drawn: Drawn::default(),
            clock: LocalClock::default(),
            owners: HashMap::new(),
            home: None,
            names: false,
            hosts: Hosts::default(),
            interfaces: false,
        }
    }

    /// Position of the current tab among the tabs shown.
    pub fn position(&self) -> usize {
        self.tabs.iter().position(|&tab| tab == self.tab).unwrap_or(0)
    }

    /// Shows the tab labelled `digit`, if there is one.
    fn select(&mut self, digit: char) {
        let index = digit.to_digit(10).and_then(|n| n.checked_sub(1));
        if let Some(&tab) = index.and_then(|i| self.tabs.get(i as usize)) {
            self.tab = tab;
        }
    }

    fn next_tab(&mut self) {
        let count = self.tabs.len().max(1);
        if let Some(&tab) = self.tabs.get((self.position() + 1) % count) {
            self.tab = tab;
        }
    }

    fn previous_tab(&mut self) {
        let count = self.tabs.len().max(1);
        if let Some(&tab) = self.tabs.get((self.position() + count - 1) % count) {
            self.tab = tab;
        }
    }

    /// Position of the selected row in the current table, whose rows `stats` holds, if a row
    /// is selected. A selected target no longer listed, as after a reset, is let go.
    pub fn selected_rank(&mut self, stats: &Stats) -> Option<usize> {
        let tab = self.tab;
        let selected = self.selected.get_mut(tab.index())?;
        let rank = selected
            .as_ref()
            .and_then(|key| stats.rank(|category| tab.lists(category), self.sort, key));
        if rank.is_none() {
            *selected = None;
        }
        rank
    }

    /// The selected row of the current table, if a row is selected.
    pub fn selected_row<'s>(&mut self, stats: &'s Stats) -> Option<(&'s Key, &'s Row)> {
        let tab = self.tab;
        let rank = self.selected_rank(stats)?;
        stats
            .page(|category| tab.lists(category), self.sort, rank, 1)
            .pop()
    }

    /// True when the current tab's table has a selected row.
    pub fn has_selection(&self) -> bool {
        self.selected.get(self.tab.index()).is_some_and(Option::is_some)
    }

    /// Selects the row ranked `rank` in the current table.
    fn select_rank(&mut self, stats: &Stats, rank: usize) {
        let tab = self.tab;
        let row = stats.page(|category| tab.lists(category), self.sort, rank, 1);
        if let Some(selected) = self.selected.get_mut(tab.index()) {
            *selected = row.first().map(|&(key, _)| key.clone());
        }
    }

    /// Lets go of the current table's selection, and of its details.
    fn deselect(&mut self) {
        if let Some(selected) = self.selected.get_mut(self.tab.index()) {
            *selected = None;
        }
        self.details = false;
    }

    /// Moves the selection of a table, or scrolls the Events tab.
    fn scroll(&mut self, motion: Motion, stats: &Stats) {
        let page = self.drawn.page.max(1);
        match self.tab {
            tab @ (Tab::Files | Tab::Network) => {
                let Some(last) = tab.rows(stats).checked_sub(1) else {
                    self.selected[tab.index()] = None;
                    return;
                };
                let wanted = match (self.selected_rank(stats), motion) {
                    (_, Motion::Bottom) => last,
                    // Without a selection, the first key selects the top row.
                    (None, _) | (Some(_), Motion::Top) => 0,
                    (Some(rank), Motion::Up(n)) => rank.saturating_sub(n),
                    (Some(rank), Motion::Down(n)) => rank.saturating_add(n).min(last),
                };
                self.select_rank(stats, wanted);
            }
            Tab::Events => {
                let Drawn { first, end, .. } = self.drawn;
                let Some(newest) = end.checked_sub(1) else {
                    self.bottom = None;
                    return;
                };
                // The lowest bottom row that still fills the page.
                let lowest = first.saturating_add(page as u64 - 1).min(newest);
                let current = self.bottom.unwrap_or(newest).clamp(lowest, newest);
                let wanted = match motion {
                    Motion::Up(n) => current.saturating_sub(n as u64).max(lowest),
                    Motion::Down(n) => current.saturating_add(n as u64).min(newest),
                    Motion::Top => lowest,
                    Motion::Bottom => newest,
                };
                self.bottom = (wanted < newest).then_some(wanted);
            }
        }
    }
}

/// A copy of what the screen showed when the view was paused. Tracing goes on meanwhile.
#[derive(Clone, Debug)]
struct Frozen {
    stats: Stats,
    events: Ring,
    processes: Vec<ProcessStatus>,
    lost_events: u64,
    now_ns: u64,
}

impl Frozen {
    fn of(model: &Model, session: &Session, now_ns: u64) -> Self {
        Self {
            stats: model.stats.clone(),
            events: model.events.clone(),
            processes: session.processes(),
            lost_events: model.lost_events(session),
            now_ns,
        }
    }
}

/// What one frame shows.
#[derive(Debug)]
pub struct Shown<'a> {
    pub stats: &'a Stats,
    pub events: &'a Ring,
    pub processes: Cow<'a, [ProcessStatus]>,
    pub lost_events: u64,
    /// Unix nanoseconds now and when tracing started, or when the view was last reset.
    pub now_ns: u64,
    pub start_ns: u64,
    /// True once the view has been reset.
    pub reset: bool,
    pub filter: &'a Filter,
    pub paused: bool,
    /// The latest notice.
    pub status: Option<&'a str>,
    /// Why tracing ended, once it has.
    pub ended: Option<&'a str>,
}

/// Where the screen's data comes from: what arrived since the view was last reset, or a copy
/// while paused. The session keeps its own statistics for the summary, which a reset leaves
/// alone.
#[derive(Debug)]
pub struct Model {
    stats: Stats,
    events: Ring,
    /// Records the kernel had dropped when the view was last reset.
    lost_before: u64,
    /// Unix nanoseconds of the last reset.
    reset_ns: Option<u64>,
    frozen: Option<Frozen>,
    status: Option<String>,
    ended: Option<String>,
    clock: LocalClock,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            stats: Stats::default(),
            events: Ring::new(EVENT_CAPACITY),
            lost_before: 0,
            reset_ns: None,
            frozen: None,
            status: None,
            ended: None,
            clock: LocalClock::default(),
        }
    }
}

impl Model {
    pub fn shown<'a>(&'a self, session: &'a Session, now_ns: u64) -> Shown<'a> {
        let (stats, events, processes, lost_events, now_ns) = match &self.frozen {
            Some(frozen) => (
                &frozen.stats,
                &frozen.events,
                Cow::Borrowed(frozen.processes.as_slice()),
                frozen.lost_events,
                frozen.now_ns,
            ),
            None => (
                &self.stats,
                &self.events,
                Cow::Owned(session.processes()),
                self.lost_events(session),
                now_ns,
            ),
        };
        Shown {
            stats,
            events,
            processes,
            lost_events,
            now_ns,
            start_ns: self.reset_ns.unwrap_or(session.info().anchor.unix_nanos),
            reset: self.reset_ns.is_some(),
            filter: session.filter(),
            paused: self.frozen.is_some(),
            status: self.status.as_deref(),
            ended: self.ended.as_deref(),
        }
    }

    /// Records the kernel dropped since the view was last reset.
    fn lost_events(&self, session: &Session) -> u64 {
        session.lost_events().saturating_sub(self.lost_before)
    }

    /// The statistics shown: live, or the copy taken when the view was paused.
    fn stats(&self) -> &Stats {
        self.frozen.as_ref().map_or(&self.stats, |frozen| &frozen.stats)
    }

    fn toggle_pause(&mut self, session: &Session, now_ns: u64) {
        self.frozen = match self.frozen.take() {
            Some(_) => None,
            None => Some(Frozen::of(self, session, now_ns)),
        };
    }

    /// Forgets the statistics and events shown so far; a paused view stays paused, now empty.
    fn reset(&mut self, session: &Session, now_ns: u64) {
        self.stats = Stats::default();
        self.events = Ring::new(EVENT_CAPACITY);
        self.lost_before = session.lost_events();
        self.reset_ns = Some(now_ns);
        if self.frozen.is_some() {
            self.frozen = Some(Frozen::of(self, session, now_ns));
        }
        let mut time = self.clock.format(now_ns);
        time.truncate(8);
        self.status = Some(format!("view reset at {time}"));
    }
}

/// The terminal UI's state. It is also the session's sink while the UI runs.
#[derive(Debug, Default)]
pub struct App {
    pub view: View,
    pub model: Model,
    /// Text a key asked to copy, until the frame loop copies it.
    copy: Option<String>,
    quit: bool,
}

impl App {
    /// An app showing `tabs`; without the Events tab, events are not kept at all.
    pub fn new(tabs: &'static [Tab]) -> Self {
        Self {
            view: View::new(tabs),
            ..Self::default()
        }
    }

    fn keeps_events(&self) -> bool {
        self.view.tabs.contains(&Tab::Events)
    }

    /// Shows `text` in the status line.
    pub fn message(&mut self, text: String) {
        self.model.status = Some(text);
    }

    /// Records that no more input will come, and why.
    pub fn end(&mut self, reason: String) {
        self.model.ended = Some(reason);
    }

    pub fn has_ended(&self) -> bool {
        self.model.ended.is_some()
    }

    pub fn wants_quit(&self) -> bool {
        self.quit
    }

    /// Text a key asked to copy, once.
    pub fn take_copy(&mut self) -> Option<String> {
        self.copy.take()
    }

    /// Says in the status line how copying `text` went.
    pub fn copied(&mut self, text: &str, copied: &Copied) {
        let text = brief(text);
        self.model.status = Some(match copied {
            Copied::Pasteboard => format!("copied {text}"),
            Copied::Terminal(None) => format!("asked the terminal to copy {text}"),
            Copied::Terminal(Some(why)) => {
                format!("asked the terminal to copy {text}; pbcopy failed: {why}")
            }
        });
    }

    /// Applies a key press. Pausing copies what `session` holds at `now_ns`.
    pub fn key(&mut self, key: KeyEvent, session: &Session, now_ns: u64) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        // Ctrl and Alt make other keys of the letters, ones that habits of the shell and the
        // terminal reach for: Ctrl-S, Ctrl-R, Ctrl-P, Ctrl-N, Ctrl-Q. Only Ctrl-C is iotap's.
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if (ctrl || key.modifiers.contains(KeyModifiers::ALT)) && !(ctrl && key.code == KeyCode::Char('c')) {
            return;
        }
        let page = self.view.drawn.page.max(1);
        let view = &mut self.view;
        let table = view.tab != Tab::Events;
        let selected = view.selected_rank(self.model.stats()).is_some();
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Enter if table && selected => view.details = !view.details,
            // Enter on a table without a selection shows the details of its top row.
            KeyCode::Enter if table && view.tab.rows(self.model.stats()) > 0 => {
                view.select_rank(self.model.stats(), 0);
                view.details = true;
            }
            // Esc backs out a step at a time: the details, the selection, then iotap.
            KeyCode::Esc if table && selected && view.details => view.details = false,
            KeyCode::Esc if table && selected => view.deselect(),
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char(digit @ '1'..='9') => view.select(digit),
            KeyCode::Tab | KeyCode::Right => view.next_tab(),
            KeyCode::BackTab | KeyCode::Left => view.previous_tab(),
            KeyCode::Char('s') => view.sort = view.sort.next(),
            KeyCode::Char('p' | ' ') => self.model.toggle_pause(session, now_ns),
            KeyCode::Char('y') if table => {
                let key = view.selected_row(self.model.stats()).map(|(key, _)| key.clone());
                match key {
                    Some(key) => match copy_text(&key) {
                        Some(text) => self.copy = Some(text),
                        None => self.model.status = Some(format!("nothing to copy for {key}")),
                    },
                    None if view.tab.rows(self.model.stats()) > 0 => {
                        self.model.status = Some("select a row to copy with ↑ or ↓".to_owned());
                    }
                    None => {}
                }
            }
            KeyCode::Char('n') => {
                view.names = !view.names;
                self.model.status = Some(if view.names {
                    "showing host names".to_owned()
                } else {
                    "showing addresses".to_owned()
                });
            }
            KeyCode::Char('i') if session.filter().network => {
                view.interfaces = !view.interfaces;
                self.model.status = Some(if view.interfaces {
                    "showing network I/O by interface".to_owned()
                } else {
                    "hiding network I/O by interface".to_owned()
                });
            }
            KeyCode::Char('i') => self.model.status = Some("network I/O is not traced".to_owned()),
            KeyCode::Char('r') => {
                self.model.reset(session, now_ns);
                view.offsets = [0; 2];
                view.selected = [None, None];
                view.details = false;
                view.bottom = None;
            }
            KeyCode::Up | KeyCode::Char('k') => view.scroll(Motion::Up(1), self.model.stats()),
            KeyCode::Down | KeyCode::Char('j') => view.scroll(Motion::Down(1), self.model.stats()),
            KeyCode::PageUp => view.scroll(Motion::Up(page), self.model.stats()),
            KeyCode::PageDown => view.scroll(Motion::Down(page), self.model.stats()),
            KeyCode::Home | KeyCode::Char('g') => view.scroll(Motion::Top, self.model.stats()),
            KeyCode::End | KeyCode::Char('G') => view.scroll(Motion::Bottom, self.model.stats()),
            _ => {}
        }
    }
}

/// What copying a target puts on the clipboard: a file's path, or a socket's address or path.
fn copy_text(key: &Key) -> Option<String> {
    match key {
        Key::File(path)
        | Key::Socket {
            peer: Peer::Path(path),
            ..
        } if !path.is_empty() => Some(path.clone()),
        Key::Socket {
            peer: Peer::Remote(addr) | Peer::Local(addr),
            ..
        } => Some(addr.to_string()),
        _ => None,
    }
}

/// `text` as the status line repeats it: whole when short, else its last path name.
fn brief(text: &str) -> Cow<'_, str> {
    if text.width() <= BRIEF {
        return Cow::Borrowed(text);
    }
    match text.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => Cow::Owned(format!("…/{name}")),
        _ => Cow::Borrowed(text),
    }
}

impl Sink for App {
    fn event(&mut self, event: &IoEvent) -> io::Result<()> {
        self.model.stats.record(event);
        if self.keeps_events() {
            self.model.events.push(event.clone());
        }
        Ok(())
    }

    fn notice(&mut self, notice: &Notice) -> io::Result<()> {
        let text = text::notice_text(notice, &mut self.model.clock);
        self.model.status = Some(text);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::model::{Op, Provenance, Target, Via};
    use crate::session::{Input, Process, SessionInfo};
    use crate::sys::time::{ClockAnchor, Timebase};
    use crate::trace::kdebug::pairing::PathRecords;
    use crate::trace::kdebug::synth::Synth;
    use crate::trace::procs::Fixed;
    use crate::trace::{Records, System};

    fn event(time_ns: u64) -> IoEvent {
        IoEvent {
            time_ns,
            pid: 1,
            tid: 1,
            op: Op::Read,
            syscall: "read",
            fd: Some(3),
            requested: Some(10),
            bytes: Some(10),
            messages: None,
            errno: 0,
            latency_ns: Some(1_000),
            target: Arc::new(Target::File { path: "/a".into() }),
            provenance: Provenance::Traced,
            interface: Via::NoInterface,
        }
    }

    fn session() -> (Session, Fixed) {
        let info = SessionInfo {
            timebase: Timebase { numer: 1, denom: 1 },
            anchor: ClockAnchor {
                ticks: 1_000,
                unix_nanos: 1_000_000_000_000,
            },
            processes: vec![Process {
                pid: 7,
                name: "demo".into(),
            }],
            path_records: PathRecords::Whole,
            system: System::Macos,
        };
        let mut src = Fixed::default();
        let session = Session::new(info, Filter::ALL, &mut src);
        (session, src)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn ring_keeps_the_latest_events_and_numbers_them() {
        let mut ring = Ring::new(3);
        for t in 0..5 {
            ring.push(event(t));
        }
        assert_eq!((ring.first(), ring.end(), ring.len()), (2, 5, 3));
        let times: Vec<u64> = ring.range(0, 4).map(|e| e.time_ns).collect();
        assert_eq!(times, [2, 3]);
        assert_eq!(ring.range(4, 99).count(), 1);
        assert_eq!(ring.range(4, 3).count(), 0);
    }

    /// A write of `bytes` to `path`.
    fn write(path: &str, bytes: u64, time_ns: u64) -> IoEvent {
        IoEvent {
            op: Op::Write,
            syscall: "write",
            bytes: Some(bytes),
            target: Arc::new(Target::File { path: path.into() }),
            ..event(time_ns)
        }
    }

    #[test]
    fn table_selection_moves_by_rank_and_stays_with_its_target() {
        let mut stats = Stats::default();
        for (path, bytes) in [("/a", 50), ("/b", 40), ("/c", 30), ("/d", 20), ("/e", 10)] {
            stats.record(&write(path, bytes, 0));
        }
        let mut view = View {
            drawn: Drawn {
                page: 2,
                ..Drawn::default()
            },
            ..View::default()
        };
        let selected = |view: &View| view.selected[0].as_ref().map(ToString::to_string);
        assert_eq!(view.selected_rank(&stats), None, "nothing is selected at first");
        assert!(!view.has_selection());
        view.scroll(Motion::Down(1), &stats);
        assert_eq!(
            selected(&view).as_deref(),
            Some("/a"),
            "the first key selects the top row"
        );
        view.scroll(Motion::Down(1), &stats);
        assert_eq!(selected(&view).as_deref(), Some("/b"));
        view.scroll(Motion::Down(2), &stats);
        assert_eq!(selected(&view).as_deref(), Some("/d"));
        view.scroll(Motion::Down(9), &stats);
        assert_eq!(selected(&view).as_deref(), Some("/e"), "stops at the last row");
        view.scroll(Motion::Up(1), &stats);
        assert_eq!(selected(&view).as_deref(), Some("/d"));

        stats.record(&write("/d", 1_000, 1));
        assert_eq!(
            view.selected_rank(&stats),
            Some(0),
            "the selection moves with its target"
        );
        view.scroll(Motion::Down(1), &stats);
        assert_eq!(selected(&view).as_deref(), Some("/a"));
        view.scroll(Motion::Bottom, &stats);
        assert_eq!(selected(&view).as_deref(), Some("/e"));
        view.scroll(Motion::Top, &stats);
        assert_eq!(selected(&view).as_deref(), Some("/d"), "Home selects the top row");

        view.deselect();
        assert!(!view.has_selection());
        view.scroll(Motion::Bottom, &stats);
        assert_eq!(selected(&view).as_deref(), Some("/e"), "End selects the last row");
        view.deselect();
        view.scroll(Motion::Up(1), &stats);
        assert_eq!(selected(&view).as_deref(), Some("/d"));

        view.tab = Tab::Network;
        view.scroll(Motion::Down(1), &stats);
        assert_eq!(view.selected[1], None, "an empty table selects nothing");
        view.tab = Tab::Files;
        view.selected[0] = Some(Key::File("/gone".into()));
        assert_eq!(view.selected_rank(&stats), None);
        assert_eq!(view.selected[0], None, "a target no longer listed is let go");
    }

    #[test]
    fn events_follow_the_newest_until_scrolled_back() {
        let stats = Stats::default();
        let mut view = View {
            tab: Tab::Events,
            drawn: Drawn {
                page: 10,
                first: 100,
                end: 150,
            },
            ..View::default()
        };
        view.scroll(Motion::Down(1), &stats);
        assert_eq!(view.bottom, None);
        view.scroll(Motion::Up(1), &stats);
        assert_eq!(view.bottom, Some(148));
        view.scroll(Motion::Top, &stats);
        assert_eq!(view.bottom, Some(109), "the top page stays full");
        view.scroll(Motion::Up(5), &stats);
        assert_eq!(view.bottom, Some(109));
        view.scroll(Motion::Down(100), &stats);
        assert_eq!(view.bottom, None, "reaching the newest follows again");
        view.drawn.end = 105;
        view.scroll(Motion::Up(1), &stats);
        assert_eq!(view.bottom, None, "fewer events than a page cannot scroll");
    }

    #[test]
    fn keys_switch_tabs_sort_pause_and_quit() {
        let (mut session, mut src) = session();
        let mut app = App::default();
        app.key(press(KeyCode::Char('3')), &session, 0);
        assert_eq!(app.view.tab, Tab::Events);
        app.key(press(KeyCode::Tab), &session, 0);
        assert_eq!(app.view.tab, Tab::Files);
        app.key(press(KeyCode::Left), &session, 0);
        assert_eq!(app.view.tab, Tab::Events);
        app.key(press(KeyCode::Char('s')), &session, 0);
        assert_eq!(app.view.sort, SortBy::Read);

        let mut synth = Synth::new(2_000, 10);
        let records = synth.io(1, 7, 4, 1, 5, 5);
        app.key(press(KeyCode::Char('p')), &session, 42);
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        let shown = app.model.shown(&session, 99);
        assert!(shown.paused);
        assert_eq!(
            (shown.now_ns, shown.events.len(), shown.stats.totals().events),
            (42, 0, 0)
        );
        app.key(press(KeyCode::Char(' ')), &session, 99);
        let shown = app.model.shown(&session, 99);
        assert!(!shown.paused);
        assert_eq!(
            (shown.now_ns, shown.events.len(), shown.stats.totals().events),
            (99, 1, 1)
        );

        assert!(!app.wants_quit());
        app.key(
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &session,
            0,
        );
        assert!(app.wants_quit());
    }

    #[test]
    fn i_shows_network_io_by_interface_when_it_is_traced() {
        let (session, _) = session();
        let mut app = App::default();
        app.key(press(KeyCode::Char('i')), &session, 0);
        assert!(app.view.interfaces);
        assert_eq!(
            app.model.shown(&session, 0).status,
            Some("showing network I/O by interface")
        );
        // A reset leaves the view's layout alone.
        app.key(press(KeyCode::Char('r')), &session, 0);
        assert!(app.view.interfaces);
        app.key(press(KeyCode::Char('i')), &session, 0);
        assert!(!app.view.interfaces);

        let mut src = Fixed::default();
        let files_only = Filter {
            network: false,
            ..Filter::ALL
        };
        let session = Session::new(session.info().clone(), files_only, &mut src);
        app.key(press(KeyCode::Char('i')), &session, 0);
        assert!(!app.view.interfaces);
        assert_eq!(
            app.model.shown(&session, 0).status,
            Some("network I/O is not traced")
        );
    }

    #[test]
    fn without_the_events_tab_keys_skip_it_and_events_are_not_kept() {
        let (mut session, mut src) = session();
        let mut app = App::new(&Tab::TARGETS);
        app.key(press(KeyCode::Char('3')), &session, 0);
        assert_eq!(app.view.tab, Tab::Files);
        app.key(press(KeyCode::Char('2')), &session, 0);
        assert_eq!(app.view.tab, Tab::Network);
        app.key(press(KeyCode::Tab), &session, 0);
        assert_eq!(app.view.tab, Tab::Files);
        app.key(press(KeyCode::Left), &session, 0);
        assert_eq!(app.view.tab, Tab::Network);
        app.key(press(KeyCode::Right), &session, 0);
        assert_eq!(app.view.tab, Tab::Files);

        let mut synth = Synth::new(2_000, 10);
        let records = synth.io(1, 7, 4, 1, 5, 5);
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        let shown = app.model.shown(&session, 0);
        assert_eq!((shown.events.len(), shown.stats.totals().events), (0, 1));
    }

    #[test]
    fn reset_empties_the_view_but_not_the_session() {
        let (mut session, mut src) = session();
        let mut app = App::default();
        let mut synth = Synth::new(2_000, 10);
        let mut records = synth.io(1, 7, 4, 1, 5, 5);
        records.push(synth.lost_events());
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        app.view.tab = Tab::Events;
        app.view.bottom = Some(0);
        app.view.offsets = [3, 4];
        app.view.selected = [Some(Key::File("/a".into())), None];
        app.view.details = true;
        assert_eq!(app.model.shown(&session, 0).lost_events, 1);

        app.key(press(KeyCode::Char('r')), &session, 5_000_000_000);
        let shown = app.model.shown(&session, 7_000_000_000);
        assert_eq!(
            (shown.events.len(), shown.stats.totals().events, shown.lost_events),
            (0, 0, 0)
        );
        assert!(shown.reset);
        assert_eq!(shown.start_ns, 5_000_000_000);
        assert!(shown.status.is_some_and(|s| s.starts_with("view reset at ")));
        assert_eq!((app.view.bottom, app.view.offsets), (None, [0, 0]));
        assert_eq!(app.view.selected, [None, None]);
        assert!(!app.view.details, "a reset closes the details");
        assert_eq!(
            session.stats().totals().events,
            1,
            "the summary keeps every event"
        );

        let records = synth.io(1, 7, 3, 1, 8, 8);
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        let shown = app.model.shown(&session, 0);
        assert_eq!((shown.events.len(), shown.stats.totals().events), (1, 1));
        assert_eq!(shown.events.range(0, 1).next().unwrap().bytes, Some(8));
        assert_eq!(session.stats().totals().events, 2);
    }

    #[test]
    fn reset_while_paused_stays_paused_and_empty() {
        let (mut session, mut src) = session();
        let mut app = App::default();
        let mut synth = Synth::new(2_000, 10);
        let records = synth.io(1, 7, 4, 1, 5, 5);
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        app.key(press(KeyCode::Char('p')), &session, 10);
        app.key(press(KeyCode::Char('r')), &session, 20);
        let records = synth.io(1, 7, 4, 1, 6, 6);
        session
            .handle(&Input::Records(Records::Kdebug(records)), &mut src, &mut app)
            .unwrap();
        let shown = app.model.shown(&session, 30);
        assert!(shown.paused);
        assert_eq!(
            (shown.now_ns, shown.events.len(), shown.stats.totals().events),
            (20, 0, 0)
        );
        app.key(press(KeyCode::Char('p')), &session, 30);
        let shown = app.model.shown(&session, 30);
        assert_eq!(
            (shown.events.len(), shown.stats.totals().events),
            (1, 1),
            "what arrived while paused after the reset shows on resume"
        );
    }

    #[test]
    fn y_asks_to_copy_the_selected_target() {
        use crate::model::{Endpoint, FdType, Proto};
        let (session, _) = session();
        let mut app = App::default();
        let status = |app: &App| app.model.shown(&session, 0).status.map(str::to_owned);
        app.event(&write("/b/long", 10, 0)).unwrap();
        app.event(&write("/a", 50, 0)).unwrap();
        app.event(&IoEvent {
            target: Arc::new(Target::Other {
                fd_type: FdType::Pipe,
            }),
            ..write("", 1, 0)
        })
        .unwrap();
        app.event(&IoEvent {
            target: Arc::new(Target::Socket(Endpoint {
                proto: Proto::Tcp,
                local: Some("10.0.0.1:5000".parse().unwrap()),
                remote: Some("1.2.3.4:443".parse().unwrap()),
                path: None,
            })),
            ..write("", 1, 0)
        })
        .unwrap();

        app.key(press(KeyCode::Char('y')), &session, 0);
        assert_eq!(app.take_copy(), None, "nothing is selected yet");
        assert_eq!(status(&app).as_deref(), Some("select a row to copy with ↑ or ↓"));
        app.key(press(KeyCode::Down), &session, 0);
        app.key(press(KeyCode::Char('y')), &session, 0);
        assert_eq!(app.take_copy().as_deref(), Some("/a"));
        assert_eq!(app.take_copy(), None, "each press asks once");
        app.key(press(KeyCode::Down), &session, 0);
        app.key(press(KeyCode::Char('y')), &session, 0);
        assert_eq!(app.take_copy().as_deref(), Some("/b/long"));
        app.key(press(KeyCode::End), &session, 0);
        app.key(press(KeyCode::Char('y')), &session, 0);
        assert_eq!(app.take_copy(), None);
        assert_eq!(status(&app).as_deref(), Some("nothing to copy for <pipe>"));
        app.key(press(KeyCode::Char('2')), &session, 0);
        app.key(press(KeyCode::Down), &session, 0);
        app.key(press(KeyCode::Char('y')), &session, 0);
        assert_eq!(app.take_copy().as_deref(), Some("1.2.3.4:443"));
        app.key(press(KeyCode::Char('3')), &session, 0);
        app.key(press(KeyCode::Char('y')), &session, 0);
        assert_eq!(app.take_copy(), None, "the Events tab has no selection");

        app.copied("/b/long", &Copied::Pasteboard);
        assert_eq!(status(&app).as_deref(), Some("copied /b/long"));
        let long = format!("/{}/leaf.txt", "d".repeat(40));
        app.copied(&long, &Copied::Terminal(Some("pbcopy exit status: 1".into())));
        assert_eq!(
            status(&app).as_deref(),
            Some("asked the terminal to copy …/leaf.txt; pbcopy failed: pbcopy exit status: 1")
        );
        app.copied("/b/long", &Copied::Terminal(None));
        assert_eq!(
            status(&app).as_deref(),
            Some("asked the terminal to copy /b/long")
        );
    }

    #[test]
    fn keys_held_with_ctrl_or_alt_are_not_the_plain_keys() {
        let (session, _) = session();
        let mut app = App::default();
        app.event(&write("/a", 10, 0)).unwrap();
        for held in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            // Habits of the shell and the terminal: Ctrl-S, Ctrl-R, Ctrl-P, Ctrl-N and so on.
            for code in "qspnriy2".chars() {
                app.key(KeyEvent::new(KeyCode::Char(code), held), &session, 0);
            }
            app.key(KeyEvent::new(KeyCode::Tab, held), &session, 0);
        }
        assert!(!app.wants_quit());
        assert!(!app.model.shown(&session, 0).paused);
        assert_eq!(app.view.sort, SortBy::default());
        assert_eq!(app.view.tab, Tab::Files);
        assert!(!app.view.interfaces && !app.view.names);
        assert_eq!(
            app.view.tab.rows(app.model.stats()),
            1,
            "Ctrl-R did not reset the view"
        );
        // Ctrl-C still ends iotap, as it does when the terminal sends no SIGINT.
        app.key(
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &session,
            0,
        );
        assert!(app.wants_quit());
    }

    #[test]
    fn notices_and_endings_reach_the_status_line() {
        let (session, _) = session();
        let mut app = App::default();
        app.notice(&Notice::Exited(Process {
            pid: 7,
            name: "demo".into(),
        }))
        .unwrap();
        app.end("every traced process has exited".into());
        let shown = app.model.shown(&session, 0);
        assert_eq!(shown.status, Some("7 (demo) exited"));
        assert_eq!(shown.ended, Some("every traced process has exited"));
        assert!(app.has_ended());
    }
}
