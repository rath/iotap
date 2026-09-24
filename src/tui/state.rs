//! What the terminal UI keeps between frames, and how keys change it.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::model::IoEvent;
use crate::output::text;
use crate::session::{Filter, Notice, ProcessStatus, Session, Sink};
use crate::stats::{SortBy, Stats};
use crate::sys::time::LocalClock;

/// Events kept for the Events tab.
pub const EVENT_CAPACITY: usize = 10_000;

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
    pub fn range(&self, from: u64, to: u64) -> impl Iterator<Item = &IoEvent> {
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

    pub fn index(self) -> usize {
        match self {
            Self::Files => 0,
            Self::Network => 1,
            Self::Events => 2,
        }
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn previous(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// What the last frame drew, so keys can scroll by pages and stop at the ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drawn {
    /// Table rows that fit on screen.
    pub page: usize,
    /// Rows of the Files or Network table.
    pub rows: usize,
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

/// Navigation: the tab, the sort order and where each table is scrolled to.
#[derive(Debug, Default)]
pub struct View {
    pub tab: Tab,
    pub sort: SortBy,
    /// First visible row of the Files and Network tables.
    pub offsets: [usize; 2],
    /// Sequence number of the lowest visible event; `None` follows the newest.
    pub bottom: Option<u64>,
    pub drawn: Drawn,
    /// Formats event times; a cache, not state.
    pub clock: LocalClock,
}

impl View {
    fn scroll(&mut self, motion: Motion) {
        let page = self.drawn.page.max(1);
        match self.tab {
            Tab::Files | Tab::Network => {
                let max = self.drawn.rows.saturating_sub(page);
                let offset = &mut self.offsets[self.tab.index()];
                let current = (*offset).min(max);
                *offset = match motion {
                    Motion::Up(n) => current.saturating_sub(n),
                    Motion::Down(n) => current.saturating_add(n).min(max),
                    Motion::Top => 0,
                    Motion::Bottom => max,
                };
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
    pub filter: Filter,
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
    quit: bool,
}

impl App {
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

    /// Applies a key press. Pausing copies what `session` holds at `now_ns`.
    pub fn key(&mut self, key: KeyEvent, session: &Session, now_ns: u64) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        let page = self.view.drawn.page.max(1);
        let view = &mut self.view;
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('1') => view.tab = Tab::Files,
            KeyCode::Char('2') => view.tab = Tab::Network,
            KeyCode::Char('3') => view.tab = Tab::Events,
            KeyCode::Tab | KeyCode::Right => view.tab = view.tab.next(),
            KeyCode::BackTab | KeyCode::Left => view.tab = view.tab.previous(),
            KeyCode::Char('s') => view.sort = view.sort.next(),
            KeyCode::Char('p' | ' ') => self.model.toggle_pause(session, now_ns),
            KeyCode::Char('r') => {
                self.model.reset(session, now_ns);
                view.offsets = [0; 2];
                view.bottom = None;
            }
            KeyCode::Up | KeyCode::Char('k') => view.scroll(Motion::Up(1)),
            KeyCode::Down | KeyCode::Char('j') => view.scroll(Motion::Down(1)),
            KeyCode::PageUp => view.scroll(Motion::Up(page)),
            KeyCode::PageDown => view.scroll(Motion::Down(page)),
            KeyCode::Home | KeyCode::Char('g') => view.scroll(Motion::Top),
            KeyCode::End | KeyCode::Char('G') => view.scroll(Motion::Bottom),
            _ => {}
        }
    }
}

impl Sink for App {
    fn event(&mut self, event: &IoEvent) -> io::Result<()> {
        self.model.stats.record(event);
        self.model.events.push(event.clone());
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
    use crate::model::{Op, Provenance, Target};
    use crate::session::{Input, Process, SessionInfo};
    use crate::sys::time::{ClockAnchor, Timebase};
    use crate::trace::pairing::PathRecords;
    use crate::trace::procs::Fixed;
    use crate::trace::synth::Synth;

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

    #[test]
    fn tables_scroll_within_their_rows() {
        let mut view = View {
            drawn: Drawn {
                page: 10,
                rows: 25,
                ..Drawn::default()
            },
            ..View::default()
        };
        view.scroll(Motion::Down(1));
        assert_eq!(view.offsets, [1, 0]);
        view.scroll(Motion::Down(100));
        assert_eq!(view.offsets, [15, 0]);
        view.scroll(Motion::Up(10));
        assert_eq!(view.offsets, [5, 0]);
        view.tab = Tab::Network;
        view.scroll(Motion::Bottom);
        assert_eq!(view.offsets, [5, 15]);
        view.drawn.rows = 3;
        view.scroll(Motion::Up(1));
        assert_eq!(view.offsets, [5, 0], "an offset past the end is clamped first");
    }

    #[test]
    fn events_follow_the_newest_until_scrolled_back() {
        let mut view = View {
            tab: Tab::Events,
            drawn: Drawn {
                page: 10,
                rows: 0,
                first: 100,
                end: 150,
            },
            ..View::default()
        };
        view.scroll(Motion::Down(1));
        assert_eq!(view.bottom, None);
        view.scroll(Motion::Up(1));
        assert_eq!(view.bottom, Some(148));
        view.scroll(Motion::Top);
        assert_eq!(view.bottom, Some(109), "the top page stays full");
        view.scroll(Motion::Up(5));
        assert_eq!(view.bottom, Some(109));
        view.scroll(Motion::Down(100));
        assert_eq!(view.bottom, None, "reaching the newest follows again");
        view.drawn.end = 105;
        view.scroll(Motion::Up(1));
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
            .handle(&Input::Records(records), &mut src, &mut app)
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
    fn reset_empties_the_view_but_not_the_session() {
        let (mut session, mut src) = session();
        let mut app = App::default();
        let mut synth = Synth::new(2_000, 10);
        let mut records = synth.io(1, 7, 4, 1, 5, 5);
        records.push(synth.lost_events());
        session
            .handle(&Input::Records(records), &mut src, &mut app)
            .unwrap();
        app.view.tab = Tab::Events;
        app.view.bottom = Some(0);
        app.view.offsets = [3, 4];
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
        assert_eq!(
            session.stats().totals().events,
            1,
            "the summary keeps every event"
        );

        let records = synth.io(1, 7, 3, 1, 8, 8);
        session
            .handle(&Input::Records(records), &mut src, &mut app)
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
            .handle(&Input::Records(records), &mut src, &mut app)
            .unwrap();
        app.key(press(KeyCode::Char('p')), &session, 10);
        app.key(press(KeyCode::Char('r')), &session, 20);
        let records = synth.io(1, 7, 4, 1, 6, 6);
        session
            .handle(&Input::Records(records), &mut src, &mut app)
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
