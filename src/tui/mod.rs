//! The live terminal UI (`--tui`).
//!
//! One thread hands pending input to the session for at most one frame, draws at most 20
//! frames a second and handles keys. Pausing freezes only the view: tracing goes on, so the
//! kernel buffer never waits for the user.

pub mod draw;
pub mod state;

use std::io::{self, IsTerminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::{cursor, execute, terminal};

use self::state::App;
use crate::session::Session;

/// Time between frames while input arrives.
const FRAME: Duration = Duration::from_millis(50);
/// Longest wait for a key once input has ended.
const IDLE: Duration = Duration::from_millis(250);

/// True while the terminal is in raw mode on the alternate screen.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Where the session's input comes from.
pub trait Feed {
    /// Hands input to the session until `until`, or until input ends; then says why it ended,
    /// as a sentence.
    fn pump(&mut self, session: &mut Session, app: &mut App, until: Instant) -> io::Result<Option<String>>;

    /// The time to show, in Unix nanoseconds.
    fn now_ns(&self, session: &Session) -> u64;

    /// True once iotap was asked to quit from outside the UI, e.g. by a signal.
    fn interrupted(&self) -> bool {
        false
    }
}

/// Runs the UI until the user quits, restoring the terminal on every path.
pub fn run(session: &mut Session, feed: &mut dyn Feed) -> io::Result<()> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            ratatui::restore();
            return Err(err);
        }
    };
    ACTIVE.store(true, Ordering::SeqCst);
    // Frames are drawn as differences from a blank screen. `Terminal::clear` would also work
    // but asks the terminal for the cursor position, which not every terminal answers.
    let result = execute!(io::stdout(), terminal::Clear(terminal::ClearType::All))
        .and_then(|()| run_loop(&mut terminal, session, feed));
    // Dropping the terminal shows the cursor again.
    drop(terminal);
    ACTIVE.store(false, Ordering::SeqCst);
    let restored = ratatui::try_restore();
    result.and(restored)
}

/// Restores the terminal from any thread, for exits that skip the normal path.
pub fn emergency_restore() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = terminal::disable_raw_mode();
        // stdout may be locked by the stuck main thread; stderr is the same terminal.
        let mut stderr = io::stderr();
        if stderr.is_terminal() {
            let _ = execute!(stderr, terminal::LeaveAlternateScreen, cursor::Show);
        }
    }
}

fn run_loop(terminal: &mut DefaultTerminal, session: &mut Session, feed: &mut dyn Feed) -> io::Result<()> {
    let mut app = App::default();
    let mut dirty = true;
    loop {
        if !app.has_ended() {
            if let Some(reason) = feed.pump(session, &mut app, Instant::now() + FRAME)? {
                app.end(reason);
            }
            // Time moves on while tracing, so every frame differs.
            dirty = true;
        }
        if feed.interrupted() {
            return Ok(());
        }
        if dirty {
            let now_ns = feed.now_ns(session);
            terminal.draw(|frame| {
                let shown = app.model.shown(session, now_ns);
                draw::draw(frame, &mut app.view, &shown);
            })?;
            dirty = false;
        }
        let wait = if app.has_ended() { IDLE } else { Duration::ZERO };
        if event::poll(wait)? {
            let now_ns = feed.now_ns(session);
            loop {
                if let Event::Key(key) = event::read()? {
                    app.key(key, session, now_ns);
                }
                // Resizes and other events only need a new frame.
                dirty = true;
                if app.wants_quit() {
                    return Ok(());
                }
                if !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
    }
}
