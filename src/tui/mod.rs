//! The live terminal UI (`--tui`).
//!
//! One thread hands pending input to the session for at most one frame, draws at most 20
//! frames a second and handles keys. Pausing freezes only the view: tracing goes on, so the
//! kernel buffer never waits for the user. Host names are looked up by threads of their own and
//! taken in between frames, so no frame waits for the resolver.

pub mod clipboard;
mod details;
pub mod draw;
mod fit;
pub mod state;

use std::fs::File;
use std::io::{self, IsTerminal};
use std::os::fd::AsFd;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::{cursor, execute, terminal};
use ratatui::{DefaultTerminal, Terminal};

use self::state::App;
use crate::session::Session;
use crate::sys::user;

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

/// Runs the UI of `app` until the user quits, restoring the terminal on every path.
pub fn run(session: &mut Session, feed: &mut dyn Feed, app: &mut App) -> io::Result<()> {
    install_panic_hook();
    let mut terminal = match enter() {
        Ok(terminal) => terminal,
        Err(err) => {
            let _ = ratatui::try_restore();
            return Err(err);
        }
    };
    ACTIVE.store(true, Ordering::SeqCst);
    // Frames are drawn as differences from a blank screen. `Terminal::clear` would also work
    // but asks the terminal for the cursor position, which not every terminal answers.
    let result = execute!(io::stdout(), terminal::Clear(terminal::ClearType::All))
        .and_then(|()| run_loop(&mut terminal, session, feed, app));
    // Shows the cursor again, which dropping the terminal would too. That prints to stderr
    // when it fails, as it does once the terminal has hung up, and printing to a stderr that
    // cannot be written to panics: in this hook-less path the process would abort.
    let _ = terminal.show_cursor();
    std::mem::forget(terminal);
    ACTIVE.store(false, Ordering::SeqCst);
    let restored = ratatui::try_restore();
    result.and(restored)
}

/// Takes the terminal: raw mode, on the alternate screen. This is `ratatui::try_init` without
/// the panic hook it installs. That hook prints with `eprintln!`, which panics when the
/// terminal has hung up, and a panic inside a panic hook aborts the process before the hook of
/// [`crate::app`] has released the trace facility.
fn enter() -> io::Result<DefaultTerminal> {
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), terminal::EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(io::stdout()))
}

/// Restores the terminal before the message of a panic is printed, so that the message reaches
/// the normal screen. Whatever fails is ignored: a terminal that has hung up cannot be restored.
fn install_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            emergency_restore();
            previous(info);
        }));
    });
}

/// True while the terminal UI is up: from when it takes the terminal until it gives it back.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// Restores the terminal from any thread, for exits that skip the normal path.
pub fn emergency_restore() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = terminal::disable_raw_mode();
        leave_screen();
    }
}

/// Leaves the alternate screen and shows the cursor, on whichever of stderr and stdout is the
/// terminal, through a duplicate of its descriptor. Not through `io::stdout()`, which the
/// thread that is stuck writing to a terminal that does not drain may hold locked; and not to
/// stderr alone, which may be redirected to a file.
fn leave_screen() {
    let (stderr, stdout) = (io::stderr(), io::stdout());
    let terminal = [stderr.as_fd(), stdout.as_fd()]
        .into_iter()
        .find(IsTerminal::is_terminal)
        .and_then(|fd| fd.try_clone_to_owned().ok());
    if let Some(fd) = terminal {
        let mut out = File::from(fd);
        let _ = execute!(out, terminal::LeaveAlternateScreen, cursor::Show);
    }
}

fn run_loop(
    terminal: &mut DefaultTerminal,
    session: &mut Session,
    feed: &mut dyn Feed,
    app: &mut App,
) -> io::Result<()> {
    app.view.home = user::invoking().map(|account| account.home.to_string_lossy().into_owned());
    let mut dirty = true;
    loop {
        if !app.has_ended() {
            if let Some(reason) = feed.pump(session, app, Instant::now() + FRAME)? {
                app.end(reason);
            }
            // Time moves on while tracing, so every frame differs.
            dirty = true;
        }
        if app.view.hosts.collect() {
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
                    if let Some(text) = app.take_copy() {
                        let copied = clipboard::copy(&text)?;
                        app.copied(&text, &copied);
                    }
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
