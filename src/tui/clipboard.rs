//! Copies text to the clipboard: through the terminal, and through the pasteboard of the Mac
//! iotap runs on.

use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::clipboard::CopyToClipboard;
use crossterm::execute;

use crate::sys::{self, user};

/// Longest wait for `pbcopy`.
const PBCOPY_TIMEOUT: Duration = Duration::from_secs(1);

/// How a copy went.
#[derive(Debug, PartialEq, Eq)]
pub enum Copied {
    /// The pasteboard has the text; the terminal was asked to copy it too.
    Pasteboard,
    /// Only the terminal was asked to copy the text, which it may ignore; `pbcopy` failed for
    /// the reason given.
    Terminal(String),
}

/// Copies `text` both ways: the terminal's clipboard (OSC 52) reaches the machine the user sits
/// at even over SSH, where terminals allow it; `pbcopy` reaches this Mac's pasteboard in any
/// terminal.
pub fn copy(text: &str) -> io::Result<Copied> {
    execute!(io::stdout(), CopyToClipboard::to_clipboard_from(text))?;
    Ok(match pbcopy(text) {
        Ok(()) => Copied::Pasteboard,
        Err(err) => Copied::Terminal(err.to_string()),
    })
}

/// Runs `pbcopy` as the user who started iotap, so the text reaches their pasteboard rather
/// than root's.
fn pbcopy(text: &str) -> io::Result<()> {
    let mut command = Command::new("/usr/bin/pbcopy");
    // pbcopy reads its input in the encoding LANG names.
    command
        .env_clear()
        .env("LANG", "en_US.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if sys::is_root()
        && let Some(account) = user::invoking().filter(|account| account.uid != 0)
    {
        command.uid(account.uid).gid(account.gid);
    }
    let mut child = command.spawn()?;
    let written = child
        .stdin
        .take()
        .map_or(Ok(()), |mut stdin| stdin.write_all(text.as_bytes()));
    // The child sees the end of its input once `stdin` is dropped above.
    let finished = wait(&mut child, Instant::now() + PBCOPY_TIMEOUT);
    written?;
    finished
}

fn wait(child: &mut Child, deadline: Instant) -> io::Result<()> {
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("pbcopy {status}")))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("pbcopy did not finish"));
        }
        thread::sleep(Duration::from_millis(5));
    }
}
