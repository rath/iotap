//! Copies text to the clipboard: through the terminal, and on macOS through the pasteboard of
//! the Mac iotap runs on.

use std::io;

use crossterm::clipboard::CopyToClipboard;
use crossterm::execute;

/// How a copy went.
#[derive(Debug, PartialEq, Eq)]
pub enum Copied {
    /// The pasteboard has the text; the terminal was asked to copy it too.
    Pasteboard,
    /// Only the terminal was asked to copy the text, which it may ignore: the system has no
    /// pasteboard iotap reaches, or `pbcopy` failed for the reason given.
    Terminal(Option<String>),
}

/// Copies `text` every way the system has: the terminal's clipboard (OSC 52) reaches the
/// machine the user sits at even over SSH, where terminals allow it; on macOS `pbcopy` reaches
/// the pasteboard of this Mac in any terminal.
pub fn copy(text: &str) -> io::Result<Copied> {
    execute!(io::stdout(), CopyToClipboard::to_clipboard_from(text))?;
    #[cfg(target_os = "macos")]
    return Ok(match pasteboard::copy(text) {
        Ok(()) => Copied::Pasteboard,
        Err(err) => Copied::Terminal(Some(err.to_string())),
    });
    #[cfg(not(target_os = "macos"))]
    Ok(Copied::Terminal(None))
}

/// The pasteboard of the Mac iotap runs on, through `pbcopy`.
#[cfg(target_os = "macos")]
mod pasteboard {
    use std::io::{self, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::sys::{self, user};

    /// Longest wait for `pbcopy`.
    const PBCOPY_TIMEOUT: Duration = Duration::from_secs(1);

    /// Runs `pbcopy` as the user who started iotap, so the text reaches their pasteboard rather
    /// than root's.
    pub(super) fn copy(text: &str) -> io::Result<()> {
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
}
