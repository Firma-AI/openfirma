//! Saves and restores the terminal's input mode around a hidden prompt. On
//! Unix the prompt turns echo off and restores it only after reading a line,
//! so an interrupted read would otherwise leave the terminal without echo. On
//! Windows the prompt reads console input without changing the mode today;
//! restoring it guards against a prompt that does.

#[cfg(unix)]
pub use unix::{Saved, restore, save};
#[cfg(windows)]
pub use windows::{Saved, restore, save};

#[cfg(unix)]
mod unix {
    use std::io;

    use nix::sys::termios::{SetArg, Termios, tcgetattr, tcsetattr};

    /// The terminal attributes before the prompt.
    pub type Saved = Termios;

    /// Reads the current attributes of standard input.
    pub fn save() -> io::Result<Saved> {
        tcgetattr(io::stdin()).map_err(io::Error::from)
    }

    /// Puts back attributes read by [`save`].
    pub fn restore(saved: &Saved) -> io::Result<()> {
        tcsetattr(io::stdin(), SetArg::TCSANOW, saved).map_err(io::Error::from)
    }
}

#[cfg(windows)]
mod windows {
    #![expect(unsafe_code, reason = "reads and sets the console mode through Win32")]

    use std::io;
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::System::Console::{CONSOLE_MODE, GetConsoleMode, SetConsoleMode};

    /// The console input mode before the prompt.
    pub struct Saved(CONSOLE_MODE);

    /// Reads the current console mode of standard input.
    pub fn save() -> io::Result<Saved> {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: the handle is this process's standard input, and `mode` is a
        // valid, writable `CONSOLE_MODE`.
        if unsafe { GetConsoleMode(io::stdin().as_raw_handle(), &mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Saved(mode))
    }

    /// Puts back the mode read by [`save`].
    pub fn restore(saved: &Saved) -> io::Result<()> {
        // SAFETY: the handle is this process's standard input; the mode was
        // read from it by `save`.
        if unsafe { SetConsoleMode(io::stdin().as_raw_handle(), saved.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
const RESET_HINT: &str = "run `stty sane`";
#[cfg(windows)]
const RESET_HINT: &str = "open a new terminal";

/// Restores `saved`, if any, and tells the user when that fails.
pub fn restore_or_warn(saved: Option<&Saved>) {
    if let Some(saved) = saved
        && restore(saved).is_err()
    {
        eprintln!("\nterminal settings could not be restored; {RESET_HINT}");
    }
}
