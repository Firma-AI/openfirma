use std::io::{self, IsTerminal as _};
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};

use crate::runner::{RunnerError, RunnerResult};

/// Terminal dimensions accepted for PTY resize forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}

/// Restores host terminal mode when the PTY bridge exits.
#[derive(Debug)]
pub struct RawTerminalMode {
    fd: RawFd,
    original: libc::termios,
}

impl RawTerminalMode {
    /// Switches the host terminal into raw mode until the guard is dropped.
    pub fn enable() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command PTY mode requires host stdin and stdout to be terminals",
            ));
        }

        let fd = libc::STDIN_FILENO;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(std::ptr::addr_of_mut!(raw));
        }

        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(raw)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, original })
    }
}

impl Drop for RawTerminalMode {
    fn drop(&mut self) {
        let _ =
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, std::ptr::addr_of!(self.original)) };
    }
}

/// Duplicates a raw file descriptor into an owned descriptor.
pub fn duplicate_fd(fd: RawFd) -> RunnerResult<OwnedFd> {
    if fd < 0 {
        return Err(RunnerError::CommandPtyClosedConnectionFd);
    }

    unsafe { BorrowedFd::borrow_raw(fd) }
        .try_clone_to_owned()
        .map_err(|source| RunnerError::CommandPtyDuplicateFd { fd, source })
}

/// Reads the current host terminal size for PTY resize forwarding.
pub fn read_host_terminal_size() -> io::Result<TerminalSize> {
    let mut winsize = std::mem::MaybeUninit::<libc::winsize>::uninit();
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, winsize.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let winsize = unsafe { winsize.assume_init() };
    if winsize.ws_row == 0 || winsize.ws_col == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host terminal reported zero rows or columns",
        ));
    }

    Ok(TerminalSize {
        rows: winsize.ws_row,
        cols: winsize.ws_col,
    })
}

/// Parses terminal size as `ROWSxCOLS` or `ROWS,COLS`.
pub fn parse_terminal_size(value: &str) -> io::Result<TerminalSize> {
    let (rows, cols) = value
        .split_once('x')
        .or_else(|| value.split_once(','))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected terminal size as ROWSxCOLS, got {value:?}"),
            )
        })?;

    let rows = rows.parse::<u16>().map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("parse terminal rows from {value:?}: {source}"),
        )
    })?;

    let cols = cols.parse::<u16>().map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("parse terminal cols from {value:?}: {source}"),
        )
    })?;

    if rows == 0 || cols == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "terminal startup size must be non-zero",
        ));
    }

    Ok(TerminalSize { rows, cols })
}

/// Ensures command PTY mode only starts with a usable host terminal.
pub fn ensure_host_terminal_available() -> RunnerResult<()> {
    ensure_host_terminal_available_for_stdio(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )
}

/// Accepts host terminal availability before the runner enters PTY mode.
pub fn ensure_host_terminal_available_for_stdio(
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> RunnerResult<()> {
    if !stdin_is_terminal || !stdout_is_terminal {
        return Err(RunnerError::CommandPtyHostTerminalUnavailable);
    }

    Ok(())
}
