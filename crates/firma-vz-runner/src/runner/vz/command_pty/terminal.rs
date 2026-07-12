use std::io::{self, IsTerminal as _};
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};

use crate::runner::{RunnerError, RunnerResult};

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
