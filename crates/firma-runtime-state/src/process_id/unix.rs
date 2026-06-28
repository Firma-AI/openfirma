use super::{SignalProcessError, UserProcessId};

impl UserProcessId {
    /// Return whether this process ID appears to identify a live process.
    ///
    /// On Unix, this reaps exited child zombies before falling back to
    /// `kill(pid, 0)` for non-child processes. It is intended for local
    /// runtime-state observation, not for process ownership or signaling.
    #[must_use]
    pub fn is_alive(self) -> bool {
        let Ok(raw) = i32::try_from(self.get()) else {
            return false;
        };
        let pid = nix::unistd::Pid::from_raw(raw);
        // If the process is our child and has exited, reap the zombie here.
        // Otherwise `kill(pid, 0)` still reports a zombie as present.
        match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(
                nix::sys::wait::WaitStatus::Exited(_, _)
                | nix::sys::wait::WaitStatus::Signaled(_, _, _),
            ) => false,
            Ok(_) => true,
            Err(nix::errno::Errno::ECHILD) => matches!(
                nix::sys::signal::kill(pid, None),
                Ok(()) | Err(nix::errno::Errno::EPERM)
            ),
            Err(_) => false,
        }
    }

    /// Send `SIGTERM` to this process ID.
    ///
    /// This is a best-effort process signal by PID, not an ownership guarantee.
    /// The operating system may reuse process IDs after the original process
    /// exits.
    ///
    /// # Errors
    ///
    /// Returns an error if the process ID cannot be represented as the
    /// platform `pid_t`, or if the signal cannot be delivered.
    pub fn send_sigterm_signal(self) -> Result<(), SignalProcessError> {
        let raw = i32::try_from(self.get()).map_err(|_| SignalProcessError::PidOutOfRange(self))?;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(raw),
            nix::sys::signal::Signal::SIGTERM,
        )
        .map_err(|source| SignalProcessError::Signal { pid: self, source })
    }
}
