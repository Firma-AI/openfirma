use super::{SignalProcessError, UserProcessId};

pub(super) fn in_range_for_platform(raw: u32) -> bool {
    u32::try_from(nix::libc::pid_t::MAX).is_ok_and(|max| raw <= max)
}

impl UserProcessId {
    /// Return this process ID as a `nix` PID.
    #[must_use]
    pub fn as_nix_pid(&self) -> nix::unistd::Pid {
        (*self).into()
    }

    /// Return whether this process ID appears to identify a live process.
    ///
    /// On Unix, this reaps exited child zombies before falling back to
    /// `kill(pid, 0)` for non-child processes. It is intended for local
    /// runtime-state observation, not for process ownership or signaling.
    #[must_use]
    pub fn is_alive(self) -> bool {
        let pid = self.as_nix_pid();
        // If the process is our direct child and has exited, reap the zombie
        // here. Otherwise we cannot `waitpid` it, and `kill(pid, 0)` still
        // reports a zombie as present.
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
    /// Returns an error if the signal cannot be delivered.
    pub fn send_sigterm_signal(self) -> Result<(), SignalProcessError> {
        nix::sys::signal::kill(self.into(), nix::sys::signal::Signal::SIGTERM)
            .map_err(|source| SignalProcessError::Signal { pid: self, source })
    }
}

impl From<UserProcessId> for nix::unistd::Pid {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "Type invariant: UserProcessId only stores values that fit Unix pid_t"
    )]
    fn from(value: UserProcessId) -> Self {
        Self::from_raw(value.get() as nix::libc::pid_t)
    }
}
