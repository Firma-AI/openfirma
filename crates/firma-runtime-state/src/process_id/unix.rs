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

    /// Reap this process if it is an exited direct child.
    ///
    /// Returns `true` only when an exited or signaled child was reaped. Returns
    /// `false` when the process is still running, is not a direct child, or its
    /// status could not be queried.
    #[must_use]
    pub fn reap_if_exited(self) -> bool {
        matches!(
            nix::sys::wait::waitpid(
                self.as_nix_pid(),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            ),
            Ok(nix::sys::wait::WaitStatus::Exited(_, _)
                | nix::sys::wait::WaitStatus::Signaled(_, _, _))
        )
    }

    /// Return whether this process ID identifies an existing process.
    ///
    /// This probe is non-destructive. An unreaped zombie therefore counts as
    /// existing. It does not establish process ownership, and the operating
    /// system may reuse the PID after this method returns.
    #[must_use]
    pub fn process_exists(self) -> bool {
        matches!(
            nix::sys::signal::kill(self.as_nix_pid(), None),
            Ok(()) | Err(nix::errno::Errno::EPERM)
        )
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
