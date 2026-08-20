use super::UserProcessId;

pub(super) fn in_range_for_platform(raw: u32) -> bool {
    u32::try_from(nix::libc::pid_t::MAX).is_ok_and(|max| raw <= max)
}

impl UserProcessId {
    /// Return this process ID as a `nix` PID.
    #[must_use]
    fn as_nix_pid(self) -> nix::unistd::Pid {
        self.into()
    }

    /// Return whether this process ID identifies an existing process.
    ///
    /// This probe is non-destructive. An unreaped zombie therefore counts as
    /// existing. It does not establish process ownership, and the operating
    /// system may reuse the PID after this method returns.
    ///
    /// # Errors
    ///
    /// Returns an OS error when process existence cannot be determined.
    pub fn process_exists(self) -> std::io::Result<bool> {
        match nix::sys::signal::kill(self.as_nix_pid(), None) {
            Ok(()) | Err(nix::errno::Errno::EPERM) => Ok(true),
            Err(nix::errno::Errno::ESRCH) => Ok(false),
            Err(error) => Err(std::io::Error::from_raw_os_error(error as i32)),
        }
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
