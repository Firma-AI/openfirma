use super::{SignalProcessError, UserProcessId};

pub(super) fn in_range_for_platform(_raw: u32) -> bool {
    // All `u32` are (potentially) valid process ids on Windows.
    true
}

#[expect(
    unsafe_code,
    reason = "Windows process liveness uses raw Win32 process handles"
)]
impl UserProcessId {
    /// Reap this process if it is an exited direct child.
    ///
    /// Windows process handles do not require Unix-style child reaping, so this
    /// method has no effect and always returns `false`.
    #[must_use]
    pub fn reap_if_exited(self) -> bool {
        let _ = self;
        false
    }

    /// Return whether this process ID identifies a running process.
    ///
    /// This probe is non-destructive. It does not establish process ownership,
    /// and the operating system may reuse the PID after this method returns.
    #[must_use]
    pub fn process_exists(self) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self.get()) };
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && code == STILL_ACTIVE as u32
    }

    /// Send a graceful termination signal to this process ID.
    ///
    /// This currently does nothing on non-Unix platforms; Windows process
    /// shutdown uses higher-level named events in `firma-stack`.
    ///
    /// # Errors
    ///
    /// This method currently always succeeds on Windows.
    #[must_use]
    pub fn send_sigterm_signal(self) -> Result<(), SignalProcessError> {
        let _ = self;
        Ok(())
    }
}
