use super::{SignalProcessError, UserProcessId};

#[expect(
    unsafe_code,
    reason = "Windows process liveness uses raw Win32 process handles"
)]
impl UserProcessId {
    /// Return whether this process ID appears to identify a live process.
    ///
    /// This is intended for local runtime-state observation, not for process
    /// ownership or signaling.
    #[must_use]
    pub fn is_alive(self) -> bool {
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
    pub fn send_sigterm_signal(self) -> Result<(), SignalProcessError> {
        let _ = self;
        Ok(())
    }
}
