use super::UserProcessId;

pub(super) fn in_range_for_platform(_raw: u32) -> bool {
    // All `u32` are (potentially) valid process ids on Windows.
    true
}

#[expect(
    unsafe_code,
    reason = "Windows process liveness uses raw Win32 process handles"
)]
impl UserProcessId {
    /// Return whether this process ID identifies a running process.
    ///
    /// This probe is non-destructive. It does not establish process ownership,
    /// and the operating system may reuse the PID after this method returns.
    ///
    /// # Errors
    ///
    /// Returns an OS error when process existence cannot be determined.
    pub fn process_exists(self) -> std::io::Result<bool> {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, STILL_ACTIVE,
        };
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self.get()) };
        if handle.is_null() {
            let error = unsafe { GetLastError() };
            return if error == ERROR_INVALID_PARAMETER {
                Ok(false)
            } else {
                Err(std::io::Error::from_raw_os_error(error.cast_signed()))
            };
        }
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
        let error = (ok == 0).then(std::io::Error::last_os_error);
        unsafe { CloseHandle(handle) };
        if let Some(error) = error {
            return Err(error);
        }
        Ok(code == STILL_ACTIVE as u32)
    }
}
