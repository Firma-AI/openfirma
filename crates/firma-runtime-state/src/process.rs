//! Minimal process liveness probe used by runtime-state readers.

#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "Windows process liveness uses raw Win32 process handles"
    )
)]

#[cfg(unix)]
pub fn is_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    let pid = nix::unistd::Pid::from_raw(raw);
    matches!(
        nix::sys::signal::kill(pid, None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

#[cfg(windows)]
pub fn is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut code: u32 = 0;
    let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
    unsafe { CloseHandle(handle) };
    ok != 0 && code == STILL_ACTIVE as u32
}

#[cfg(not(any(unix, windows)))]
pub fn is_alive(_pid: u32) -> bool {
    false
}
