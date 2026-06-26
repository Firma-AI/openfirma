//! Minimal process liveness probe used by runtime-state readers.

use crate::process_id::NonZeroProcessId;

#[cfg(unix)]
pub fn is_alive(pid: NonZeroProcessId) -> bool {
    let Ok(raw) = i32::try_from(pid.get()) else {
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

#[cfg(windows)]
#[cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "Windows process liveness uses raw Win32 process handles"
    )
)]
pub fn is_alive(pid: NonZeroProcessId) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid.get()) };
    if handle.is_null() {
        return false;
    }
    let mut code: u32 = 0;
    let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
    unsafe { CloseHandle(handle) };
    ok != 0 && code == STILL_ACTIVE as u32
}

#[cfg(not(any(unix, windows)))]
pub fn is_alive(_pid: NonZeroProcessId) -> bool {
    false
}
