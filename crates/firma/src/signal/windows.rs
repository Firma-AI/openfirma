//! Windows-only graceful shutdown listener.
//!
//! Each `firma` service running on Windows creates a named event at startup
//! whose name is derived from its own PID (see
//! `firma_stack::shutdown_event::windows_shutdown_event_name`). The
//! `firma stack stop` command opens that event by name and signals it,
//! which wakes the watcher thread below and cancels the service's shutdown
//! token — the same token `tokio::signal::ctrl_c()` would cancel.
//!
//! This is the Windows equivalent of receiving `SIGTERM` on Unix.
//! `GenerateConsoleCtrlEvent` cannot be used because it only crosses
//! processes that share a console — `stop` does not.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

/// Install a watcher thread that cancels `token` when the per-PID shutdown
/// event is signalled. Best-effort: if event creation or thread spawning
/// fails, `firma stack stop` falls back to its hard-kill path after the
/// grace window.
pub fn install_listener(token: CancellationToken) {
    let pid = std::process::id();
    let name = firma_stack::shutdown_event::windows_shutdown_event_name(pid);
    let wide: Vec<u16> = OsStr::new(&name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Manual-reset, initially non-signalled. Manual-reset means a single
    // SetEvent wakes every waiter — defensive in case multiple listeners
    // are installed within the same process.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
    if handle.is_null() {
        let err = unsafe { GetLastError() };
        tracing::warn!(
            error = err,
            event = %name,
            "CreateEventW failed; firma stack stop will fall back to hard kill",
        );
        return;
    }
    // HANDLE is `*mut c_void` and not `Send`, but the kernel object behind
    // it is process-wide — passing the raw address across threads is safe.
    let handle_addr = handle as usize;
    let thread = std::thread::Builder::new()
        .name("firma-shutdown-event".into())
        .spawn(move || {
            let handle = handle_addr as windows_sys::Win32::Foundation::HANDLE;
            let result = unsafe { WaitForSingleObject(handle, INFINITE) };
            unsafe { CloseHandle(handle) };
            if result == WAIT_OBJECT_0 {
                tracing::info!("received Windows shutdown event, shutting down");
                token.cancel();
            } else {
                let err = unsafe { GetLastError() };
                tracing::warn!(
                    result,
                    error = err,
                    "WaitForSingleObject on shutdown event returned unexpected status",
                );
            }
        });
    if let Err(e) = thread {
        unsafe { CloseHandle(handle) };
        tracing::warn!(%e, "failed to spawn shutdown-event watcher thread");
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panics are acceptable test failures"
)]
mod tests {
    use std::time::Duration;

    use windows_sys::Win32::System::Threading::EVENT_MODIFY_STATE;
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent};

    use super::*;

    /// Listener half of the contract: signalling the per-PID event must
    /// cancel the supplied `CancellationToken`. Mirrors the round-trip test
    /// in `firma-stack::platform_windows`, but exercises the wait-side.
    #[tokio::test]
    async fn install_listener_cancels_token_on_event_signal() {
        let token = CancellationToken::new();
        install_listener(token.clone());
        // Wait a beat to let the watcher thread reach WaitForSingleObject.
        // Not strictly required (CreateEventW + SetEvent compose correctly
        // even if SetEvent races the wait) but reduces test flakiness.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let name = firma_stack::shutdown_event::windows_shutdown_event_name(std::process::id());
        let wide: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
        assert!(!event.is_null(), "OpenEventW failed");
        let ok = unsafe { SetEvent(event) };
        unsafe { CloseHandle(event) };
        assert_ne!(ok, 0, "SetEvent failed");

        tokio::time::timeout(Duration::from_secs(5), token.cancelled())
            .await
            .expect("token was not cancelled within 5s");
    }
}
