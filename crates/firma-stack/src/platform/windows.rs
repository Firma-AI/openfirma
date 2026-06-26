//! Windows platform implementation.

#![cfg(windows)]
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, EVENT_MODIFY_STATE, OpenEventW, OpenProcess,
    PROCESS_SET_QUOTA, PROCESS_TERMINATE, SetEvent, TerminateProcess,
};

use crate::error::{Result, StackError};
use crate::platform::{Group, Platform, SpawnedChild};
use crate::shutdown_event::windows_shutdown_event_name;
use firma_runtime_state::UserProcessId;

pub struct WindowsPlatform;

pub fn close_job_object(handle: HANDLE) {
    if !handle.is_null() {
        let _ = unsafe { CloseHandle(handle) };
    }
}

impl Platform for WindowsPlatform {
    fn new_group() -> Result<Group> {
        // Note: we intentionally do NOT set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
        // The Job Object is used only to group children for inspection / teardown.
        // If the parent process exits (e.g. `firma stack start --detach` returning
        // after spawning the supervisor), children must survive. Stop reaches
        // children via the per-pid named shutdown event (see `signal_soft`) and
        // falls back to TerminateProcess.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(StackError::Platform("CreateJobObjectW failed".into()));
        }
        Ok(Group { job })
    }

    fn spawn_in_group(group: &Group, cmd: &mut Command, log_path: &Path) -> Result<SpawnedChild> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(log_path)?;
        let stderr_log = log.try_clone()?;

        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        cmd.stdout(Stdio::from(log)).stderr(Stdio::from(stderr_log));
        let child = cmd.spawn().map_err(|source| StackError::Spawn {
            component: log_path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("child")
                .to_string(),
            source,
        })?;
        let pid = UserProcessId::new(child.id())
            .ok_or_else(|| StackError::Platform("spawned child returned reserved pid 0".into()))?;
        // AssignProcessToJobObject requires PROCESS_SET_QUOTA and PROCESS_TERMINATE
        // on the process handle (per MSDN). Opening with only
        // PROCESS_QUERY_LIMITED_INFORMATION makes the assignment fail with
        // ERROR_ACCESS_DENIED.
        let process_handle =
            unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid.get()) };
        if process_handle.is_null() {
            let err = unsafe { GetLastError() };
            return Err(StackError::Platform(format!(
                "OpenProcess failed (error {err})"
            )));
        }
        let assigned = unsafe { AssignProcessToJobObject(group.job, process_handle) };
        let assign_err = if assigned == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        unsafe { CloseHandle(process_handle) };
        if assigned == 0 {
            return Err(StackError::Platform(format!(
                "AssignProcessToJobObject failed (error {assign_err})"
            )));
        }
        std::mem::forget(child);
        Ok(SpawnedChild { pid })
    }

    fn signal_soft(group_pid: UserProcessId) -> Result<()> {
        // `GenerateConsoleCtrlEvent` only delivers to processes that share the
        // caller's console. The stop process runs in a different console than the
        // children, and the children are spawned with `CREATE_NO_WINDOW` (no
        // console at all). So we use a per-PID named event that the child
        // creates at startup (see `firma::signal`); opening + signalling it is
        // the cross-console graceful-shutdown signal.
        let name = windows_shutdown_event_name(group_pid.get());
        let wide: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
        if handle.is_null() {
            let err = unsafe { GetLastError() };
            return Err(StackError::Platform(format!(
                "OpenEventW({name}) failed (error {err})"
            )));
        }
        let ok = unsafe { SetEvent(handle) };
        let set_err = if ok == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(StackError::Platform(format!(
                "SetEvent({name}) failed (error {set_err})"
            )));
        }
        Ok(())
    }

    fn signal_hard(group_pid: UserProcessId) -> Result<()> {
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, group_pid.get()) };
        if handle.is_null() {
            return Err(StackError::Platform("OpenProcess(TERMINATE) failed".into()));
        }
        let ok = unsafe { TerminateProcess(handle, 1) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(StackError::Platform("TerminateProcess failed".into()));
        }
        Ok(())
    }

    fn is_alive(pid: UserProcessId) -> bool {
        firma_runtime_state::is_pid_alive(pid)
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    use super::*;

    /// Round-trip: a process that creates the per-PID shutdown event under
    /// the name dictated by `windows_shutdown_event_name` must be woken by
    /// `signal_soft` opening that name and calling `SetEvent`. This is the
    /// cross-process graceful-shutdown contract — using a single-process
    /// stand-in for `firma stack stop`.
    #[test]
    fn signal_soft_signals_named_event() {
        // Use a synthetic PID so the test never collides with a real
        // shutdown listener on the same machine.
        let pid = UserProcessId::new((std::process::id() ^ 0xDEAD_BEEF).wrapping_add(1))
            .expect("synthetic pid is non-zero");
        let name = windows_shutdown_event_name(pid.get());
        let wide: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Manual-reset, non-signalled — matches the listener side.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
        assert!(!event.is_null(), "CreateEventW failed");

        WindowsPlatform::signal_soft(pid).expect("signal_soft");

        let waited = unsafe { WaitForSingleObject(event, 5_000) };
        unsafe { CloseHandle(event) };
        assert_eq!(
            waited, WAIT_OBJECT_0,
            "event was not signalled (WaitForSingleObject returned {waited})",
        );
    }

    /// If no listener has created the event yet, `signal_soft` must return an
    /// error (so callers can log and proceed to hard-kill). This is the
    /// crashed-before-listener-installed case.
    #[test]
    fn signal_soft_errors_when_event_absent() {
        // PID with no matching event — `OpenEventW` must return null.
        let pid = UserProcessId::new(0xDEAD_BEEF).expect("synthetic pid is non-zero");
        let err =
            WindowsPlatform::signal_soft(pid).expect_err("signal_soft must fail with no event");
        let msg = err.to_string();
        assert!(
            msg.contains("OpenEventW"),
            "unexpected error message: {msg}",
        );
    }
}
