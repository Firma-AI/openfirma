//! Windows platform implementation.

#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "Windows platform integration uses raw Win32 handles"
)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    DETACHED_PROCESS, EVENT_MODIFY_STATE, GetCurrentProcess, OpenEventW, OpenProcess, OpenThread,
    PROCESS_SET_QUOTA, PROCESS_TERMINATE, ResumeThread, SetEvent, THREAD_SUSPEND_RESUME,
    TerminateProcess,
};

use crate::collect::{collect_child_in_background, collect_child_until};
use crate::error::OrchestratorError;
use crate::platform::{Group, Platform, SpawnedChild, TerminationTarget};
use crate::shutdown_event::windows_shutdown_event_name;
use crate::timeouts::CHILD_COLLECTION_TIMEOUT;
use firma_runtime_state::ChildExt as _;

/// Windows implementation of the process-authority [`Platform`] contract.
///
/// [`Group`] establishes Job Object membership before component code executes,
/// while each owned [`TerminationTarget`] retains a duplicate handle so process
/// authority survives setup. Closing the final handle triggers owner-loss
/// termination. A target reconstructed from runtime state is leader-only, as
/// described by [`TerminationTarget::from_stored_id`]. Graceful shutdown follows
/// [`windows_shutdown_event_name`] because stack children do not share the
/// caller's console.
pub struct WindowsPlatform;

/// Release one owned Job Object handle.
///
/// Ready components retain duplicate handles in their [`TerminationTarget`]
/// values, so releasing the setup [`Group`] does not end their stack. Releasing
/// the final handle enforces the owner-loss policy.
pub fn close_job_object(handle: HANDLE) {
    if !handle.is_null() {
        let _ = unsafe { CloseHandle(handle) };
    }
}

impl Platform for WindowsPlatform {
    fn new_group() -> Result<Group, OrchestratorError> {
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(OrchestratorError::Platform(
                "CreateJobObjectW failed".into(),
            ));
        }
        Ok(Group { job })
    }

    fn arm_group_termination(group: &Group) -> Result<(), OrchestratorError> {
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                group.job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).unwrap_or(u32::MAX),
            )
        };
        if configured == 0 {
            let error = unsafe { GetLastError() };
            return Err(OrchestratorError::Platform(format!(
                "SetInformationJobObject failed (error {error})"
            )));
        }
        Ok(())
    }

    fn termination_target_exists(target: &TerminationTarget) -> Result<bool, OrchestratorError> {
        if let Some(job) = target.job() {
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                unsafe { std::mem::zeroed() };
            let queried = unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformation,
                    std::ptr::from_mut(&mut accounting).cast(),
                    u32::try_from(std::mem::size_of_val(&accounting)).unwrap_or(u32::MAX),
                    std::ptr::null_mut(),
                )
            };
            if queried == 0 {
                let error = unsafe { GetLastError() };
                return Err(OrchestratorError::Platform(format!(
                    "QueryInformationJobObject failed (error {error})"
                )));
            }
            return Ok(accounting.ActiveProcesses != 0);
        }
        target
            .stored_id()
            .process_exists()
            .map_err(OrchestratorError::Io)
    }

    fn spawn_in_group(
        group: &Group,
        cmd: &mut Command,
        log_path: &Path,
    ) -> Result<SpawnedChild, OrchestratorError> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(log_path)?;
        let stderr_log = log.try_clone()?;

        // No component code may execute before Job assignment. This closes the
        // descendant-escape window between CreateProcess and assignment.
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_SUSPENDED);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr_log));
        let child = cmd.spawn().map_err(|source| OrchestratorError::Spawn {
            component: log_path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("child")
                .to_string(),
            source,
        })?;
        let leader_pid = child.process_id();
        // AssignProcessToJobObject requires PROCESS_SET_QUOTA and PROCESS_TERMINATE
        // on the process handle (per MSDN). Opening with only
        // PROCESS_QUERY_LIMITED_INFORMATION makes the assignment fail with
        // ERROR_ACCESS_DENIED.
        let process_handle =
            unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, leader_pid.get()) };
        if process_handle.is_null() {
            let err = unsafe { GetLastError() };
            cleanup_failed_child(child);
            return Err(OrchestratorError::Platform(format!(
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
            cleanup_failed_child(child);
            return Err(OrchestratorError::Platform(format!(
                "AssignProcessToJobObject failed (error {assign_err})"
            )));
        }
        let termination_target = match duplicate_job_target(group.job, leader_pid) {
            Ok(target) => target,
            Err(error) => {
                cleanup_failed_child(child);
                return Err(error);
            }
        };
        if let Err(error) = resume_suspended_process(leader_pid) {
            let _ = termination_target.signal_hard();
            cleanup_failed_child(child);
            return Err(error);
        }
        Ok(SpawnedChild {
            child,
            leader_pid,
            termination_target,
        })
    }

    fn signal_soft(target: &TerminationTarget) -> Result<(), OrchestratorError> {
        // `GenerateConsoleCtrlEvent` only delivers to processes that share the
        // caller's console. The stop process runs in a different console than the
        // children, and the children are spawned with `CREATE_NO_WINDOW` (no
        // console at all). So we use a per-PID named event that the child
        // creates at startup (see `firma::signal`); opening + signalling it is
        // the cross-console graceful-shutdown signal.
        let name = windows_shutdown_event_name(target.stored_id().get());
        let wide: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
        if handle.is_null() {
            let err = unsafe { GetLastError() };
            return Err(OrchestratorError::Platform(format!(
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
            return Err(OrchestratorError::Platform(format!(
                "SetEvent({name}) failed (error {set_err})"
            )));
        }
        Ok(())
    }

    fn signal_hard(target: &TerminationTarget) -> Result<(), OrchestratorError> {
        if let Some(job) = target.job() {
            if unsafe { TerminateJobObject(job, 1) } == 0 {
                let error = unsafe { GetLastError() };
                return Err(OrchestratorError::Platform(format!(
                    "TerminateJobObject failed (error {error})"
                )));
            }
            return Ok(());
        }
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, target.stored_id().get()) };
        if handle.is_null() {
            return Err(OrchestratorError::Platform(
                "OpenProcess(TERMINATE) failed".into(),
            ));
        }
        let ok = unsafe { TerminateProcess(handle, 1) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(OrchestratorError::Platform(
                "TerminateProcess failed".into(),
            ));
        }
        Ok(())
    }

    fn child_already_reaped(_error: &std::io::Error) -> bool {
        false
    }

    fn spawn_detached(cmd: &mut Command) -> Result<Child, OrchestratorError> {
        // The breakaway creation flag ensures the supervisor survives the
        // launcher's Job Object. If that Job does not grant breakaway, startup
        // fails closed: launching inside it would make detached lifetime depend
        // on an external owner-loss policy that Firma cannot inspect or control.
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
        cmd.spawn().map_err(|source| OrchestratorError::Spawn {
            component: "supervisor (breakaway required)".into(),
            source,
        })
    }
}

/// Duplicate Job Object authority into a component's [`TerminationTarget`].
///
/// Returning the capability only after duplication succeeds ensures the caller
/// can never receive a running component without durable descendant authority.
fn duplicate_job_target(
    job: HANDLE,
    leader_pid: firma_runtime_state::UserProcessId,
) -> Result<TerminationTarget, OrchestratorError> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    let duplicated = unsafe {
        DuplicateHandle(
            process,
            job,
            process,
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated == 0 {
        let error = unsafe { GetLastError() };
        return Err(OrchestratorError::Platform(format!(
            "DuplicateHandle(job) failed (error {error})"
        )));
    }
    Ok(TerminationTarget::for_job(leader_pid, duplicate))
}

/// Commit spawn by allowing a Job-assigned leader to execute component code.
///
/// Failure leaves the caller responsible for terminating the already-assigned
/// [`TerminationTarget`] before collecting the suspended child.
fn resume_suspended_process(
    leader_pid: firma_runtime_state::UserProcessId,
) -> Result<(), OrchestratorError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        return Err(OrchestratorError::Platform(format!(
            "CreateToolhelp32Snapshot(threads) failed (error {error})"
        )));
    }
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(std::mem::size_of::<THREADENTRY32>()).unwrap_or(u32::MAX);
    let mut found = false;
    let mut has_entry = unsafe { Thread32First(snapshot, &raw mut entry) } != 0;
    while has_entry {
        if entry.th32OwnerProcessID == leader_pid.get() {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                let error = unsafe { GetLastError() };
                unsafe { CloseHandle(snapshot) };
                return Err(OrchestratorError::Platform(format!(
                    "OpenThread(SUSPEND_RESUME) failed (error {error})"
                )));
            }
            let previous_suspend_count = unsafe { ResumeThread(thread) };
            unsafe { CloseHandle(thread) };
            if previous_suspend_count == u32::MAX {
                let error = unsafe { GetLastError() };
                unsafe { CloseHandle(snapshot) };
                return Err(OrchestratorError::Platform(format!(
                    "ResumeThread failed (error {error})"
                )));
            }
            found = true;
            break;
        }
        has_entry = unsafe { Thread32Next(snapshot, &raw mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    if !found {
        return Err(OrchestratorError::Platform(format!(
            "suspended process {} had no resumable primary thread",
            leader_pid.get()
        )));
    }
    Ok(())
}

/// Preserve direct-child collection responsibility after a Windows spawn failure.
fn cleanup_failed_child(mut child: Child) {
    let _ = child.kill();
    if !collect_child_until(&mut child, Instant::now() + CHILD_COLLECTION_TIMEOUT)
        && let Err(error) = collect_child_in_background(child)
    {
        let _ = error.terminate_and_collect();
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "Windows platform tests use expect to fail fast on setup failures"
    )]

    use std::time::Duration;

    use firma_runtime_state::UserProcessId;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    use super::*;

    const JOB_FIXTURE_STAGE: &str = "FIRMA_WINDOWS_JOB_FIXTURE_STAGE";
    const JOB_FIXTURE_MARKER: &str = "FIRMA_WINDOWS_JOB_FIXTURE_MARKER";
    const JOB_FIXTURE_TEST: &str =
        "platform::windows::tests::closing_owned_job_handles_terminates_descendant";

    #[test]
    fn closing_owned_job_handles_terminates_descendant() {
        match std::env::var(JOB_FIXTURE_STAGE).as_deref() {
            Ok("grandchild") => loop {
                std::thread::sleep(Duration::from_secs(60));
            },
            Ok("child") => {
                let marker = std::env::var_os(JOB_FIXTURE_MARKER).expect("fixture marker");
                let grandchild = Command::new(std::env::current_exe().expect("test executable"))
                    .args(["--exact", JOB_FIXTURE_TEST])
                    .env(JOB_FIXTURE_STAGE, "grandchild")
                    .spawn()
                    .expect("spawn grandchild fixture");
                std::fs::write(marker, grandchild.id().to_string()).expect("write grandchild PID");
                return;
            }
            _ => {}
        }

        let state_dir = tempfile::tempdir().expect("state dir");
        let marker = state_dir.path().join("grandchild.pid");
        let group = WindowsPlatform::new_group().expect("create job");
        WindowsPlatform::arm_group_termination(&group).expect("arm job termination");
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", JOB_FIXTURE_TEST])
            .env(JOB_FIXTURE_STAGE, "child")
            .env(JOB_FIXTURE_MARKER, &marker);
        let mut spawned = WindowsPlatform::spawn_in_group(
            &group,
            &mut command,
            &state_dir.path().join("job-fixture.log"),
        )
        .expect("spawn job leader");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                Instant::now() < deadline,
                "grandchild fixture did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(spawned.child.wait().expect("collect leader").success());
        let grandchild_pid: u32 = std::fs::read_to_string(&marker)
            .expect("read grandchild PID")
            .trim()
            .parse()
            .expect("parse grandchild PID");
        let grandchild_pid = UserProcessId::new(grandchild_pid).expect("grandchild PID");

        assert!(spawned.termination_target.exists().expect("query job"));
        drop(group);
        drop(spawned.termination_target);
        let deadline = Instant::now() + Duration::from_secs(5);
        while grandchild_pid.process_exists().expect("probe grandchild") {
            assert!(
                Instant::now() < deadline,
                "grandchild survived final Job handle closure"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

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

        TerminationTarget::for_leader(pid)
            .signal_soft()
            .expect("signal_soft");

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
        let err = TerminationTarget::for_leader(pid)
            .signal_soft()
            .expect_err("signal_soft must fail with no event");
        let msg = err.to_string();
        assert!(
            msg.contains("OpenEventW"),
            "unexpected error message: {msg}",
        );
    }
}
