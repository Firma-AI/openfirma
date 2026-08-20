//! Unix platform implementation.

#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

use crate::error::OrchestratorError;
use crate::platform::{Group, Platform, SpawnedChild, TerminationTarget};
use crate::process_id::ChildExt as _;

pub struct UnixPlatform;

/// Convert a runtime process identity to the Unix type required by group APIs.
///
/// Rejecting values outside the platform range prevents signalling a truncated
/// or unintended [`Pid`].
fn raw_pid(pid: u32) -> Result<Pid, OrchestratorError> {
    let raw = i32::try_from(pid).map_err(|_| {
        OrchestratorError::Platform(format!("pid {pid} does not fit platform pid_t"))
    })?;
    Ok(Pid::from_raw(raw))
}

impl Platform for UnixPlatform {
    fn new_group() -> Result<Group, OrchestratorError> {
        Ok(Group { pgid: 0 })
    }

    fn arm_group_termination(_group: &Group) -> Result<(), OrchestratorError> {
        Ok(())
    }

    fn termination_target_exists(target: &TerminationTarget) -> Result<bool, OrchestratorError> {
        let group_pid = target.stored_id();
        match killpg(raw_pid(group_pid.get())?, None::<Signal>) {
            Ok(()) | Err(nix::errno::Errno::EPERM) => Ok(true),
            Err(nix::errno::Errno::ESRCH) => Ok(false),
            Err(error) => Err(OrchestratorError::Platform(format!(
                "killpg(0) presence probe failed: {error}"
            ))),
        }
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

        let _ = group.pgid;
        cmd.process_group(0);
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
        Ok(SpawnedChild {
            child,
            leader_pid,
            termination_target: TerminationTarget::for_leader(leader_pid),
        })
    }

    fn signal_soft(target: &TerminationTarget) -> Result<(), OrchestratorError> {
        killpg(raw_pid(target.stored_id().get())?, Signal::SIGTERM).map_err(|error| {
            OrchestratorError::Platform(format!("killpg(SIGTERM) failed: {error}"))
        })
    }

    fn signal_hard(target: &TerminationTarget) -> Result<(), OrchestratorError> {
        killpg(raw_pid(target.stored_id().get())?, Signal::SIGKILL).map_err(|error| {
            OrchestratorError::Platform(format!("killpg(SIGKILL) failed: {error}"))
        })
    }

    fn child_already_reaped(error: &std::io::Error) -> bool {
        error.raw_os_error() == Some(nix::libc::ECHILD)
    }

    fn spawn_detached(cmd: &mut Command) -> Result<Child, OrchestratorError> {
        // Detach from the controlling terminal so closing the parent shell
        // does not deliver SIGHUP to the supervisor. `setsid` must run in
        // the child between fork and exec.
        #[expect(
            unsafe_code,
            reason = "CommandExt::pre_exec is required here to call setsid in the fork/exec window"
        )]
        // SAFETY: `setsid` is async-signal-safe and is the only syscall in
        // the pre-exec closure. No allocator or locks are used.
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid()
                    .map(|_| ())
                    .map_err(std::io::Error::from)
            });
        }
        cmd.spawn().map_err(|source| OrchestratorError::Spawn {
            component: "supervisor".into(),
            source,
        })
    }
}
