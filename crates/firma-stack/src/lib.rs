//! Process supervision and observability primitives for the firma stack.

pub mod config;
pub mod error;
pub mod shutdown_event;
pub mod start;
pub mod status;
pub mod stop;

mod detach;
mod platform;
mod readiness;
mod spawn;
mod supervisor;

pub use config::{StackConfig, resolve_stack_config};
pub use error::StackError;
pub use start::{RunningStack, StackHandle, StartMode, spawn_stack, start, supervise};
pub use status::{ComponentStatus, StackStatus, State, status};
pub use stop::{StopOutcome, stop};

#[doc(hidden)]
pub mod test_support {
    pub use firma_runtime_state::pidfile;

    /// Spawn an arbitrary command into the same process grouping used by the stack.
    ///
    /// # Errors
    ///
    /// Returns process spawn, log, or pidfile errors.
    pub fn spawn_raw_into_group(
        state_dir: &std::path::Path,
        name: &str,
        cmd: &mut std::process::Command,
    ) -> crate::error::Result<u32> {
        let mut child = spawn_raw_owned_into_group(state_dir, name, cmd)?;
        let pid = child.id();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(pid)
    }

    /// Spawn an arbitrary grouped command while retaining its child handle.
    ///
    /// # Errors
    ///
    /// Returns process spawn, log, or pidfile errors.
    pub fn spawn_raw_owned_into_group(
        state_dir: &std::path::Path,
        name: &str,
        cmd: &mut std::process::Command,
    ) -> crate::error::Result<std::process::Child> {
        use crate::platform::{Platform, SystemPlatform};
        let group = SystemPlatform::new_group()?;
        let log_path = state_dir.join(format!("{name}.log"));
        let pidfile_path = state_dir.join(format!("{name}.pid"));
        let child = SystemPlatform::spawn_in_group(&group, cmd, &log_path)?;
        firma_runtime_state::pidfile::write(&pidfile_path, child.termination_target.stored_id())?;
        std::fs::write(state_dir.join(format!("{name}.listen")), "127.0.0.1:0\n")?;
        Ok(child.child)
    }

    /// Collect two owned child processes in the same background loop used by
    /// detached stack startup.
    #[must_use]
    pub fn collect_raw_in_background(
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> std::thread::JoinHandle<()> {
        crate::supervisor::collect_in_background(authority, sidecar)
    }

    /// Construct an owned running stack from arbitrary child processes.
    #[must_use]
    pub fn running_stack_from_raw(
        state_dir: &std::path::Path,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> crate::RunningStack {
        crate::RunningStack::from_components(
            owned_component(authority),
            owned_component(sidecar),
            state_dir.to_path_buf(),
        )
    }

    /// Forcefully terminate a raw process using the stack platform abstraction.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform cannot request termination.
    pub fn terminate_raw(pid: u32) -> crate::error::Result<()> {
        let pid = firma_runtime_state::UserProcessId::try_from(pid)
            .map_err(|error| crate::StackError::Platform(error.to_string()))?;
        crate::platform::TerminationTarget::for_leader(pid).signal_hard()
    }

    /// Run detached observation with a caller-selected teardown timeout.
    ///
    /// # Errors
    ///
    /// Returns pidfile, observation, termination, or cleanup errors.
    pub fn supervise_with_timeout(
        state_dir: &std::path::Path,
        timeout: std::time::Duration,
    ) -> crate::error::Result<()> {
        crate::start::supervise_with_timeout(state_dir, timeout)
    }

    /// Spawn through the production component setup path.
    ///
    /// # Errors
    ///
    /// Returns process spawn, group setup, log, or pidfile errors.
    pub fn spawn_raw_component(
        state_dir: &std::path::Path,
        name: &str,
        exe: &std::path::Path,
        args: &[&str],
    ) -> crate::error::Result<std::process::Child> {
        use crate::platform::{Platform, SystemPlatform};

        let group = SystemPlatform::new_group()?;
        crate::spawn::spawn_component(
            &group,
            &crate::spawn::SpawnRequest {
                name,
                args,
                state_dir,
                exe: Some(exe),
            },
        )
        .map(|component| component.child)
    }

    fn owned_component(child: std::process::Child) -> crate::spawn::SpawnedComponent {
        use firma_runtime_state::ChildExt as _;

        let leader_pid = child.process_id();
        crate::spawn::SpawnedComponent {
            child,
            leader_pid,
            termination_target: crate::platform::TerminationTarget::for_leader(leader_pid),
        }
    }
}
