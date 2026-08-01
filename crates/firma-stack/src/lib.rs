//! Process supervision and observability primitives for the firma stack.

pub mod config;
pub mod error;
pub mod shutdown_event;
pub mod start;
pub mod status;
pub mod stop;

mod component;
mod detach;
mod platform;
mod readiness;
mod spawn;
mod supervisor;

pub use config::{StackConfig, resolve_stack_config};
pub use error::StackError;
pub use start::{RunningStack, StackHandle, StartMode, spawn_stack, start, supervise_owned};
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

    /// Collect one owned child in the same background loop used by detached
    /// supervisor startup.
    #[must_use]
    pub fn collect_raw_child_in_background(
        child: std::process::Child,
    ) -> Option<std::thread::JoinHandle<()>> {
        crate::supervisor::collect_child_in_background(child)
    }

    /// Simulate component-reaper thread creation failure and recover both children.
    #[must_use]
    pub fn recover_raw_children_after_reaper_failure(
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> Vec<std::process::Child> {
        let components = vec![
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
        ];
        match crate::supervisor::collect_in_background_with(components, |_| {
            Err(std::io::Error::other("injected reaper start failure"))
        }) {
            Ok(_) => Vec::new(),
            Err(error) => error
                .into_components()
                .into_iter()
                .map(|component| component.into_parts().0)
                .collect(),
        }
    }

    /// Construct an owned running stack from arbitrary child processes.
    #[must_use]
    pub fn running_stack_from_raw(
        state_dir: &std::path::Path,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> crate::RunningStack {
        crate::RunningStack::from_components(
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
            state_dir.to_path_buf(),
        )
    }

    /// Bind a raw running stack's cleanup to one supervisor identity.
    pub fn set_running_stack_owner(stack: &mut crate::RunningStack, owner: u32) {
        if let Some(owner) = firma_runtime_state::UserProcessId::new(owner) {
            stack.set_state_owner(owner);
        }
    }

    /// Return the PID-scoped detached readiness path.
    #[must_use]
    pub fn supervisor_ready_path(state_dir: &std::path::Path, owner: u32) -> std::path::PathBuf {
        firma_runtime_state::UserProcessId::new(owner).map_or_else(
            || state_dir.join("invalid-supervisor.ready"),
            |owner| crate::start::supervisor_ready_path(state_dir, owner),
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

    /// Wait for a detached supervisor child to confirm attachment.
    ///
    /// # Errors
    ///
    /// Returns readiness, child-exit, or runtime-state errors.
    pub fn wait_for_supervisor_attachment(
        state_dir: &std::path::Path,
        supervisor: &mut std::process::Child,
        timeout: std::time::Duration,
    ) -> crate::error::Result<()> {
        crate::start::wait_for_supervisor_attachment(state_dir, supervisor, timeout)
    }

    /// Supervise arbitrary owned children through the production detached
    /// ownership loop.
    ///
    /// # Errors
    ///
    /// Returns supervision, termination, or cleanup errors.
    pub fn supervise_raw_owned(
        state_dir: &std::path::Path,
        timeout: std::time::Duration,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> crate::error::Result<()> {
        let stack = crate::RunningStack::from_components(
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
            state_dir.to_path_buf(),
        );
        crate::start::supervise_running_stack(stack, state_dir, timeout)
    }

    /// Spawn a raw child and run the production setup-failure cleanup path.
    ///
    /// # Errors
    ///
    /// Returns process spawn, group setup, or log errors.
    pub fn simulate_spawn_setup_failure(
        state_dir: &std::path::Path,
        name: &str,
        cmd: &mut std::process::Command,
    ) -> crate::error::Result<u32> {
        use crate::platform::{Platform, SystemPlatform};

        let group = SystemPlatform::new_group()?;
        let log_path = state_dir.join(format!("{name}.log"));
        let spawned = SystemPlatform::spawn_in_group(&group, cmd, &log_path)?;
        let pid = spawned.leader_pid.get();
        crate::spawn::cleanup_failed_spawn(spawned);
        Ok(pid)
    }

    fn owned_component(
        role: crate::component::ComponentRole,
        child: std::process::Child,
    ) -> crate::component::OwnedComponent {
        use firma_runtime_state::ChildExt as _;

        let leader_pid = child.process_id();
        crate::component::OwnedComponent::from_child(
            role,
            child,
            leader_pid,
            crate::platform::TerminationTarget::for_leader(leader_pid),
        )
    }
}
