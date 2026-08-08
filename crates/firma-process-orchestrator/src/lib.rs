//! Generic process-supervision machinery for a local multi-component stack.
//!
//! This crate owns the platform-agnostic supervision core: ordered startup with
//! rollback, generation-fenced runtime state, foreground and detached ownership,
//! fail-closed teardown, and observational status. It is agnostic to which
//! components a stack contains — callers describe the topology as a
//! [`ComponentSpec`] plan and supply the ordered component names.
//!
//! The firma-specific topology (the `[authority, sidecar]` plan and its config
//! parsing) lives in `firma-stack`, which wraps these entry points.

pub mod error;
pub mod shutdown_event;
pub mod start;
pub mod status;
pub mod stop;
mod topology;

mod collect;
mod component;
mod detach;
mod platform;
mod readiness;
mod spawn;
mod state_lease;
mod supervisor;

pub use component::{ComponentName, ComponentSpec};
pub use error::{OrchestratorError, StartError};
pub use start::{
    RunningStack, StackHandle, spawn_stack_from_plan, start_detached, start_foreground_from_plan,
    supervise_owned_generation_from_plan,
};
pub use state_lease::StackGeneration;
pub use status::{ComponentStatus, StackStatus, State, status_components};
pub use stop::{StopOutcome, stop_components};
pub use topology::StackTopology;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    use crate::component::{ComponentName, OwnedComponent};
    use crate::{OrchestratorError, RunningStack, StackGeneration, StackTopology, StopOutcome};

    /// Component names, in startup order, used by the test scaffolding.
    ///
    /// These strings are ordinary test data that drive the generic machinery;
    /// they mirror the firma stack topology only so the fixtures exercise a
    /// realistic two-component ordering.
    const TEST_COMPONENT_NAMES: &[&str] = &["authority", "sidecar"];

    fn test_topology() -> Result<StackTopology, OrchestratorError> {
        StackTopology::new(TEST_COMPONENT_NAMES.iter().copied())
    }

    /// Test-only capability holding startup's exclusive runtime-state transaction.
    pub struct RawStartupTransaction {
        transaction: crate::state_lease::StateTransaction,
        state_lease: crate::state_lease::StateLease,
        generation: StackGeneration,
    }

    /// Test-only capability holding runtime-state serialization without mutation.
    pub struct RawStateTransaction {
        _transaction: crate::state_lease::StateTransaction,
    }

    impl RawStartupTransaction {
        /// Return the launcher identity assigned to this raw startup attempt.
        #[must_use]
        pub const fn generation(&self) -> StackGeneration {
            self.generation
        }

        /// Run generation-fenced startup cleanup while retaining serialization.
        ///
        /// # Errors
        ///
        /// Returns runtime-state read or removal errors.
        pub fn cleanup(&self, state_dir: &std::path::Path) -> Result<(), OrchestratorError> {
            crate::stop::cleanup_generation(
                state_dir,
                &test_topology()?,
                Some(self.state_lease),
                &self.transaction,
            )
        }
    }

    /// Begin a raw startup generation and retain its state transaction.
    ///
    /// # Errors
    ///
    /// Returns coordination-lock, generation-publication, or stale-lock errors.
    pub fn begin_raw_startup(
        state_dir: &std::path::Path,
    ) -> Result<RawStartupTransaction, OrchestratorError> {
        let transaction = crate::state_lease::StateTransaction::acquire(state_dir)?;
        if state_dir.join("stack.lock").exists() {
            std::fs::remove_file(state_dir.join("stack.lock"))?;
        }
        let generation = StackGeneration::new();
        let state_lease = crate::state_lease::StateLease::try_claim(state_dir, generation)?
            .ok_or_else(|| {
                OrchestratorError::Platform("raw startup generation could not be claimed".into())
            })?;
        Ok(RawStartupTransaction {
            transaction,
            state_lease,
            generation,
        })
    }

    /// Hold runtime-state serialization until the returned capability is dropped.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the coordination lock cannot be acquired.
    pub fn hold_runtime_state_transaction(
        state_dir: &std::path::Path,
    ) -> Result<RawStateTransaction, OrchestratorError> {
        Ok(RawStateTransaction {
            _transaction: crate::state_lease::StateTransaction::acquire(state_dir)?,
        })
    }

    /// Spawn an arbitrary command into the same process grouping used by the stack.
    ///
    /// # Errors
    ///
    /// Returns process spawn, log, or pidfile errors.
    pub fn spawn_raw_into_group(
        state_dir: &std::path::Path,
        name: &str,
        cmd: &mut std::process::Command,
    ) -> Result<u32, OrchestratorError> {
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
    ) -> Result<std::process::Child, OrchestratorError> {
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
        crate::collect::collect_child_in_background(child)
    }

    /// Simulate component-reaper thread creation failure and recover both children.
    ///
    /// # Errors
    ///
    /// Returns an error if a test component name is invalid.
    pub fn recover_raw_children_after_reaper_failure(
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> Result<Vec<std::process::Child>, OrchestratorError> {
        let components = vec![
            owned_component(ComponentName::new("authority")?, authority),
            owned_component(ComponentName::new("sidecar")?, sidecar),
        ];
        Ok(
            match crate::supervisor::collect_in_background_with(components, |_| {
                Err(std::io::Error::other("injected reaper start failure"))
            }) {
                Ok(_) => Vec::new(),
                Err(error) => error
                    .into_components()
                    .into_iter()
                    .map(|component| component.into_parts().0)
                    .collect(),
            },
        )
    }

    /// Simulate reaper creation failure and run the production fallback.
    ///
    /// # Errors
    ///
    /// Returns the first child collection error after attempting to terminate
    /// and collect both children.
    pub fn terminate_raw_children_after_reaper_failure(
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> std::io::Result<()> {
        let components = vec![
            owned_component(
                ComponentName::new("authority").map_err(std::io::Error::other)?,
                authority,
            ),
            owned_component(
                ComponentName::new("sidecar").map_err(std::io::Error::other)?,
                sidecar,
            ),
        ];
        match crate::supervisor::collect_in_background_with(components, |_| {
            Err(std::io::Error::other("injected reaper start failure"))
        }) {
            Ok(_) => Err(std::io::Error::other(
                "injected reaper start failure unexpectedly succeeded",
            )),
            Err(error) => error.terminate_and_collect(),
        }
    }

    /// Construct an owned running stack from arbitrary child processes.
    pub fn running_stack_from_raw(
        state_dir: &std::path::Path,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> Result<RunningStack, OrchestratorError> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        Ok(RunningStack::from_components(
            vec![
                owned_component(ComponentName::new("authority")?, authority),
                owned_component(ComponentName::new("sidecar")?, sidecar),
            ],
            test_topology()?,
            state_dir.to_path_buf(),
            state_lease,
            None,
        ))
    }

    /// Supervise arbitrary owned children through the foreground lifecycle.
    ///
    /// # Errors
    ///
    /// Returns supervision, termination, or cleanup errors.
    pub fn supervise_raw_owned_until_exit(
        state_dir: &std::path::Path,
        timeout: std::time::Duration,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> Result<(), OrchestratorError> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        // Components in startup order: authority (server) then sidecar (client).
        let mut components = vec![
            owned_component(ComponentName::new("authority")?, authority),
            owned_component(ComponentName::new("sidecar")?, sidecar),
        ];
        let stop = crate::supervisor::StopSignal::install()?;
        let supervision_result =
            crate::supervisor::block_until_owned_exit_with(&stop, &mut components);
        let teardown_result = crate::stop::stop_owned(
            state_dir,
            timeout,
            &test_topology()?,
            &mut components,
            state_lease,
        );
        if teardown_result.is_ok() {
            // Collect in reverse of startup, consistent with owned teardown.
            for component in components.iter_mut().rev() {
                let _ = component.wait();
            }
        }
        supervision_result?;
        teardown_result.map(|_| ())
    }

    /// Construct an owned running stack whose component reaper cannot start.
    pub fn running_stack_from_raw_with_reaper_start_failure(
        state_dir: &std::path::Path,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> Result<RunningStack, OrchestratorError> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        Ok(RunningStack::from_components_with_reaper_launcher(
            vec![
                owned_component(ComponentName::new("authority")?, authority),
                owned_component(ComponentName::new("sidecar")?, sidecar),
            ],
            test_topology()?,
            state_dir.to_path_buf(),
            state_lease,
            None,
            fail_reaper_start,
        ))
    }

    /// Construct an owned running stack that must never launch a component reaper.
    pub fn running_stack_from_raw_with_forbidden_reaper(
        state_dir: &std::path::Path,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> Result<RunningStack, OrchestratorError> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        Ok(RunningStack::from_components_with_reaper_launcher(
            vec![
                owned_component(ComponentName::new("authority")?, authority),
                owned_component(ComponentName::new("sidecar")?, sidecar),
            ],
            test_topology()?,
            state_dir.to_path_buf(),
            state_lease,
            None,
            forbid_reaper_start,
        ))
    }

    /// Spawn an owned stack through the production Windows Job Object path.
    ///
    /// # Errors
    ///
    /// Returns state-lease, process-group creation, spawn, or publication errors.
    #[cfg(windows)]
    pub fn running_stack_from_commands_with_reaper_start_failure(
        state_dir: &std::path::Path,
        authority_command: &mut std::process::Command,
        sidecar_command: &mut std::process::Command,
    ) -> Result<RunningStack, OrchestratorError> {
        use crate::platform::{Platform, SystemPlatform};

        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        let group = SystemPlatform::new_group()?;
        SystemPlatform::arm_group_termination(&group)?;
        let authority = spawn_test_component(
            &group,
            state_dir,
            ComponentName::new("authority")?,
            authority_command,
        )?;
        let sidecar = spawn_test_component(
            &group,
            state_dir,
            ComponentName::new("sidecar")?,
            sidecar_command,
        )?;
        Ok(RunningStack::from_components_with_reaper_launcher(
            vec![authority, sidecar],
            test_topology()?,
            state_dir.to_path_buf(),
            state_lease,
            None,
            fail_reaper_start,
        ))
    }

    /// Replace persisted cleanup authority without changing an existing owner.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the new generation cannot be persisted.
    pub fn replace_stack_generation(state_dir: &std::path::Path) -> Result<(), OrchestratorError> {
        let _transaction = crate::state_lease::StateTransaction::acquire(state_dir)?;
        crate::state_lease::StateLease::replace_for_test(state_dir).map(|_| ())
    }

    /// Replace a generation without taking the transaction lock.
    ///
    /// This deliberately violates the production protocol to verify that the
    /// generation fence still protects replacement state from delayed cleanup.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the generation cannot be atomically replaced.
    pub fn force_replace_stack_generation(
        state_dir: &std::path::Path,
    ) -> Result<(), OrchestratorError> {
        crate::state_lease::StateLease::replace_for_test(state_dir).map(|_| ())
    }

    /// Run generation-scoped stop for a simulated detached rollback.
    ///
    /// # Errors
    ///
    /// Returns process, transaction, or runtime-state errors.
    pub fn stop_stack_generation(
        state_dir: &std::path::Path,
        timeout: std::time::Duration,
        generation: StackGeneration,
    ) -> Result<StopOutcome, OrchestratorError> {
        let topology = StackTopology::new(TEST_COMPONENT_NAMES.iter().copied())?;
        crate::stop::stop_generation(state_dir, timeout, &topology, generation)
    }

    /// Return the PID-scoped detached readiness path.
    #[must_use]
    pub fn supervisor_ready_path(state_dir: &std::path::Path, owner: u32) -> std::path::PathBuf {
        firma_runtime_state::UserProcessId::new(owner).map_or_else(
            || state_dir.join("invalid-supervisor.ready"),
            |owner| crate::start::supervisor_ready_path(state_dir, owner),
        )
    }

    /// Return the PID-scoped detached attachment-confirmation path.
    #[must_use]
    pub fn supervisor_attached_path(state_dir: &std::path::Path, owner: u32) -> std::path::PathBuf {
        firma_runtime_state::UserProcessId::new(owner).map_or_else(
            || state_dir.join("invalid-supervisor.attached"),
            |owner| crate::start::supervisor_attached_path(state_dir, owner),
        )
    }

    /// Forcefully terminate a raw process using the stack platform abstraction.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform cannot request termination.
    pub fn terminate_raw(pid: u32) -> Result<(), OrchestratorError> {
        let pid = firma_runtime_state::UserProcessId::try_from(pid)
            .map_err(|error| OrchestratorError::Platform(error.to_string()))?;
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
    ) -> Result<(), OrchestratorError> {
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
    ) -> Result<(), OrchestratorError> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        let stack = RunningStack::from_components(
            vec![
                owned_component(ComponentName::new("authority")?, authority),
                owned_component(ComponentName::new("sidecar")?, sidecar),
            ],
            test_topology()?,
            state_dir.to_path_buf(),
            state_lease,
            Some(transaction),
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
    ) -> Result<u32, OrchestratorError> {
        use crate::platform::{Platform, SystemPlatform};

        let group = SystemPlatform::new_group()?;
        let log_path = state_dir.join(format!("{name}.log"));
        let spawned = SystemPlatform::spawn_in_group(&group, cmd, &log_path)?;
        let pid = spawned.leader_pid.get();
        crate::spawn::cleanup_failed_spawn(spawned);
        Ok(pid)
    }

    fn owned_component(name: ComponentName, child: std::process::Child) -> OwnedComponent {
        use firma_runtime_state::ChildExt as _;

        let leader_pid = child.process_id();
        OwnedComponent::from_child(
            name,
            child,
            leader_pid,
            crate::platform::TerminationTarget::for_leader(leader_pid),
        )
    }

    #[cfg(windows)]
    fn spawn_test_component(
        group: &crate::platform::Group,
        state_dir: &std::path::Path,
        name: ComponentName,
        command: &mut std::process::Command,
    ) -> Result<OwnedComponent, OrchestratorError> {
        use crate::platform::{Platform, SystemPlatform};

        let spawned = SystemPlatform::spawn_in_group(
            group,
            command,
            &state_dir.join(format!("{}.log", name.as_str())),
        )?;
        firma_runtime_state::pidfile::write(
            &state_dir.join(name.pidfile_name()),
            spawned.termination_target.stored_id(),
        )?;
        std::fs::write(state_dir.join(name.listen_file_name()), "127.0.0.1:0\n")?;
        Ok(OwnedComponent::from_spawned(name, spawned))
    }

    fn fail_reaper_start(
        _: Box<dyn FnOnce() + Send>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        Err(std::io::Error::other("injected reaper start failure"))
    }

    #[expect(
        clippy::panic,
        reason = "this test-only launcher is a negative assertion"
    )]
    fn forbid_reaper_start(
        _: Box<dyn FnOnce() + Send>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        panic!("component reaper must not start after owned shutdown")
    }

    fn claim_test_generation(
        state_dir: &std::path::Path,
    ) -> Result<
        (
            crate::state_lease::StateLease,
            crate::state_lease::StateTransaction,
        ),
        OrchestratorError,
    > {
        let transaction = crate::state_lease::StateTransaction::acquire(state_dir)?;
        if let Some(state_lease) =
            crate::state_lease::StateLease::try_claim(state_dir, StackGeneration::new())?
        {
            return Ok((state_lease, transaction));
        }
        std::fs::remove_file(state_dir.join("stack.lock"))?;
        let state_lease =
            crate::state_lease::StateLease::try_claim(state_dir, StackGeneration::new())?
                .ok_or_else(|| {
                    OrchestratorError::Platform("test generation lock could not be claimed".into())
                })?;
        Ok((state_lease, transaction))
    }
}
