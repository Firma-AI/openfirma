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
mod state_lease;
mod supervisor;

pub use config::{StackConfig, resolve_stack_config};
pub use error::StackError;
#[doc(hidden)]
pub use start::supervise_owned_generation;
pub use start::{RunningStack, StackHandle, StartMode, spawn_stack, start};
pub use state_lease::StackGeneration;
pub use status::{ComponentStatus, StackStatus, State, status};
pub use stop::{StopOutcome, stop};

#[doc(hidden)]
pub mod test_support {
    pub use firma_runtime_state::pidfile;

    /// Sans-I/O access to teardown policy for integration coverage.
    pub mod teardown_policy {
        /// Tagged target-presence observation supplied to [`Harness`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Presence {
            /// The target is proven absent.
            Absent,
            /// The target remains present.
            Present,
            /// Presence is unknown and carries a stable test error tag.
            Unknown(u8),
        }

        /// Tagged forced-termination observation supplied to [`Harness`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum HardObservation {
            /// The target accepted the forced request.
            Accepted,
            /// Delivery failed and the target was subsequently proven absent.
            FailedThenAbsent(u8),
            /// Delivery failed without proof that the target disappeared.
            FailedStillPresent(u8),
        }

        /// Next graceful-phase action selected by [`Harness`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum GraceDecision {
            /// Teardown may clean runtime state.
            Complete,
            /// Teardown must continue polling.
            Poll,
            /// Teardown must enter forced termination.
            Escalate,
        }

        /// Next forced-settlement action selected by [`Harness`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum SettlementDecision {
            /// Teardown must continue polling.
            Poll,
            /// Teardown may clean runtime state and reports whether a forced
            /// request was accepted.
            Complete { forced: bool },
            /// Teardown failed with the retained test error tag.
            Fail(u8),
        }

        /// Deterministic driver for the production teardown policy.
        pub struct Harness(crate::stop::TeardownPolicy<u8>);

        impl Harness {
            /// Error tag emitted when settlement expires without an earlier error.
            pub const TIMEOUT_ERROR: u8 = u8::MAX;

            /// Begin teardown without any prior observations.
            #[must_use]
            pub const fn new() -> Self {
                Self(crate::stop::TeardownPolicy::new())
            }

            /// Record one direct-child collection result.
            pub fn observe_collection(&mut self, result: Result<(), u8>) {
                self.0.observe_collection(result);
            }

            /// Classify target presence under the production fail-closed policy.
            pub fn target_may_exist(&mut self, presence: Presence) -> bool {
                self.0.target_may_exist(match presence {
                    Presence::Absent => crate::stop::Presence::Absent,
                    Presence::Present => crate::stop::Presence::Present,
                    Presence::Unknown(error) => crate::stop::Presence::Unknown(error),
                })
            }

            /// Select the next graceful-phase action.
            #[must_use]
            pub fn decide_grace(&self, all_absent: bool, deadline_elapsed: bool) -> GraceDecision {
                match self.0.decide_grace(all_absent, deadline_elapsed) {
                    crate::stop::GraceDecision::Complete => GraceDecision::Complete,
                    crate::stop::GraceDecision::Poll => GraceDecision::Poll,
                    crate::stop::GraceDecision::Escalate => GraceDecision::Escalate,
                }
            }

            /// Record one forced-termination result.
            pub fn observe_hard(&mut self, observation: HardObservation) {
                self.0.observe_hard(match observation {
                    HardObservation::Accepted => crate::stop::HardObservation::Accepted,
                    HardObservation::FailedThenAbsent(error) => {
                        crate::stop::HardObservation::Failed {
                            error,
                            confirmed_absent_afterward: true,
                        }
                    }
                    HardObservation::FailedStillPresent(error) => {
                        crate::stop::HardObservation::Failed {
                            error,
                            confirmed_absent_afterward: false,
                        }
                    }
                });
            }

            /// Select the next forced-settlement action.
            pub fn decide_settlement(
                &mut self,
                all_absent: bool,
                deadline_elapsed: bool,
            ) -> SettlementDecision {
                match self
                    .0
                    .decide_settlement(all_absent, deadline_elapsed, || Self::TIMEOUT_ERROR)
                {
                    crate::stop::SettlementDecision::Poll => SettlementDecision::Poll,
                    crate::stop::SettlementDecision::Complete { forced } => {
                        SettlementDecision::Complete { forced }
                    }
                    crate::stop::SettlementDecision::Fail(error) => SettlementDecision::Fail(error),
                }
            }
        }

        impl Default for Harness {
            fn default() -> Self {
                Self::new()
            }
        }
    }

    /// Test-only capability holding startup's exclusive runtime-state transaction.
    pub struct RawStartupTransaction {
        transaction: crate::state_lease::StateTransaction,
        state_lease: crate::state_lease::StateLease,
        generation: crate::StackGeneration,
    }

    /// Test-only capability holding runtime-state serialization without mutation.
    pub struct RawStateTransaction {
        _transaction: crate::state_lease::StateTransaction,
    }

    impl RawStartupTransaction {
        /// Return the launcher identity assigned to this raw startup attempt.
        #[must_use]
        pub const fn generation(&self) -> crate::StackGeneration {
            self.generation
        }

        /// Run generation-fenced startup cleanup while retaining serialization.
        ///
        /// # Errors
        ///
        /// Returns runtime-state read or removal errors.
        pub fn cleanup(&self, state_dir: &std::path::Path) -> crate::error::Result<()> {
            crate::stop::cleanup_generation(state_dir, Some(self.state_lease), &self.transaction)
        }
    }

    /// Begin a raw startup generation and retain its state transaction.
    ///
    /// # Errors
    ///
    /// Returns coordination-lock, generation-publication, or stale-lock errors.
    pub fn begin_raw_startup(
        state_dir: &std::path::Path,
    ) -> crate::error::Result<RawStartupTransaction> {
        let transaction = crate::state_lease::StateTransaction::acquire(state_dir)?;
        if state_dir.join("stack.lock").exists() {
            std::fs::remove_file(state_dir.join("stack.lock"))?;
        }
        let generation = crate::StackGeneration::new();
        let state_lease = crate::state_lease::StateLease::try_claim(state_dir, generation)?
            .ok_or_else(|| {
                crate::StackError::Platform("raw startup generation could not be claimed".into())
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
    ) -> crate::error::Result<RawStateTransaction> {
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
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
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
    ) -> crate::error::Result<crate::RunningStack> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        Ok(crate::RunningStack::from_components(
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
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
    ) -> crate::error::Result<()> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        let mut authority = owned_component(crate::component::ComponentRole::Authority, authority);
        let mut sidecar = owned_component(crate::component::ComponentRole::Sidecar, sidecar);
        let stop = crate::supervisor::StopSignal::install()?;
        let supervision_result =
            crate::supervisor::block_until_owned_exit_with(&stop, &mut authority, &mut sidecar);
        let teardown_result = crate::stop::stop_owned(
            state_dir,
            timeout,
            &mut authority,
            &mut sidecar,
            state_lease,
        );
        if teardown_result.is_ok() {
            let _ = sidecar.wait();
            let _ = authority.wait();
        }
        supervision_result?;
        teardown_result.map(|_| ())
    }

    /// Construct an owned running stack whose component reaper cannot start.
    pub fn running_stack_from_raw_with_reaper_start_failure(
        state_dir: &std::path::Path,
        authority: std::process::Child,
        sidecar: std::process::Child,
    ) -> crate::error::Result<crate::RunningStack> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        Ok(crate::RunningStack::from_components_with_reaper_launcher(
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
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
    ) -> crate::error::Result<crate::RunningStack> {
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        Ok(crate::RunningStack::from_components_with_reaper_launcher(
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
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
    ) -> crate::error::Result<crate::RunningStack> {
        use crate::platform::{Platform, SystemPlatform};

        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        drop(transaction);
        let group = SystemPlatform::new_group()?;
        SystemPlatform::arm_group_termination(&group)?;
        let authority = spawn_test_component(
            &group,
            state_dir,
            crate::component::ComponentRole::Authority,
            authority_command,
        )?;
        let sidecar = spawn_test_component(
            &group,
            state_dir,
            crate::component::ComponentRole::Sidecar,
            sidecar_command,
        )?;
        Ok(crate::RunningStack::from_components_with_reaper_launcher(
            authority,
            sidecar,
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
    pub fn replace_stack_generation(state_dir: &std::path::Path) -> crate::error::Result<()> {
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
    pub fn force_replace_stack_generation(state_dir: &std::path::Path) -> crate::error::Result<()> {
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
        generation: crate::StackGeneration,
    ) -> crate::error::Result<crate::StopOutcome> {
        crate::stop::stop_generation(state_dir, timeout, generation)
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
        let (state_lease, transaction) = claim_test_generation(state_dir)?;
        let stack = crate::RunningStack::from_components(
            owned_component(crate::component::ComponentRole::Authority, authority),
            owned_component(crate::component::ComponentRole::Sidecar, sidecar),
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

    #[cfg(windows)]
    fn spawn_test_component(
        group: &crate::platform::Group,
        state_dir: &std::path::Path,
        role: crate::component::ComponentRole,
        command: &mut std::process::Command,
    ) -> crate::error::Result<crate::component::OwnedComponent> {
        use crate::platform::{Platform, SystemPlatform};

        let spawned = SystemPlatform::spawn_in_group(
            group,
            command,
            &state_dir.join(format!("{}.log", role.name())),
        )?;
        firma_runtime_state::pidfile::write(
            &state_dir.join(role.pidfile_name()),
            spawned.termination_target.stored_id(),
        )?;
        std::fs::write(state_dir.join(role.listen_file_name()), "127.0.0.1:0\n")?;
        Ok(crate::component::OwnedComponent::from_spawned(
            role, spawned,
        ))
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
    ) -> crate::error::Result<(
        crate::state_lease::StateLease,
        crate::state_lease::StateTransaction,
    )> {
        let transaction = crate::state_lease::StateTransaction::acquire(state_dir)?;
        if let Some(state_lease) =
            crate::state_lease::StateLease::try_claim(state_dir, crate::StackGeneration::new())?
        {
            return Ok((state_lease, transaction));
        }
        std::fs::remove_file(state_dir.join("stack.lock"))?;
        let state_lease =
            crate::state_lease::StateLease::try_claim(state_dir, crate::StackGeneration::new())?
                .ok_or_else(|| {
                    crate::StackError::Platform("test generation lock could not be claimed".into())
                })?;
        Ok((state_lease, transaction))
    }
}
