//! Ordered startup, ownership transfer, and supervision.
//!
//! See the [crate-level lifecycle model](crate) for how this phase relates to
//! external stop, status, and runtime-state authority.
//!
//! # Startup transaction
//!
//! [`StartupGuard`] owns every [`OwnedComponent`] before startup performs another
//! fallible operation. After ordered readiness it transfers the complete set to
//! [`RunningStack`]. Normal errors invoke explicit rollback so a cleanup failure
//! can be returned alongside the initiating error. Guard destruction is only an
//! emergency hard-termination and collection-handoff path; it deliberately
//! leaves uncertain runtime state for later teardown.
//!
//! # Foreground and detached supervision
//!
//! [`start_foreground_from_plan`] keeps the [`RunningStack`] in the calling
//! process through supervision and shutdown. [`start_detached`] instead owns a
//! direct supervisor child through a two-phase readiness and attachment
//! handshake. The supervisor calls [`supervise_owned_generation_from_plan`] and
//! creates the components itself, so component capabilities never cross a
//! process boundary. The launcher transfers only supervisor-child collection
//! after attachment is confirmed; failures roll back only the generation it
//! assigned.
//!
//! A process-global collector is initialized before any managed child is
//! spawned. Explicit detachment and destructor backstops transfer direct-child
//! collection to it without creating threads or waiting for process exit during
//! [`Drop`].

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::LifecycleTimeouts;
use crate::StackTopology;
use crate::collect::{collect_child_in_background, collect_child_until, initialize_collector};
use crate::component::{
    ComponentEndpoint, ComponentName, ComponentPlanContext, ComponentSpec, OwnedComponent,
    Readiness, ReadyComponent, read_endpoint,
};
use crate::detach::spawn_supervisor;
use crate::error::{OrchestratorError, ShutdownError, StartError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::{wait_for_child_published, wait_for_endpoint};
use crate::spawn::{SpawnRequest, spawn_component};
use crate::state_lease::{StackGeneration, StateLease, StateTransaction};
use crate::stop::StopOutcome;
use crate::supervisor::{StopSignal, block_until_owned_exit_with, collect_in_background};
use crate::timeouts::CHILD_COLLECTION_TIMEOUT;
use firma_runtime_state::{UserProcessId, pidfile};

const STARTUP_ROLLBACK_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DETACHED_HANDOFF_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Informational handle returned once the stack is ready.
///
/// The handle does not own the children's lifecycle. [`RunningStack`] holds
/// in-process ownership; persisted runtime state supports external observation
/// through [`crate::status::status_components()`] and retryable teardown through [`crate::stop::stop_components()`].
/// See the [crate-level lifecycle model](crate) for its place in foreground and
/// detached operation.
#[derive(Clone)]
pub struct StackHandle {
    components: Vec<ComponentHandle>,
}

/// Observational identity, process ID, and ready endpoint for one component.
///
/// This value grants no authority to signal or collect the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentHandle {
    name: String,
    leader_pid: UserProcessId,
    endpoint: ComponentEndpoint,
}

impl ComponentHandle {
    /// Return the component's topology identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the leader process ID observed at startup.
    #[must_use]
    pub const fn leader_pid(&self) -> UserProcessId {
        self.leader_pid
    }

    /// Return the endpoint that passed readiness and canonical publication.
    #[must_use]
    pub const fn endpoint(&self) -> &ComponentEndpoint {
        &self.endpoint
    }
}

impl StackHandle {
    /// Iterate over ready components in topology and startup order.
    #[must_use]
    pub fn components(&self) -> impl ExactSizeIterator<Item = &ComponentHandle> {
        self.components.iter()
    }

    /// Look up a ready component by its topology identity.
    #[must_use]
    pub fn component(&self, name: &str) -> Option<&ComponentHandle> {
        self.components
            .iter()
            .find(|component| component.name == name)
    }
}

/// An in-process stack whose component child handles are owned by the caller.
///
/// Call [`RunningStack::shutdown`] for an orderly teardown. Successful shutdown
/// consumes the [`OwnedStack`], so repeated calls are no-ops. Call
/// [`RunningStack::detach`] to leave processes running under a background child
/// collector. Dropping an owned stack fails closed by hard-terminating its
/// process scopes and retaining runtime state for a later cleanup attempt.
/// See the [crate-level lifecycle model](crate) for the capabilities transferred
/// by each transition.
pub struct RunningStack {
    handle: StackHandle,
    state: RunningStackState,
}

/// Process and runtime-state capabilities held by a [`RunningStack`].
///
/// Each [`OwnedComponent`] couples direct-child collection with its
/// [`TerminationTarget`]. [`StateLease`] fences cleanup to this generation, and
/// the optional [`StateTransaction`] prevents partial state observation until
/// [`RunningStack::mark_ready`] publishes complete startup.
struct OwnedStack {
    components: Vec<OwnedComponent>,
    topology: StackTopology,
    state_dir: PathBuf,
    state_lease: StateLease,
    startup_transaction: Option<StateTransaction>,
}

/// Ownership states for an in-process stack.
///
/// Only [`RunningStackState::Owned`] authorizes process collection, termination,
/// and generation-fenced cleanup. Successful shutdown or ownership transfer
/// moves permanently to [`RunningStackState::Stopped`], making repeated
/// transitions harmless rather than duplicating authority.
enum RunningStackState {
    /// This process may supervise, terminate, collect, and clean up the stack.
    Owned(Box<OwnedStack>),
    /// Process authority has been consumed by shutdown or transferred away.
    Stopped,
}

/// Rollback guard for the ordered component-startup state machine.
///
/// Every spawned [`OwnedComponent`] is recorded before startup performs another
/// fallible operation. Normal error paths call [`StartupGuard::rollback`] unless
/// [`StartupGuard::finish`] commits the [`StartupState::Building`] components to
/// a [`RunningStack`]. [`Drop`] is only a fail-closed emergency backstop: it
/// hard-terminates and transfers collection without performing fallible
/// generation cleanup. The guard retains the [`StateTransaction`] and
/// [`StateLease`] needed to remove only its generation; target or collection
/// uncertainty preserves state for [`crate::stop::stop_components()`].
struct StartupGuard {
    state: StartupState,
    state_dir: PathBuf,
    state_lease: StateLease,
    transaction: Option<StateTransaction>,
    topology: StackTopology,
    startup_report_dir: PathBuf,
}

/// Valid process-ownership phases while the components are starting.
///
/// The enum makes invalid startup phases, such as retaining children after
/// ownership transfer, unrepresentable. Components are recorded in spawn order
/// so rollback, readiness polling, and finish observe them identically.
/// [`ComponentName`] assignment remains in the crate-internal spawn path, so
/// transitions cannot relabel capabilities.
enum StartupState {
    /// The generation is claimed; the ordered components spawned so far remain
    /// exclusively owned by the guard.
    Building(Vec<OwnedComponent>),
    /// Ownership was transferred to [`RunningStack`]; rollback is disarmed.
    Finished,
}

/// Launcher states in the generation-bound detached-supervisor handoff.
///
/// [`start_detached`] assigns a [`StackGeneration`] to its direct supervisor
/// child. The supervisor claims that generation, creates and owns the components,
/// then publishes [`supervisor_ready_path`] while retaining its startup
/// [`StateTransaction`]. The launcher validates the direct-child identity and
/// removes that file as acknowledgement. The supervisor then publishes
/// [`supervisor_attached_path`] and calls [`RunningStack::mark_ready`]; only
/// after validating that confirmation does the launcher relinquish collection.
/// Any launcher rollback uses the assigned generation, so it cannot stop a
/// replacement stack.
enum LauncherAttachmentState {
    /// Waiting for the supervisor to publish component readiness.
    AwaitingReadiness,
    /// Readiness was acknowledged; waiting for supervisor confirmation.
    AwaitingConfirmation,
}

/// Armed launcher ownership of a detached supervisor and its generation.
///
/// Explicit rollback handles fallible generation cleanup. Dropping an armed
/// guard is an emergency path that terminates and transfers collection of the
/// direct supervisor child while retaining durable state for later cleanup.
struct DetachedLaunchGuard<'a> {
    supervisor: Option<std::process::Child>,
    generation: StackGeneration,
    state_dir: &'a Path,
    topology: &'a StackTopology,
    teardown_timeout: Duration,
}

impl<'a> DetachedLaunchGuard<'a> {
    fn new(
        supervisor: std::process::Child,
        generation: StackGeneration,
        state_dir: &'a Path,
        topology: &'a StackTopology,
        teardown_timeout: Duration,
    ) -> Self {
        Self {
            supervisor: Some(supervisor),
            generation,
            state_dir,
            topology,
            teardown_timeout,
        }
    }

    fn supervisor_mut(&mut self) -> Result<&mut std::process::Child, OrchestratorError> {
        self.supervisor.as_mut().ok_or_else(|| {
            OrchestratorError::Platform("detached supervisor ownership unavailable".into())
        })
    }

    /// Transfer collection ownership and disarm launcher rollback.
    fn transfer_to_collector(&mut self) -> Result<(), OrchestratorError> {
        let supervisor = self.supervisor.take().ok_or_else(|| {
            OrchestratorError::Platform("detached supervisor ownership unavailable".into())
        })?;
        match collect_child_in_background(supervisor) {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = format!(
                    "could not start detached supervisor collector: {}",
                    error.reason()
                );
                self.supervisor = error.into_child();
                Err(OrchestratorError::Platform(message))
            }
        }
    }

    /// Terminate the supervisor and roll back only this launcher's generation.
    fn rollback(&mut self) -> Result<(), OrchestratorError> {
        let supervisor_result = self
            .supervisor
            .take()
            .map_or(Ok(()), terminate_detached_supervisor);
        let generation_result = rollback_detached_start(
            self.state_dir,
            self.topology,
            self.generation,
            self.teardown_timeout,
        );
        match supervisor_result {
            Ok(()) => generation_result,
            Err(error) => Err(with_rollback(error, generation_result)),
        }
    }
}

impl Drop for DetachedLaunchGuard<'_> {
    fn drop(&mut self) {
        let Some(mut supervisor) = self.supervisor.take() else {
            return;
        };
        let target =
            TerminationTarget::for_leader(firma_runtime_state::ChildExt::process_id(&supervisor));
        let _ = target.signal_hard();
        let _ = supervisor.kill();
        if let Err(error) = collect_child_in_background(supervisor) {
            debug!(error = %error.reason(), "detached launch drop could not hand off collection");
            error.forget();
        }
    }
}

/// Per-component transaction for transient and canonical endpoint publication.
///
/// Process ownership remains with [`StartupGuard`]. This guard ensures a
/// canonical endpoint survives the loop iteration only after matching
/// [`ReadyComponent`] evidence is committed.
struct ComponentPublicationGuard {
    startup_report_path: PathBuf,
    canonical_listen_path: PathBuf,
    startup_report_pending: bool,
    canonical_published: bool,
}

impl ComponentPublicationGuard {
    fn new(startup_report_path: PathBuf, canonical_listen_path: PathBuf) -> Self {
        Self {
            startup_report_path,
            canonical_listen_path,
            startup_report_pending: true,
            canonical_published: false,
        }
    }

    fn remove_startup_report(&mut self) -> Result<(), OrchestratorError> {
        std::fs::remove_file(&self.startup_report_path)?;
        self.startup_report_pending = false;
        Ok(())
    }

    fn publish_canonical(&mut self, endpoint: &ComponentEndpoint) -> Result<(), OrchestratorError> {
        publish_canonical_listen_endpoint(&self.canonical_listen_path, endpoint)?;
        self.canonical_published = true;
        Ok(())
    }

    fn commit(mut self, name: &ComponentName, endpoint: ComponentEndpoint) -> ReadyComponent {
        self.startup_report_pending = false;
        self.canonical_published = false;
        ReadyComponent::new(name.as_str(), endpoint)
    }
}

impl Drop for ComponentPublicationGuard {
    fn drop(&mut self) {
        if self.startup_report_pending {
            let _ = pidfile::remove(&self.startup_report_path);
        }
        if self.canonical_published {
            let _ = pidfile::remove(&self.canonical_listen_path);
        }
    }
}

impl StartupGuard {
    /// Begin an armed, empty [`StartupState::Building`] after generation claim.
    fn new(
        state_dir: &Path,
        state_lease: StateLease,
        transaction: StateTransaction,
        topology: StackTopology,
    ) -> Self {
        Self {
            state: StartupState::Building(Vec::new()),
            state_dir: state_dir.to_path_buf(),
            state_lease,
            transaction: Some(transaction),
            topology,
            startup_report_dir: startup_report_dir(state_dir, state_lease.generation()),
        }
    }

    fn prepare_startup_report_dir(&self) -> Result<(), OrchestratorError> {
        create_private_startup_report_dir(&self.startup_report_dir)
    }

    fn cleanup_startup_reports(&self) -> Result<(), OrchestratorError> {
        if !self.state_lease.is_current(&self.state_dir)? {
            return Err(OrchestratorError::Platform(
                "startup generation changed before report cleanup".into(),
            ));
        }
        remove_startup_report_dir(&self.startup_report_dir)
    }

    /// Spawn, record, and publish one component without an unowned failure gap.
    ///
    /// The guard takes ownership of the child and its termination target before
    /// writing the pidfile. A publication failure therefore follows the same
    /// generation-fenced rollback path as every later startup failure.
    fn spawn_component(
        &mut self,
        group: &crate::platform::Group,
        name: &ComponentName,
        command: &mut Command,
    ) -> Result<UserProcessId, OrchestratorError> {
        let StartupState::Building(components) = &mut self.state else {
            return Err(OrchestratorError::Platform(
                "component child spawned after startup finished".into(),
            ));
        };
        let spawned = spawn_component(
            group,
            &mut SpawnRequest {
                name: name.clone(),
                command,
                state_dir: &self.state_dir,
            },
        )?;
        let leader_pid = spawned.leader_pid;
        let stored_id = spawned.termination_target.stored_id();
        components.push(OwnedComponent::from_spawned(name.clone(), spawned));

        let pidfile_path = self.state_dir.join(name.pidfile_name());
        pidfile::write(&pidfile_path, stored_id)?;
        debug!(
            name = name.as_str(),
            pid = %leader_pid,
            pidfile = %pidfile_path.display(),
            "pidfile written"
        );
        Ok(leader_pid)
    }

    /// Collect and report the first exited component currently owned by startup.
    ///
    /// Components are polled in spawn order so readiness observes the same
    /// ordering as startup. Polling occurs through the guard so readiness never
    /// borrows a process ID without the corresponding [`OwnedComponent`]
    /// collection capability.
    fn exited_component(&mut self) -> Result<Option<(String, ExitStatus)>, OrchestratorError> {
        match &mut self.state {
            StartupState::Building(components) => {
                for component in components {
                    if let Some(exit) = Self::poll_exit(component)? {
                        return Ok(Some(exit));
                    }
                }
                Ok(None)
            }
            StartupState::Finished => Err(OrchestratorError::Platform(
                "component readiness checked without owned startup processes".into(),
            )),
        }
    }

    /// Poll one owned leader while preserving its broader termination capability.
    fn poll_exit(
        component: &mut OwnedComponent,
    ) -> Result<Option<(String, ExitStatus)>, OrchestratorError> {
        Ok(component
            .try_wait()
            .map_err(OrchestratorError::Io)?
            .map(|status| (component.name().as_str().to_string(), status)))
    }

    /// Transfer complete ownership and state capabilities into a [`RunningStack`].
    ///
    /// # Errors
    ///
    /// Returns an error and leaves rollback armed if startup has already
    /// finished.
    fn finish(
        mut self,
        ready_components: Vec<ReadyComponent>,
    ) -> Result<RunningStack, OrchestratorError> {
        match std::mem::replace(&mut self.state, StartupState::Finished) {
            StartupState::Building(components) => Ok(RunningStack::from_components(
                components,
                ready_components,
                self.topology.clone(),
                self.state_dir.clone(),
                self.state_lease,
                self.transaction.take(),
            )),
            StartupState::Finished => Err(OrchestratorError::Platform(
                "startup ownership already transferred".into(),
            )),
        }
    }

    /// Roll back an incomplete startup and report any cleanup failure.
    fn rollback(mut self) -> Result<(), OrchestratorError> {
        self.rollback_inner()
    }

    /// Consume the currently owned startup capabilities exactly once.
    fn rollback_inner(&mut self) -> Result<(), OrchestratorError> {
        let state = std::mem::replace(&mut self.state, StartupState::Finished);
        let StartupState::Building(components) = state else {
            return Ok(());
        };
        let report_result = self.cleanup_startup_reports();
        let process_result = if components.is_empty() {
            remove_startup_state(
                &self.state_dir,
                &self.topology,
                self.state_lease,
                self.transaction.as_ref(),
            )
        } else {
            rollback_startup_components(
                components,
                &self.state_dir,
                &self.topology,
                self.state_lease,
                self.transaction.as_ref(),
            )
        };
        match report_result {
            Ok(()) => process_result,
            Err(error) => Err(with_rollback(error, process_result)),
        }
    }

    /// Fail closed without performing fallible generation cleanup from `Drop`.
    fn emergency_rollback(&mut self) {
        let state = std::mem::replace(&mut self.state, StartupState::Finished);
        let StartupState::Building(mut components) = state else {
            return;
        };
        if let Err(error) = self.cleanup_startup_reports() {
            debug!(%error, "startup drop retained report state");
        }
        if components.is_empty() {
            return;
        }
        for component in &mut components {
            let _ = component.termination_target().signal_hard();
            let _ = component.kill_leader();
        }
        if let Err(error) = collect_in_background(components) {
            debug!(error = %error.reason(), "startup drop could not hand off collection");
            error.forget();
        }
    }
}

impl Drop for StartupGuard {
    /// Fail closed for an incomplete startup outside the explicit error path.
    ///
    /// Normal failures use [`StartupGuard::rollback`] so absence proof and
    /// generation cleanup can report errors. Destruction only hard-terminates
    /// and transfers collection, retaining durable state for a later stop.
    fn drop(&mut self) {
        self.emergency_rollback();
    }
}

/// Terminate and collect an incomplete startup without losing retry evidence.
///
/// All component [`TerminationTarget`] values receive a forced request before
/// bounded collection begins. If target absence or child collection cannot be
/// established, ownership moves to [`collect_in_background`]. An invariant
/// failure in that pre-initialized handoff falls back to explicit synchronous
/// termination and collection.
/// [`remove_startup_state`] applies the guard's generation fence only after
/// teardown is proven complete.
fn rollback_startup_components(
    mut components: Vec<OwnedComponent>,
    state_dir: &Path,
    topology: &StackTopology,
    state_lease: StateLease,
    transaction: Option<&StateTransaction>,
) -> Result<(), OrchestratorError> {
    debug!(state_dir = %state_dir.display(), "startup failed; collecting owned children");
    for component in &mut components {
        if let Err(error) = component.termination_target().signal_hard() {
            debug!(
                target = %component.termination_target().stored_id(),
                %error,
                "startup rollback hard termination failed"
            );
        }
        let _ = component.kill_leader();
    }

    let deadline = Instant::now() + CHILD_COLLECTION_TIMEOUT;
    loop {
        let mut children_collected = true;
        for component in &mut components {
            if !collect_child_until(component.child_mut(), Instant::now()) {
                children_collected = false;
            }
        }
        let mut all_absent = true;
        let mut probe_error = None;
        for component in &components {
            match component.termination_target().exists() {
                Ok(false) => {}
                Ok(true) => all_absent = false,
                Err(error) => {
                    debug!(
                        target = %component.termination_target().stored_id(),
                        %error,
                        "startup rollback target probe failed"
                    );
                    if probe_error.is_none() {
                        probe_error = Some(error);
                    }
                    all_absent = false;
                }
            }
        }
        if all_absent && children_collected {
            return remove_startup_state(state_dir, topology, state_lease, transaction);
        }
        if probe_error.is_some() || Instant::now() >= deadline {
            debug!("startup rollback retained runtime state for a later cleanup attempt");
            let collection_result = match collect_in_background(components) {
                Ok(()) => Ok(()),
                Err(error) => {
                    debug!(error = %error.reason(), "could not hand rollback to component collector");
                    let components = error.into_components().unwrap_or_default();
                    terminate_and_collect_components(components).map_err(OrchestratorError::Io)
                }
            };
            let rollback_error = probe_error.unwrap_or(OrchestratorError::TerminationTimeout {
                timeout_secs: CHILD_COLLECTION_TIMEOUT.as_secs(),
            });
            return Err(with_rollback(rollback_error, collection_result));
        }
        std::thread::sleep(STARTUP_ROLLBACK_POLL_INTERVAL);
    }
}

impl RunningStack {
    /// Construct the sole running owner from complete process and state capabilities.
    ///
    /// The startup [`StateTransaction`] remains held until
    /// [`RunningStack::mark_ready`] commits complete-state publication.
    fn from_components(
        components: Vec<OwnedComponent>,
        ready_components: Vec<ReadyComponent>,
        topology: StackTopology,
        state_dir: PathBuf,
        state_lease: StateLease,
        startup_transaction: Option<StateTransaction>,
    ) -> Self {
        let handle = StackHandle {
            components: components
                .iter()
                .zip(ready_components)
                .map(|(component, ready)| ComponentHandle {
                    name: component.name().as_str().to_string(),
                    leader_pid: component.leader_pid(),
                    endpoint: ready.endpoint().clone(),
                })
                .collect(),
        };
        Self {
            handle,
            state: RunningStackState::Owned(Box::new(OwnedStack {
                components,
                topology,
                state_dir,
                state_lease,
                startup_transaction,
            })),
        }
    }

    /// Borrow capabilities only while state is [`RunningStackState::Owned`].
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Platform`] after ownership has been consumed.
    fn owned_mut(&mut self) -> Result<&mut OwnedStack, OrchestratorError> {
        match &mut self.state {
            RunningStackState::Owned(owned) => Ok(owned),
            RunningStackState::Stopped => Err(OrchestratorError::Platform(
                "stack process ownership is no longer available".into(),
            )),
        }
    }

    /// Commit complete-state publication by releasing startup serialization.
    ///
    /// Process and cleanup capabilities remain in [`OwnedStack`]; this transition
    /// only allows other processes to snapshot the now-complete runtime state.
    fn mark_ready(&mut self) -> Result<(), OrchestratorError> {
        let owned = self.owned_mut()?;
        owned.startup_transaction = None;
        Ok(())
    }

    /// Borrow the informational handle, including ready endpoints.
    #[must_use]
    pub const fn handle(&self) -> &StackHandle {
        &self.handle
    }

    /// Stop the stack and collect its child processes.
    ///
    /// # Errors
    ///
    /// Returns [`ShutdownError::TeardownUncertain`] when process absence cannot
    /// be proven, or [`ShutdownError::StateCleanup`] when only durable state
    /// cleanup fails after every process is confirmed absent.
    pub fn shutdown(&mut self, timeout: Duration) -> Result<StopOutcome, ShutdownError> {
        let RunningStackState::Owned(owned) = &mut self.state else {
            return Ok(StopOutcome { forced: false });
        };
        // A detached attachment failure may tear down before publishing ready.
        // Release startup serialization before the owned stop reacquires it.
        owned.startup_transaction = None;
        let state_dir = &owned.state_dir;
        let state_lease = owned.state_lease;
        let result = crate::stop::stop_owned(
            state_dir,
            timeout,
            &owned.topology,
            &mut owned.components,
            state_lease,
        );
        if matches!(result.as_ref(), Ok(_) | Err(ShutdownError::StateCleanup(_))) {
            for component in owned.components.iter_mut().rev() {
                let _ = component.wait();
            }
            self.state = RunningStackState::Stopped;
        }
        result
    }

    /// Leave the stack running while transferring direct-child collection.
    ///
    /// The stack remains owned if the persistent collector rejects the handoff,
    /// allowing `Drop` to apply its fail-closed fallback rather than losing
    /// process capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if collection ownership cannot be transferred.
    pub fn detach(&mut self) -> Result<(), OrchestratorError> {
        let state = std::mem::replace(&mut self.state, RunningStackState::Stopped);
        if let RunningStackState::Owned(owned) = state {
            let mut owned = *owned;
            let components = std::mem::take(&mut owned.components);
            return match collect_in_background(components) {
                Ok(()) => Ok(()),
                Err(error) => {
                    let message = format!(
                        "could not transfer components to background reaper: {}",
                        error.reason()
                    );
                    owned.components = error.into_components().unwrap_or_default();
                    self.state = RunningStackState::Owned(Box::new(owned));
                    Err(OrchestratorError::Platform(message))
                }
            };
        }
        Ok(())
    }

    /// Hard-terminate and transfer collection without deleting runtime state.
    fn emergency_terminate(&mut self) {
        let state = std::mem::replace(&mut self.state, RunningStackState::Stopped);
        let RunningStackState::Owned(owned) = state else {
            return;
        };
        let mut components = owned.components;
        for component in &mut components {
            let _ = component.termination_target().signal_hard();
            let _ = component.kill_leader();
        }
        if let Err(error) = collect_in_background(components) {
            debug!(error = %error.reason(), "dropped stack could not hand off collection");
            error.forget();
        }
    }
}

impl Drop for RunningStack {
    fn drop(&mut self) {
        self.emergency_terminate();
    }
}

/// Spawn the stack and wait for readiness without blocking on supervision.
///
/// Returns ownership of the component child handles once every component is
/// listening. `topology` defines startup order and runtime-state identity;
/// `build_component` receives an aligned [`ComponentPlanContext`] immediately
/// before each component's spawn, in topology order. Its prior endpoints have
/// already passed publication validation, probing, and canonical publication.
/// Planning begins **after** the lock is claimed and the generation startup-report
/// directory is created, so an already-running stack is reported before the
/// caller's (possibly failing) resolution runs. Commands are spawned unchanged
/// except for the documented lifecycle process settings on [`ComponentSpec`].
/// The caller chooses an ownership transition on the returned stack:
/// [`RunningStack::shutdown`] tears it down, [`RunningStack::detach`] explicitly
/// leaves it running under the persistent collector, and [`Drop`] is a
/// fail-closed emergency termination path. See the
/// [crate-level lifecycle model](crate).
///
/// Used by wrappers that need in-process ownership after readiness.
///
/// # Errors
///
/// Returns state-directory, lock, plan-resolution, spawn, or readiness errors.
/// On failure after children have been spawned, this function tears them down.
/// Runtime state is retained when target disappearance cannot be confirmed so
/// callers can retry cleanup.
pub fn spawn_stack_from_plan<E>(
    topology: &StackTopology,
    build_component: impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, E>,
    state_dir: &Path,
    timeouts: LifecycleTimeouts,
) -> Result<RunningStack, StartError<E>> {
    spawn_stack_from_plan_with_phase(
        topology,
        build_component,
        state_dir,
        true,
        StackGeneration::new(),
        None,
        timeouts,
    )
}

/// Spawn a stack while optionally deferring complete-state publication.
///
/// [`StateTransaction`] acquisition precedes the supplied [`StackGeneration`]
/// claim and remains in the returned [`RunningStack`] when detached attachment
/// must publish more state. Component planning begins only after the lock is
/// claimed, so an already-running stack is reported before plan resolution.
/// When supplied, one [`StopSignal`] spans readiness and supervision so
/// termination cannot fall between those phases. Every error after
/// [`StartupGuard::new`] remains rollback-protected.
fn spawn_stack_from_plan_with_phase<E>(
    topology: &StackTopology,
    build_component: impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, E>,
    state_dir: &Path,
    publish_ready: bool,
    generation: StackGeneration,
    stop_signal: Option<&StopSignal>,
    timeouts: LifecycleTimeouts,
) -> Result<RunningStack, StartError<E>> {
    info!(state_dir = %state_dir.display(), "spawning stack");
    initialize_collector().map_err(OrchestratorError::Io)?;
    firma_fs::create_private_dir_all(state_dir).map_err(OrchestratorError::StateDir)?;
    let transaction = StateTransaction::acquire(state_dir)?;
    debug!("acquiring stack lock");
    let state_lease = acquire_lock(state_dir, &transaction, generation, topology)?;
    let mut startup = StartupGuard::new(state_dir, state_lease, transaction, topology.clone());
    let startup_result = (|| {
        startup.prepare_startup_report_dir()?;
        debug!("reaping stale pidfiles");
        reap_stale(state_dir, topology)?;

        let startup_report_paths: Vec<_> = topology
            .components()
            .iter()
            .enumerate()
            .map(|(index, _)| startup.startup_report_dir.join(format!("{index}.toml")))
            .collect();
        clear_canonical_listen_state(state_dir, topology)?;
        let ready_components = spawn_stack_inner(
            topology,
            build_component,
            startup_report_paths,
            state_dir,
            &mut startup,
            stop_signal,
            timeouts.component_readiness,
        )?;
        startup.cleanup_startup_reports()?;
        Ok::<_, StartError<E>>(ready_components)
    })();
    let ready_components = match startup_result {
        Ok(ready_components) => ready_components,
        Err(error) => {
            debug!("startup failed; rolling back explicit ownership");
            let rollback = startup.rollback();
            return Err(with_start_rollback(error, rollback));
        }
    };

    let mut stack = startup.finish(ready_components)?;
    if publish_ready {
        stack.mark_ready()?;
    }
    info!(components = ?stack.handle.components, "stack ready");
    Ok(stack)
}

/// Perform the ordered, rollback-protected component startup sequence.
///
/// The topology fixes component cardinality and order before any spawn. For each
/// identity, the caller produces one complete [`ComponentSpec`] using only
/// prior validated endpoints and its own generation publication context. Each
/// successful spawn is recorded in [`StartupGuard`] before the next fallible
/// step, and probe callbacks use [`StartupGuard::exited_component`] rather than
/// unowned process identities. These probes establish bounded startup evidence
/// only; ongoing health belongs to supervision.
fn spawn_stack_inner<E>(
    topology: &StackTopology,
    mut build_component: impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, E>,
    startup_report_paths: Vec<PathBuf>,
    state_dir: &Path,
    startup: &mut StartupGuard,
    stop_signal: Option<&StopSignal>,
    readiness_timeout: Duration,
) -> Result<Vec<ReadyComponent>, StartError<E>> {
    let mut ready_components = Vec::with_capacity(topology.components().len());

    for (name, startup_report_path) in topology
        .components()
        .iter()
        .cloned()
        .zip(startup_report_paths)
    {
        let context =
            ComponentPlanContext::new(name.as_str(), &startup_report_path, &ready_components);
        let spec = build_component(context).map_err(StartError::Plan)?;
        let ComponentSpec {
            mut command,
            readiness,
        } = spec;
        let mut publication = ComponentPublicationGuard::new(
            startup_report_path.clone(),
            state_dir.join(name.listen_file_name()),
        );
        // Each component needs an independently probeable and terminable scope
        // so dependency-sequential shutdown can settle it before advancing.
        let group = SystemPlatform::new_group()?;
        SystemPlatform::arm_group_termination(&group)?;
        let pid = startup.spawn_component(&group, &name, &mut command)?;
        info!(component = %name.as_str(), pid = %pid, "component spawned");
        let endpoint = match readiness {
            Readiness::Configured(endpoint) => wait_for_endpoint(
                name.as_str(),
                &endpoint,
                readiness_timeout,
                stop_signal,
                || startup.exited_component(),
            )?,
            Readiness::ChildPublished(crate::component::ChildPublishedReadiness {
                expected_endpoint,
            }) => {
                let endpoint = wait_for_child_published(
                    name.as_str(),
                    &expected_endpoint,
                    &startup_report_path,
                    readiness_timeout,
                    stop_signal,
                    || startup.exited_component(),
                )?;
                publication.remove_startup_report()?;
                endpoint
            }
        };
        if let Some((component, status)) = startup.exited_component()? {
            return Err(OrchestratorError::ReadinessProcessExited { component, status }.into());
        }
        publication.publish_canonical(&endpoint)?;
        if let Some((component, status)) = startup.exited_component()? {
            return Err(OrchestratorError::ReadinessProcessExited { component, status }.into());
        }
        info!(component = %name.as_str(), endpoint = %endpoint, "component listening");
        ready_components.push(publication.commit(&name, endpoint));
    }

    Ok(ready_components)
}

/// Start a caller-described stack in the foreground.
///
/// The plan is resolved only after the topology's runtime-state lock is claimed.
/// `timeouts` bounds component readiness and graceful shutdown.
///
/// # Errors
///
/// Returns state directory, plan-resolution, spawn, readiness, or detach errors.
/// On failure after children have been spawned, this function tears them down.
/// Runtime state is retained when hard termination fails so callers can retry
/// cleanup.
pub fn start_foreground_from_plan<E>(
    topology: &StackTopology,
    build_component: impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, E>,
    state_dir: &Path,
    timeouts: LifecycleTimeouts,
) -> Result<StackHandle, StartError<E>> {
    let stop_signal = StopSignal::install()?;
    let mut stack = spawn_stack_from_plan_with_phase(
        topology,
        build_component,
        state_dir,
        true,
        StackGeneration::new(),
        Some(&stop_signal),
        timeouts,
    )?;
    let handle = stack.handle().clone();
    info!("entering foreground supervisor loop");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit_with(&stop_signal, &mut owned.components)
    };
    info!("foreground supervisor exiting; tearing down stack");
    let teardown_result = stack
        .shutdown(timeouts.graceful_teardown)
        .map_err(ShutdownError::into_orchestrator_error);
    if let Err(error) = supervision_result {
        return Err(StartError::Orchestrator(with_rollback(
            error,
            teardown_result,
        )));
    }
    teardown_result?;
    Ok(handle)
}

/// Launch a generation-bound supervisor that becomes the component owner.
///
/// The handoff protocol is defined by [`LauncherAttachmentState`]. The launcher
/// retains the supervisor child handle through both phases and uses
/// [`rollback_detached_start`] on any failure before collection transfer. The
/// caller constructs the complete supervisor command from the allocated
/// generation. The orchestrator adds detached-process settings and log
/// redirection, but assigns no command-line protocol to the child.
/// `timeouts` applies to the handoff and failed-handoff rollback; callers must
/// separately pass the same policy to the supervisor process they construct.
///
/// # Errors
///
/// Returns state-directory, supervisor spawn, attachment, handle
/// reconstruction, collection-transfer, or rollback errors.
pub fn start_detached(
    topology: &StackTopology,
    state_dir: &Path,
    timeouts: LifecycleTimeouts,
    build_supervisor: impl FnOnce(StackGeneration) -> Command,
) -> Result<StackHandle, OrchestratorError> {
    initialize_collector().map_err(OrchestratorError::Io)?;
    firma_fs::create_private_dir_all(state_dir).map_err(OrchestratorError::StateDir)?;
    let generation = StackGeneration::new();
    info!("forking detached supervisor owner");
    let mut supervisor_command = build_supervisor(generation);
    let supervisor = spawn_supervisor(state_dir, &mut supervisor_command)?;
    let mut launch = DetachedLaunchGuard::new(
        supervisor,
        generation,
        state_dir,
        topology,
        timeouts.graceful_teardown,
    );
    let launch_result = (|| {
        wait_for_supervisor_attachment(
            state_dir,
            launch.supervisor_mut()?,
            timeouts.detached_handoff,
        )?;
        let handle = read_stack_handle(state_dir, topology)?;
        launch.transfer_to_collector()?;
        Ok(handle)
    })();
    match launch_result {
        Ok(handle) => Ok(handle),
        Err(error) => Err(with_rollback(error, launch.rollback())),
    }
}

/// Roll back only state matching this launcher's [`StackGeneration`].
fn rollback_detached_start(
    state_dir: &Path,
    topology: &StackTopology,
    generation: StackGeneration,
    teardown_timeout: Duration,
) -> Result<(), OrchestratorError> {
    crate::stop::stop_generation(state_dir, teardown_timeout, topology, generation).map(|_| ())
}

/// Terminate the supervisor and preserve collection responsibility.
fn terminate_detached_supervisor(
    mut supervisor: std::process::Child,
) -> Result<(), OrchestratorError> {
    let target =
        TerminationTarget::for_leader(firma_runtime_state::ChildExt::process_id(&supervisor));
    let _ = target.signal_hard();
    let _ = supervisor.kill();
    if collect_child_until(&mut supervisor, Instant::now() + CHILD_COLLECTION_TIMEOUT) {
        return Ok(());
    }
    match collect_child_in_background(supervisor) {
        Ok(()) => Ok(()),
        Err(error) => {
            let Some(mut supervisor) = error.into_child() else {
                return Err(OrchestratorError::Platform(
                    "supervisor collector returned a different ownership payload".into(),
                ));
            };
            supervisor.wait().map(|_| ()).map_err(OrchestratorError::Io)
        }
    }
}

/// Explicit fallback when the pre-initialized collector rejects components.
fn terminate_and_collect_components(mut components: Vec<OwnedComponent>) -> std::io::Result<()> {
    for component in &mut components {
        let _ = component.termination_target().signal_hard();
        let _ = component.kill_leader();
    }
    let mut collection_error = None;
    for component in &mut components {
        if let Err(error) = component.wait()
            && !SystemPlatform::child_already_reaped(&error)
            && collection_error.is_none()
        {
            collection_error = Some(error);
        }
    }
    collection_error.map_or(Ok(()), Err)
}

/// Reconstruct an informational [`StackHandle`] after supervisor-owned startup.
///
/// The caller supplies the topology used for startup; this does not grant
/// component collection, termination, or cleanup authority.
fn read_stack_handle(
    state_dir: &Path,
    topology: &StackTopology,
) -> Result<StackHandle, OrchestratorError> {
    let mut components = Vec::with_capacity(topology.components().len());
    for name in topology.names() {
        let pid = pidfile::read(&state_dir.join(format!("{name}.pid")))?.ok_or_else(|| {
            OrchestratorError::Platform(format!("{name}.pid missing after startup"))
        })?;
        let endpoint =
            read_endpoint(&state_dir.join(format!("{name}.listen")), name)?.ok_or_else(|| {
                OrchestratorError::Platform(format!("{name}.listen missing after startup"))
            })?;
        components.push(ComponentHandle {
            name: name.to_string(),
            leader_pid: pid,
            endpoint,
        });
    }
    Ok(StackHandle { components })
}

/// Remove rollback-owned state through [`crate::stop::cleanup_generation`].
///
/// A missing [`StateTransaction`] cannot safely authorize deletion, so this
/// destructor path retains state for a later [`crate::stop::stop_components()`].
fn remove_startup_state(
    state_dir: &Path,
    topology: &StackTopology,
    state_lease: StateLease,
    transaction: Option<&StateTransaction>,
) -> Result<(), OrchestratorError> {
    let Some(transaction) = transaction else {
        return Err(OrchestratorError::Platform(
            "startup rollback lost state transaction; retaining runtime state".into(),
        ));
    };
    crate::stop::cleanup_generation(state_dir, topology, Some(state_lease), transaction)
}

/// Preserve the initiating failure together with any required rollback failure.
fn with_rollback<T>(
    operation: OrchestratorError,
    rollback: Result<T, OrchestratorError>,
) -> OrchestratorError {
    match rollback {
        Ok(_) => operation,
        Err(rollback) => OrchestratorError::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        },
    }
}

/// Preserve a planning or orchestration failure with explicit startup rollback.
fn with_start_rollback<E>(
    operation: StartError<E>,
    rollback: Result<(), OrchestratorError>,
) -> StartError<E> {
    match rollback {
        Ok(()) => operation,
        Err(rollback) => StartError::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        },
    }
}

/// Spawn and own a detached stack for a launcher-assigned generation.
///
/// [`StopSignal`] is installed before component readiness and reused by
/// [`supervise_running_stack_with_signal`] for the two-phase handoff and
/// supervision. `timeouts` bounds readiness, handoff, and graceful teardown.
///
/// # Errors
///
/// Returns startup, readiness, supervision, termination, or cleanup errors.
#[doc(hidden)]
pub fn supervise_owned_generation_from_plan<E>(
    topology: &StackTopology,
    build_component: impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, E>,
    state_dir: &Path,
    generation: StackGeneration,
    timeouts: LifecycleTimeouts,
) -> Result<(), StartError<E>> {
    let stop_signal = StopSignal::install()?;
    let stack = spawn_stack_from_plan_with_phase(
        topology,
        build_component,
        state_dir,
        false,
        generation,
        Some(&stop_signal),
        timeouts,
    )?;
    supervise_running_stack_with_signal(stack, state_dir, timeouts, &stop_signal)
        .map_err(StartError::Orchestrator)
}

/// Execute the supervisor side of [`LauncherAttachmentState`] and own teardown.
///
/// Attachment state is written while the startup [`StateTransaction`] remains
/// held. Any publication or acknowledgement failure invokes
/// [`RunningStack::shutdown`] before returning.
fn supervise_running_stack_with_signal(
    mut stack: RunningStack,
    state_dir: &Path,
    timeouts: LifecycleTimeouts,
    stop_signal: &StopSignal,
) -> Result<(), OrchestratorError> {
    let supervisor_pid = UserProcessId::new(std::process::id()).ok_or_else(|| {
        OrchestratorError::Platform("current process returned invalid process id".into())
    })?;
    let attachment_result = (|| {
        let ready_path = supervisor_ready_path(state_dir, supervisor_pid);
        pidfile::write(&state_dir.join("stack.pid"), supervisor_pid)?;
        pidfile::write(&ready_path, supervisor_pid)?;
        wait_for_launcher_ack(&ready_path, stop_signal, timeouts.detached_handoff)?;
        pidfile::write(
            &supervisor_attached_path(state_dir, supervisor_pid),
            supervisor_pid,
        )?;
        stack.mark_ready()?;
        Ok(())
    })();
    if let Err(error) = attachment_result {
        let _ = stack.mark_ready();
        let rollback = stack
            .shutdown(timeouts.graceful_teardown)
            .map_err(ShutdownError::into_orchestrator_error);
        return Err(with_rollback(error, rollback));
    }

    info!(supervisor_pid = %supervisor_pid, state_dir = %state_dir.display(), "detached supervisor owns ready stack");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit_with(stop_signal, &mut owned.components)
    };
    info!("detached supervisor tearing down owned components");
    let teardown_result = stack
        .shutdown(timeouts.graceful_teardown)
        .map_err(ShutdownError::into_orchestrator_error);
    if let Err(error) = supervision_result {
        return Err(with_rollback(error, teardown_result));
    }
    teardown_result.map(|_| ())
}

/// Execute the launcher side of [`LauncherAttachmentState`].
///
/// Child exit, identity mismatch, or timeout leaves the launcher responsible for
/// terminating and collecting the supervisor.
fn wait_for_supervisor_attachment(
    state_dir: &Path,
    supervisor: &mut std::process::Child,
    timeout: Duration,
) -> Result<(), OrchestratorError> {
    let expected_pid = UserProcessId::new(supervisor.id()).ok_or_else(|| {
        OrchestratorError::Platform("detached supervisor returned invalid process id".into())
    })?;
    let ready_path = supervisor_ready_path(state_dir, expected_pid);
    let attached_path = supervisor_attached_path(state_dir, expected_pid);
    let deadline = Instant::now() + timeout;
    let mut attachment = LauncherAttachmentState::AwaitingReadiness;
    loop {
        if matches!(attachment, LauncherAttachmentState::AwaitingReadiness)
            && let Some(ready_pid) = pidfile::read(&ready_path)?
        {
            if ready_pid != expected_pid {
                return Err(OrchestratorError::Platform(format!(
                    "detached supervisor readiness belongs to pid {ready_pid}, expected {expected_pid}"
                )));
            }
            pidfile::remove(&ready_path)?;
            attachment = LauncherAttachmentState::AwaitingConfirmation;
        }
        if matches!(attachment, LauncherAttachmentState::AwaitingConfirmation)
            && let Some(attached_pid) = pidfile::read(&attached_path)?
        {
            if attached_pid != expected_pid {
                return Err(OrchestratorError::Platform(format!(
                    "detached supervisor attachment belongs to pid {attached_pid}, expected {expected_pid}"
                )));
            }
            pidfile::remove(&attached_path)?;
            if supervisor.try_wait()?.is_some() {
                return Err(OrchestratorError::Platform(
                    "detached supervisor exited after confirming attachment".into(),
                ));
            }
            return Ok(());
        }
        if supervisor.try_wait()?.is_some() {
            let phase = match attachment {
                LauncherAttachmentState::AwaitingReadiness => "before announcing readiness",
                LauncherAttachmentState::AwaitingConfirmation => {
                    "after readiness but before confirming attachment"
                }
            };
            return Err(OrchestratorError::Platform(format!(
                "detached supervisor exited {phase}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(OrchestratorError::Readiness {
                component: "detached supervisor".into(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(DETACHED_HANDOFF_POLL_INTERVAL);
    }
}

/// Return the first-phase readiness path scoped to one supervisor identity.
pub(crate) fn supervisor_ready_path(state_dir: &Path, supervisor_pid: UserProcessId) -> PathBuf {
    state_dir.join(format!("stack.{supervisor_pid}.ready"))
}

/// Return the second-phase confirmation path for [`LauncherAttachmentState`].
pub(crate) fn supervisor_attached_path(state_dir: &Path, supervisor_pid: UserProcessId) -> PathBuf {
    state_dir.join(format!("stack.{supervisor_pid}.attached"))
}

/// Wait for the launcher acknowledgement defined by [`LauncherAttachmentState`].
///
/// # Errors
///
/// Returns termination-request or acknowledgement-timeout errors.
fn wait_for_launcher_ack(
    ready_path: &Path,
    stop_signal: &StopSignal,
    timeout: Duration,
) -> Result<(), OrchestratorError> {
    let deadline = Instant::now() + timeout;
    while ready_path.try_exists()? {
        if stop_signal.requested() {
            return Err(OrchestratorError::Platform(
                "termination requested before launcher attachment".into(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(OrchestratorError::Readiness {
                component: "detached launcher acknowledgement".into(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(DETACHED_HANDOFF_POLL_INTERVAL);
    }
    Ok(())
}

/// Claim the launcher's [`StackGeneration`] only after existing state is stale.
///
/// The caller's [`StateTransaction`] prevents another mutator from racing stale
/// state removal with generation publication.
fn acquire_lock(
    state_dir: &Path,
    _transaction: &StateTransaction,
    generation: StackGeneration,
    topology: &StackTopology,
) -> Result<StateLease, OrchestratorError> {
    let lock = state_dir.join("stack.lock");
    loop {
        if !is_stack_stale(state_dir, topology)? {
            return Err(OrchestratorError::AlreadyRunning { path: lock });
        }
        if let Some(state_lease) = StateLease::try_claim(state_dir, generation)? {
            return Ok(state_lease);
        }
        std::fs::remove_file(&lock)?;
    }
}

/// Prove that no persisted supervisor or component target remains live.
fn is_stack_stale(state_dir: &Path, topology: &StackTopology) -> Result<bool, OrchestratorError> {
    if let Some(pid) = pidfile::read(&state_dir.join("stack.pid"))?
        && process_exists(pid)?
    {
        return Ok(false);
    }
    for name in topology.names() {
        if let Some(id) = pidfile::read(&state_dir.join(format!("{name}.pid")))?
            && TerminationTarget::from_stored_id(id).exists()?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Remove process records only after their targets are proven absent.
fn reap_stale(state_dir: &Path, topology: &StackTopology) -> Result<(), OrchestratorError> {
    for name in topology.names() {
        let path = state_dir.join(format!("{name}.pid"));
        if let Some(id) = pidfile::read(&path)?
            && !TerminationTarget::from_stored_id(id).exists()?
        {
            pidfile::remove(&path)?;
        }
    }
    let supervisor = state_dir.join("stack.pid");
    if let Some(pid) = pidfile::read(&supervisor)?
        && !process_exists(pid)?
    {
        pidfile::remove(&supervisor)?;
    }
    Ok(())
}

fn clear_canonical_listen_state(
    state_dir: &Path,
    topology: &StackTopology,
) -> Result<(), OrchestratorError> {
    for name in topology.names() {
        pidfile::remove(&state_dir.join(format!("{name}.listen")))?;
    }
    Ok(())
}

fn publish_canonical_listen_endpoint(
    path: &Path,
    endpoint: &ComponentEndpoint,
) -> Result<(), OrchestratorError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(temp, "{endpoint}")?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn startup_report_dir(state_dir: &Path, generation: StackGeneration) -> PathBuf {
    state_dir.join(format!(".startup-{generation}"))
}

fn create_private_startup_report_dir(path: &Path) -> Result<(), OrchestratorError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700).create(path)?;
    }
    #[cfg(windows)]
    std::fs::create_dir(path)?;
    Ok(())
}

pub(crate) fn remove_startup_report_dir(path: &Path) -> Result<(), OrchestratorError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => std::fs::remove_dir_all(path)?,
        Ok(_) => std::fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Map a supervisor liveness probe into the stack error contract.
fn process_exists(pid: UserProcessId) -> Result<bool, OrchestratorError> {
    pid.process_exists().map_err(OrchestratorError::Io)
}
