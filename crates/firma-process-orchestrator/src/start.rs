//! Stack startup, ownership, and supervision transitions.
//!
//! [`spawn_stack_from_plan`] claims a [`StateLease`] under a [`StateTransaction`]
//! and returns the sole [`RunningStack`] owner after ordered readiness.
//! [`StartupGuard`] owns every partial startup until [`StartupGuard::finish`]
//! commits that transition; its [`Drop`] implementation rolls back uncommitted
//! [`OwnedComponent`] capabilities. Foreground startup retains that owner in
//! foreground mode. In detached mode, [`start_detached`] owns only the
//! supervisor child while [`supervise_owned_generation_from_plan`] spawns and
//! owns the components, so no component capability crosses a process boundary.
//! Failure paths retain runtime state unless target absence can be proved,
//! allowing [`crate::stop_components()`] to retry cleanup without losing process
//! authority.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::LifecycleTimeouts;
use crate::StackTopology;
use crate::collect::{collect_child_in_background, collect_child_until};
use crate::component::{ComponentContext, ComponentName, ComponentSpec, OwnedComponent, Readiness};
use crate::detach::spawn_supervisor;
use crate::error::{OrchestratorError, StartError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::{wait_for_child_published_tcp, wait_for_tcp};
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
#[derive(Clone)]
pub struct StackHandle {
    /// Ordered component identities paired with their leader PIDs.
    component_pids: Vec<(String, UserProcessId)>,
}

/// An in-process stack whose component child handles are owned by the caller.
///
/// Call [`RunningStack::shutdown`] for an orderly teardown. Successful shutdown
/// consumes the [`OwnedStack`], so repeated calls are no-ops. Dropping this
/// value does not terminate the stack; [`RunningStack::transfer_to_observer`]
/// transfers collection to a background owner so later exits cannot remain
/// zombies.
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
/// fallible operation. Unless [`StartupGuard::finish`] commits the
/// [`StartupState::Building`] components to a [`RunningStack`], [`Drop`]
/// delegates rollback to [`rollback_startup_components`]. The guard retains the
/// [`StateTransaction`] and [`StateLease`] needed to remove only its generation;
/// target or collection uncertainty preserves state for [`crate::stop::stop_components()`].
struct StartupGuard {
    state: StartupState,
    state_dir: PathBuf,
    state_lease: StateLease,
    transaction: Option<StateTransaction>,
    topology: StackTopology,
    publication_dir: PathBuf,
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
            publication_dir: publication_dir(state_dir, state_lease.generation()),
        }
    }

    fn prepare_publication_dir(&self) -> Result<(), OrchestratorError> {
        create_private_publication_dir(&self.publication_dir)
    }

    fn cleanup_publications(&self) -> Result<(), OrchestratorError> {
        if !self.state_lease.is_current(&self.state_dir)? {
            return Err(OrchestratorError::Platform(
                "startup generation changed before publication cleanup".into(),
            ));
        }
        remove_publication_dir(&self.publication_dir)
    }

    /// Append one owned component in spawn order to [`StartupState::Building`].
    ///
    /// # Errors
    ///
    /// Returns an error without changing state if startup has already finished.
    fn record(&mut self, component: OwnedComponent) -> Result<(), OrchestratorError> {
        match &mut self.state {
            StartupState::Building(components) => {
                components.push(component);
                Ok(())
            }
            StartupState::Finished => Err(OrchestratorError::Platform(
                "component child recorded after startup finished".into(),
            )),
        }
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
    fn finish(mut self) -> Result<RunningStack, OrchestratorError> {
        match std::mem::replace(&mut self.state, StartupState::Finished) {
            StartupState::Building(components) => Ok(RunningStack::from_components(
                components,
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
}

impl Drop for StartupGuard {
    /// Roll back the exact capability set represented by [`StartupState`].
    ///
    /// [`StartupState::Finished`] is the only disarmed state. Destruction cannot
    /// report cleanup errors, so [`rollback_startup_components`] preserves
    /// retryable runtime state when rollback cannot prove completion.
    fn drop(&mut self) {
        let state = std::mem::replace(&mut self.state, StartupState::Finished);
        let StartupState::Building(components) = state else {
            return;
        };
        if let Err(error) = self.cleanup_publications() {
            debug!(%error, "startup rollback retained endpoint publication state");
        }
        if components.is_empty() {
            remove_startup_state(
                &self.state_dir,
                &self.topology,
                self.state_lease,
                self.transaction.as_ref(),
            );
            return;
        }
        rollback_startup_components(
            components,
            &self.state_dir,
            &self.topology,
            self.state_lease,
            self.transaction.as_ref(),
        );
    }
}

/// Terminate and collect an incomplete startup without losing retry evidence.
///
/// All component [`TerminationTarget`] values receive a forced request before
/// bounded collection begins. If target absence or child collection cannot be
/// established, ownership moves to [`collect_in_background`]; reaper startup
/// failure uses [`crate::supervisor::ReaperStartError::terminate_and_collect`].
/// [`remove_startup_state`] applies the guard's generation fence only after
/// teardown is proven complete.
fn rollback_startup_components(
    mut components: Vec<OwnedComponent>,
    state_dir: &Path,
    topology: &StackTopology,
    state_lease: StateLease,
    transaction: Option<&StateTransaction>,
) {
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
        let mut probe_failed = false;
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
                    probe_failed = true;
                    all_absent = false;
                }
            }
        }
        if all_absent && children_collected {
            remove_startup_state(state_dir, topology, state_lease, transaction);
            return;
        }
        if probe_failed || Instant::now() >= deadline {
            debug!("startup rollback retained runtime state for a later cleanup attempt");
            if let Err(error) = collect_in_background(components) {
                debug!(error = %error.source(), "could not start rollback component reaper");
                if let Err(error) = error.terminate_and_collect() {
                    debug!(%error, "could not synchronously collect rollback components");
                }
            }
            return;
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
        topology: StackTopology,
        state_dir: PathBuf,
        state_lease: StateLease,
        startup_transaction: Option<StateTransaction>,
    ) -> Self {
        let handle = StackHandle {
            component_pids: components
                .iter()
                .map(|component| {
                    (
                        component.name().as_str().to_string(),
                        component.leader_pid(),
                    )
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

    /// Return an informational handle containing the component process IDs.
    #[must_use]
    fn handle(&self) -> StackHandle {
        self.handle.clone()
    }

    /// Stop the stack and collect its child processes.
    ///
    /// # Errors
    ///
    /// Returns process-probe, termination, or runtime-state cleanup errors.
    pub fn shutdown(&mut self, timeout: Duration) -> Result<StopOutcome, OrchestratorError> {
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
        if result.is_ok() {
            for component in owned.components.iter_mut().rev() {
                let _ = component.wait();
            }
            self.state = RunningStackState::Stopped;
        }
        result
    }

    /// Transfer child collection to a background owner and disarm this value.
    fn transfer_to_observer(&mut self) -> bool {
        let state = std::mem::replace(&mut self.state, RunningStackState::Stopped);
        if let RunningStackState::Owned(owned) = state {
            let owned = *owned;
            return match collect_in_background(owned.components) {
                Ok(_) => true,
                Err(error) => {
                    debug!(error = %error.source(), "could not transfer components to background reaper");
                    if let Err(error) = error.terminate_and_collect() {
                        debug!(%error, "could not synchronously collect transferred components");
                    }
                    false
                }
            };
        }
        true
    }
}

impl Drop for RunningStack {
    fn drop(&mut self) {
        let _ = self.transfer_to_observer();
    }
}

/// Spawn the stack and wait for readiness without blocking on supervision.
///
/// Returns ownership of the component child handles once every component is
/// listening. `topology` defines startup order and runtime-state identity;
/// `build_plan` receives one aligned [`ComponentContext`] per topology component
/// and resolves the full [`ComponentSpec`] plan. It is invoked **after** the
/// lock is claimed and the generation publication directory is created, so an
/// already-running stack is reported before the caller's (possibly failing)
/// plan resolution runs. Commands are spawned unchanged except for the
/// documented lifecycle process settings on [`ComponentSpec`]. The caller must eventually call
/// [`RunningStack::shutdown`] to tear the stack down and collect its children.
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
    build_plan: impl FnOnce(&[ComponentContext<'_>]) -> Result<Vec<ComponentSpec>, E>,
    state_dir: &Path,
    timeouts: LifecycleTimeouts,
) -> Result<RunningStack, StartError<E>> {
    spawn_stack_from_plan_with_phase(
        topology,
        build_plan,
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
/// must publish more state. `build_plan` is invoked only after the lock is
/// claimed, so an already-running stack is reported before plan resolution.
/// When supplied, one [`StopSignal`] spans readiness and supervision so
/// termination cannot fall between those phases. Every error after
/// [`StartupGuard::new`] remains rollback-protected.
fn spawn_stack_from_plan_with_phase<E>(
    topology: &StackTopology,
    build_plan: impl FnOnce(&[ComponentContext<'_>]) -> Result<Vec<ComponentSpec>, E>,
    state_dir: &Path,
    publish_ready: bool,
    generation: StackGeneration,
    stop_signal: Option<&StopSignal>,
    timeouts: LifecycleTimeouts,
) -> Result<RunningStack, StartError<E>> {
    info!(state_dir = %state_dir.display(), "spawning stack");
    firma_fs::create_private_dir_all(state_dir).map_err(OrchestratorError::StateDir)?;
    let transaction = StateTransaction::acquire(state_dir)?;
    debug!("acquiring stack lock");
    let state_lease = acquire_lock(state_dir, &transaction, generation, topology)?;
    let mut startup = StartupGuard::new(state_dir, state_lease, transaction, topology.clone());
    startup.prepare_publication_dir()?;
    debug!("reaping stale pidfiles");
    reap_stale(state_dir, topology)?;

    let publication_paths: Vec<_> = topology
        .components()
        .iter()
        .enumerate()
        .map(|(index, _)| startup.publication_dir.join(format!("{index}.listen")))
        .collect();
    let contexts: Vec<_> = topology
        .components()
        .iter()
        .zip(&publication_paths)
        .map(|(name, path)| ComponentContext::new(name.as_str(), path))
        .collect();

    // The plan is resolved after the lock is claimed so that an already-running
    // stack is reported before any (possibly failing) plan resolution runs.
    let plan = build_plan(&contexts).map_err(StartError::Plan)?;
    if plan.len() != topology.components().len() {
        return Err(OrchestratorError::PlanCountMismatch {
            expected: topology.components().len(),
            actual: plan.len(),
        }
        .into());
    }
    clear_canonical_listen_state(state_dir, topology)?;
    match spawn_stack_inner(
        topology,
        plan,
        publication_paths,
        state_dir,
        &mut startup,
        stop_signal,
        timeouts.component_readiness,
    ) {
        Ok(()) => {
            startup.cleanup_publications()?;
            let mut stack = startup.finish()?;
            if publish_ready {
                stack.mark_ready()?;
            }
            let handle = stack.handle();
            info!(components = ?handle.component_pids, "stack ready");
            Ok(stack)
        }
        Err(error) => {
            debug!(%error, "spawn failed; startup guard will roll back");
            Err(StartError::Orchestrator(error))
        }
    }
}

/// Perform the ordered, rollback-protected component startup sequence.
///
/// The caller supplies a fully resolved [`ComponentSpec`] plan; this loop is
/// agnostic to which components it contains. Specs are spawned in order: each
/// component must remain owned and live before the next is spawned, and live
/// through its readiness probe. Each successful spawn records the component in
/// [`StartupGuard`] before the next fallible step, and probe callbacks use
/// [`StartupGuard::exited_component`] rather than unowned process identities.
/// These probes establish bounded startup evidence only; ongoing health belongs
/// to supervision.
fn spawn_stack_inner(
    topology: &StackTopology,
    plan: Vec<ComponentSpec>,
    publication_paths: Vec<PathBuf>,
    state_dir: &Path,
    startup: &mut StartupGuard,
    stop_signal: Option<&StopSignal>,
    readiness_timeout: Duration,
) -> Result<(), OrchestratorError> {
    let group = SystemPlatform::new_group()?;
    SystemPlatform::arm_group_termination(&group)?;

    for ((name, spec), publication_path) in topology
        .components()
        .iter()
        .cloned()
        .zip(plan)
        .zip(publication_paths)
    {
        let ComponentSpec {
            mut command,
            readiness,
        } = spec;
        let component = spawn_into_group(&group, state_dir, name.clone(), &mut command)?;
        let pid = component.leader_pid();
        startup.record(component)?;
        info!(component = %name.as_str(), pid = %pid, "component spawned");
        let addr = match readiness {
            Readiness::ConfiguredTcp(addr) => {
                wait_for_tcp(name.as_str(), addr, readiness_timeout, stop_signal, || {
                    startup.exited_component()
                })?;
                addr
            }
            Readiness::ChildPublishedTcp(crate::component::ChildPublishedTcpReadiness {
                requested_addr,
            }) => {
                let dial_addr = wait_for_child_published_tcp(
                    name.as_str(),
                    requested_addr,
                    &publication_path,
                    readiness_timeout,
                    stop_signal,
                    || startup.exited_component(),
                )?;
                std::fs::remove_file(&publication_path)?;
                dial_addr
            }
        };
        if let Some((component, status)) = startup.exited_component()? {
            return Err(OrchestratorError::ReadinessProcessExited { component, status });
        }
        publish_canonical_listen_addr(&state_dir.join(name.listen_file_name()), addr)?;
        if let Some((component, status)) = startup.exited_component()? {
            return Err(OrchestratorError::ReadinessProcessExited { component, status });
        }
        info!(component = %name.as_str(), addr = %addr, "component listening");
    }

    // The Group goes out of scope at the end of this function. On Unix that is
    // a no-op because children sit in their own process groups. On Windows,
    // each OwnedComponent retains a duplicate of the shared Job Object handle,
    // so closing the original handle does not terminate the ready stack.
    let _ = group;

    Ok(())
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
    build_plan: impl FnOnce(&[ComponentContext<'_>]) -> Result<Vec<ComponentSpec>, E>,
    state_dir: &Path,
    timeouts: LifecycleTimeouts,
) -> Result<StackHandle, StartError<E>> {
    let stop_signal = StopSignal::install()?;
    let mut stack = spawn_stack_from_plan_with_phase(
        topology,
        build_plan,
        state_dir,
        true,
        StackGeneration::new(),
        Some(&stop_signal),
        timeouts,
    )?;
    let handle = stack.handle();
    info!("entering foreground supervisor loop");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit_with(&stop_signal, &mut owned.components)
    };
    info!("foreground supervisor exiting; tearing down stack");
    let teardown_result = stack.shutdown(timeouts.graceful_teardown);
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
    firma_fs::create_private_dir_all(state_dir).map_err(OrchestratorError::StateDir)?;
    let generation = StackGeneration::new();
    info!("forking detached supervisor owner");
    let mut supervisor_command = build_supervisor(generation);
    let mut supervisor = spawn_supervisor(state_dir, &mut supervisor_command)?;
    if let Err(error) =
        wait_for_supervisor_attachment(state_dir, &mut supervisor, timeouts.detached_handoff)
    {
        terminate_detached_supervisor(&mut supervisor);
        let rollback =
            rollback_detached_start(state_dir, topology, generation, timeouts.graceful_teardown);
        return Err(with_rollback(error, rollback));
    }
    let handle = match read_stack_handle(state_dir, topology) {
        Ok(handle) => handle,
        Err(error) => {
            terminate_detached_supervisor(&mut supervisor);
            let rollback = rollback_detached_start(
                state_dir,
                topology,
                generation,
                timeouts.graceful_teardown,
            );
            return Err(with_rollback(error, rollback));
        }
    };
    if collect_child_in_background(supervisor).is_none() {
        let error =
            OrchestratorError::Platform("could not start detached supervisor collector".into());
        let rollback =
            rollback_detached_start(state_dir, topology, generation, timeouts.graceful_teardown);
        return Err(with_rollback(error, rollback));
    }
    Ok(handle)
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

/// Terminate and make a bounded collection attempt for the supervisor child.
fn terminate_detached_supervisor(supervisor: &mut std::process::Child) {
    let target =
        TerminationTarget::for_leader(firma_runtime_state::ChildExt::process_id(supervisor));
    let _ = target.signal_hard();
    let _ = supervisor.kill();
    let _ = collect_child_until(supervisor, Instant::now() + CHILD_COLLECTION_TIMEOUT);
}

/// Reconstruct an informational [`StackHandle`] after supervisor-owned startup.
///
/// The caller supplies the topology used for startup; this does not grant
/// component collection, termination, or cleanup authority.
fn read_stack_handle(
    state_dir: &Path,
    topology: &StackTopology,
) -> Result<StackHandle, OrchestratorError> {
    let mut component_pids = Vec::with_capacity(topology.components().len());
    for name in topology.names() {
        let pid = pidfile::read(&state_dir.join(format!("{name}.pid")))?.ok_or_else(|| {
            OrchestratorError::Platform(format!("{name}.pid missing after startup"))
        })?;
        component_pids.push((name.to_string(), pid));
    }
    Ok(StackHandle { component_pids })
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
) {
    let Some(transaction) = transaction else {
        debug!("startup rollback lost state transaction; retaining runtime state");
        return;
    };
    if let Err(error) =
        crate::stop::cleanup_generation(state_dir, topology, Some(state_lease), transaction)
    {
        debug!(%error, "startup rollback retained runtime state");
    }
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
    build_plan: impl FnOnce(&[ComponentContext<'_>]) -> Result<Vec<ComponentSpec>, E>,
    state_dir: &Path,
    generation: StackGeneration,
    timeouts: LifecycleTimeouts,
) -> Result<(), StartError<E>> {
    let stop_signal = StopSignal::install()?;
    let stack = spawn_stack_from_plan_with_phase(
        topology,
        build_plan,
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
        let rollback = stack.shutdown(timeouts.graceful_teardown);
        return Err(with_rollback(error, rollback));
    }

    info!(supervisor_pid = %supervisor_pid, state_dir = %state_dir.display(), "detached supervisor owns ready stack");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit_with(stop_signal, &mut owned.components)
    };
    info!("detached supervisor tearing down owned components");
    let teardown_result = stack.shutdown(timeouts.graceful_teardown);
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

/// Spawn one named component into the group with a caller-configured command.
fn spawn_into_group(
    group: &crate::platform::Group,
    state_dir: &Path,
    name: ComponentName,
    command: &mut std::process::Command,
) -> Result<OwnedComponent, OrchestratorError> {
    spawn_component(
        group,
        &mut SpawnRequest {
            name,
            command,
            state_dir,
        },
    )
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

fn publish_canonical_listen_addr(
    path: &Path,
    addr: std::net::SocketAddr,
) -> Result<(), OrchestratorError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(temp, "{addr}")?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn publication_dir(state_dir: &Path, generation: StackGeneration) -> PathBuf {
    state_dir.join(format!(".startup-{generation}"))
}

fn create_private_publication_dir(path: &Path) -> Result<(), OrchestratorError> {
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

pub(crate) fn remove_publication_dir(path: &Path) -> Result<(), OrchestratorError> {
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
