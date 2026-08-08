//! Stack startup, ownership, and supervision transitions.
//!
//! [`spawn_stack_from_plan`] claims a [`StateLease`] under a [`StateTransaction`]
//! and returns the sole [`RunningStack`] owner after ordered readiness.
//! [`StartupGuard`] owns every partial startup until [`StartupGuard::finish`]
//! commits that transition; its [`Drop`] implementation rolls back uncommitted
//! [`OwnedComponent`] capabilities. [`start_from_plan`] retains that owner in
//! foreground mode. In detached mode, [`start_detached`] owns only the
//! supervisor child while [`supervise_owned_generation_from_plan`] spawns and
//! owns the components, so no component capability crosses a process boundary.
//! Failure paths retain runtime state unless target absence can be proved,
//! allowing [`crate::stop_components()`] to retry cleanup without losing process
//! authority.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::component::{ComponentName, ComponentSpec, OwnedComponent};
use crate::error::{Result, StackError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::wait_for_tcp;
use crate::spawn::{SpawnRequest, spawn_component};
use crate::state_lease::{StackGeneration, StateLease, StateTransaction};
use crate::supervisor::{
    ReaperLauncher, StopSignal, block_until_owned_exit_with, collect_child_in_background,
    collect_child_until, collect_in_background, collect_in_background_with, launch_reaper,
};
use firma_runtime_state::{UserProcessId, pidfile};

/// Mode in which [`start_from_plan`] manages the stack after readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// Block in the calling thread, forwarding `SIGINT` / `SIGTERM` /
    /// `Ctrl-C` to children until any child exits or the user interrupts.
    /// Suitable for `systemd`-style or Docker `CMD` invocation.
    Foreground,
    /// Fork a hidden `__supervise` child that spawns and owns the stack, then
    /// return after it acknowledges readiness. The original process exits
    /// after printing a one-line summary.
    Detached,
}

/// Informational handle returned by [`start_from_plan`] once the stack is ready.
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
    state_dir: PathBuf,
    reaper_launcher: ReaperLauncher,
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
    /// Component names, in startup order, used to fence generation cleanup.
    component_names: Vec<String>,
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
        component_names: Vec<String>,
    ) -> Self {
        Self {
            state: StartupState::Building(Vec::new()),
            state_dir: state_dir.to_path_buf(),
            state_lease,
            transaction: Some(transaction),
            component_names,
        }
    }

    /// Append one owned component in spawn order to [`StartupState::Building`].
    ///
    /// # Errors
    ///
    /// Returns an error without changing state if startup has already finished.
    fn record(&mut self, component: OwnedComponent) -> Result<()> {
        match &mut self.state {
            StartupState::Building(components) => {
                components.push(component);
                Ok(())
            }
            StartupState::Finished => Err(StackError::Platform(
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
    fn exited_component(&mut self) -> Result<Option<(String, ExitStatus)>> {
        match &mut self.state {
            StartupState::Building(components) => {
                for component in components {
                    if let Some(exit) = Self::poll_exit(component)? {
                        return Ok(Some(exit));
                    }
                }
                Ok(None)
            }
            StartupState::Finished => Err(StackError::Platform(
                "component readiness checked without owned startup processes".into(),
            )),
        }
    }

    /// Poll one owned leader while preserving its broader termination capability.
    fn poll_exit(component: &mut OwnedComponent) -> Result<Option<(String, ExitStatus)>> {
        Ok(component
            .try_wait()
            .map_err(StackError::Io)?
            .map(|status| (component.name().as_str().to_string(), status)))
    }

    /// Transfer complete ownership and state capabilities into a [`RunningStack`].
    ///
    /// # Errors
    ///
    /// Returns an error and leaves rollback armed if startup has already
    /// finished.
    fn finish(mut self) -> Result<RunningStack> {
        match std::mem::replace(&mut self.state, StartupState::Finished) {
            StartupState::Building(components) => Ok(RunningStack::from_components(
                components,
                self.state_dir.clone(),
                self.state_lease,
                self.transaction.take(),
            )),
            StartupState::Finished => Err(StackError::Platform(
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
        let component_names: Vec<&str> = self.component_names.iter().map(String::as_str).collect();
        if components.is_empty() {
            remove_startup_state(
                &self.state_dir,
                &component_names,
                self.state_lease,
                self.transaction.as_ref(),
            );
            return;
        }
        rollback_startup_components(
            components,
            &self.state_dir,
            &component_names,
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
    component_names: &[&str],
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

    let deadline = Instant::now() + Duration::from_secs(2);
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
            remove_startup_state(state_dir, component_names, state_lease, transaction);
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
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl RunningStack {
    /// Construct the sole running owner from complete process and state capabilities.
    ///
    /// The startup [`StateTransaction`] remains held until
    /// [`RunningStack::mark_ready`] commits complete-state publication.
    pub(crate) fn from_components(
        components: Vec<OwnedComponent>,
        state_dir: PathBuf,
        state_lease: StateLease,
        startup_transaction: Option<StateTransaction>,
    ) -> Self {
        Self::from_components_with_reaper_launcher(
            components,
            state_dir,
            state_lease,
            startup_transaction,
            launch_reaper,
        )
    }

    /// Construct the sole running owner with a caller-supplied reaper launcher.
    pub(crate) fn from_components_with_reaper_launcher(
        components: Vec<OwnedComponent>,
        state_dir: PathBuf,
        state_lease: StateLease,
        startup_transaction: Option<StateTransaction>,
        reaper_launcher: ReaperLauncher,
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
                state_dir,
                reaper_launcher,
                state_lease,
                startup_transaction,
            })),
        }
    }

    /// Borrow capabilities only while state is [`RunningStackState::Owned`].
    ///
    /// # Errors
    ///
    /// Returns [`StackError::Platform`] after ownership has been consumed.
    fn owned_mut(&mut self) -> Result<&mut OwnedStack> {
        match &mut self.state {
            RunningStackState::Owned(owned) => Ok(owned),
            RunningStackState::Stopped => Err(StackError::Platform(
                "stack process ownership is no longer available".into(),
            )),
        }
    }

    /// Commit complete-state publication by releasing startup serialization.
    ///
    /// Process and cleanup capabilities remain in [`OwnedStack`]; this transition
    /// only allows other processes to snapshot the now-complete runtime state.
    fn mark_ready(&mut self) -> Result<()> {
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
    pub fn shutdown(&mut self, timeout: Duration) -> Result<crate::stop::StopOutcome> {
        let RunningStackState::Owned(owned) = &mut self.state else {
            return Ok(crate::stop::StopOutcome { forced: false });
        };
        // A detached attachment failure may tear down before publishing ready.
        // Release startup serialization before the owned stop reacquires it.
        owned.startup_transaction = None;
        let state_dir = &owned.state_dir;
        let state_lease = owned.state_lease;
        let result =
            crate::stop::stop_owned(state_dir, timeout, &mut owned.components, state_lease);
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
            return match collect_in_background_with(owned.components, owned.reaper_launcher) {
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
/// listening. `component_names` lists the components in startup order and is
/// used to claim the stack lock and reap stale runtime state; `build_plan`
/// resolves the full [`ComponentSpec`] plan and is invoked **after** the lock is
/// claimed, so an already-running stack is reported before the caller's
/// (possibly failing) plan resolution runs. The caller must eventually call
/// [`RunningStack::shutdown`] to tear the stack down and collect its children.
///
/// Used by the firma wrapper `spawn_stack` and as the first step of
/// [`start_from_plan`].
///
/// # Errors
///
/// Returns state-directory, lock, plan-resolution, spawn, or readiness errors.
/// On failure after children have been spawned, this function tears them down.
/// Runtime state is retained when target disappearance cannot be confirmed so
/// callers can retry cleanup.
pub fn spawn_stack_from_plan(
    component_names: &[&str],
    build_plan: impl FnOnce() -> Result<Vec<ComponentSpec>>,
    exe: Option<&Path>,
    state_dir: &Path,
) -> Result<RunningStack> {
    spawn_stack_from_plan_with_phase(
        component_names,
        build_plan,
        exe,
        state_dir,
        true,
        StackGeneration::new(),
        None,
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
fn spawn_stack_from_plan_with_phase(
    component_names: &[&str],
    build_plan: impl FnOnce() -> Result<Vec<ComponentSpec>>,
    exe: Option<&Path>,
    state_dir: &Path,
    publish_ready: bool,
    generation: StackGeneration,
    stop_signal: Option<&StopSignal>,
) -> Result<RunningStack> {
    info!(state_dir = %state_dir.display(), "spawning firma stack");
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    let transaction = StateTransaction::acquire(state_dir)?;
    debug!("acquiring stack lock");
    let state_lease = acquire_lock(state_dir, &transaction, generation, component_names)?;
    let owned_names: Vec<String> = component_names
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    let mut startup = StartupGuard::new(state_dir, state_lease, transaction, owned_names);
    debug!("reaping stale pidfiles");
    reap_stale(state_dir, component_names)?;

    // The plan is resolved after the lock is claimed so that an already-running
    // stack is reported before any (possibly failing) plan resolution runs.
    let plan = build_plan()?;
    match spawn_stack_inner(plan, exe, state_dir, &mut startup, stop_signal) {
        Ok(()) => {
            let mut stack = startup.finish()?;
            if publish_ready {
                stack.mark_ready()?;
            }
            let handle = stack.handle();
            info!(components = ?handle.component_pids, "firma stack ready");
            Ok(stack)
        }
        Err(error) => {
            debug!(%error, "spawn failed; startup guard will roll back");
            Err(error)
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
    plan: Vec<ComponentSpec>,
    exe: Option<&Path>,
    state_dir: &Path,
    startup: &mut StartupGuard,
    stop_signal: Option<&StopSignal>,
) -> Result<()> {
    let group = SystemPlatform::new_group()?;
    SystemPlatform::arm_group_termination(&group)?;

    for spec in plan {
        let ComponentSpec {
            name,
            args,
            readiness_addr: addr,
        } = spec;
        debug!(exe = ?exe, component = %name.as_str(), args = ?args, "spawning component");
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let component = spawn_into_group(&group, state_dir, name.clone(), &arg_refs, exe)?;
        let pid = component.leader_pid();
        startup.record(component)?;
        info!(component = %name.as_str(), pid = %pid, "component spawned");
        std::fs::write(state_dir.join(name.listen_file_name()), format!("{addr}\n"))?;
        debug!(component = %name.as_str(), addr = %addr, "waiting for component TCP listen");
        wait_for_tcp(
            name.as_str(),
            addr,
            Duration::from_mins(1),
            stop_signal,
            || startup.exited_component(),
        )?;
        // A connectable sidecar already implies CA readiness: the sidecar
        // generates its CA material before opening the interceptor port, so
        // readiness is a single signal with no separate CA-material probe.
        info!(component = %name.as_str(), addr = %addr, "component listening");
    }

    // The Group goes out of scope at the end of this function. On Unix that is
    // a no-op because children sit in their own process groups. On Windows,
    // each OwnedComponent retains a duplicate of the shared Job Object handle,
    // so closing the original handle does not terminate the ready stack.
    let _ = group;

    Ok(())
}

/// Start a stack made of the named components.
///
/// `component_names` lists the components in startup order. `build_plan`
/// resolves the full [`ComponentSpec`] plan for foreground startup and is only
/// invoked after the lock is claimed. `exe` is the executable used to launch
/// each component (and, in detached mode, the supervisor). `config_file` is the
/// configuration path re-passed to the detached supervisor child so it can
/// re-derive the same plan; it is unused in foreground mode, where the detached
/// supervisor is never spawned.
///
/// # Errors
///
/// Returns state directory, plan-resolution, spawn, readiness, or detach errors.
/// On failure after children have been spawned, this function tears them down.
/// Runtime state is retained when hard termination fails so callers can retry
/// cleanup.
pub fn start_from_plan(
    component_names: &[&str],
    build_plan: impl FnOnce() -> Result<Vec<ComponentSpec>>,
    exe: Option<&Path>,
    config_file: &Path,
    state_dir: &Path,
    mode: StartMode,
) -> Result<StackHandle> {
    match mode {
        StartMode::Foreground => start_foreground(component_names, build_plan, exe, state_dir),
        StartMode::Detached => start_detached(component_names, exe, config_file, state_dir),
    }
}

/// Spawn, supervise, and tear down components in the calling process.
///
/// [`StopSignal`] is installed before startup and reused for supervision, so a
/// termination request during readiness triggers [`StartupGuard`] rollback.
fn start_foreground(
    component_names: &[&str],
    build_plan: impl FnOnce() -> Result<Vec<ComponentSpec>>,
    exe: Option<&Path>,
    state_dir: &Path,
) -> Result<StackHandle> {
    let stop_signal = StopSignal::install()?;
    let mut stack = spawn_stack_from_plan_with_phase(
        component_names,
        build_plan,
        exe,
        state_dir,
        true,
        StackGeneration::new(),
        Some(&stop_signal),
    )?;
    let handle = stack.handle();
    info!("entering foreground supervisor loop");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit_with(&stop_signal, &mut owned.components)
    };
    info!("foreground supervisor exiting; tearing down stack");
    let teardown_result = stack.shutdown(Duration::from_secs(10));
    if let Err(error) = supervision_result {
        return Err(with_rollback(error, teardown_result));
    }
    teardown_result?;
    Ok(handle)
}

/// Launch a generation-bound supervisor that becomes the component owner.
///
/// The handoff protocol is defined by [`LauncherAttachmentState`]. The launcher
/// retains the supervisor child handle through both phases and uses
/// [`rollback_detached_start`] on any failure before collection transfer. The
/// launcher never resolves the plan itself: the supervisor child re-derives it
/// from `config_file`. `component_names` (startup order) drives handle
/// reconstruction and rollback so both enumerate exactly the components the
/// supervisor will own.
fn start_detached(
    component_names: &[&str],
    exe: Option<&Path>,
    config_file: &Path,
    state_dir: &Path,
) -> Result<StackHandle> {
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    let generation = StackGeneration::new();
    info!("forking detached supervisor owner");
    let mut supervisor = crate::detach::spawn_supervisor(state_dir, config_file, exe, generation)?;
    if let Err(error) =
        wait_for_supervisor_attachment(state_dir, &mut supervisor, Duration::from_mins(4))
    {
        terminate_detached_supervisor(&mut supervisor);
        let rollback = rollback_detached_start(state_dir, component_names, generation);
        return Err(with_rollback(error, rollback));
    }
    let handle = match read_stack_handle(state_dir, component_names) {
        Ok(handle) => handle,
        Err(error) => {
            terminate_detached_supervisor(&mut supervisor);
            let rollback = rollback_detached_start(state_dir, component_names, generation);
            return Err(with_rollback(error, rollback));
        }
    };
    if collect_child_in_background(supervisor).is_none() {
        let error = StackError::Platform("could not start detached supervisor collector".into());
        let rollback = rollback_detached_start(state_dir, component_names, generation);
        return Err(with_rollback(error, rollback));
    }
    Ok(handle)
}

/// Roll back only state matching this launcher's [`StackGeneration`].
fn rollback_detached_start(
    state_dir: &Path,
    component_names: &[&str],
    generation: StackGeneration,
) -> Result<()> {
    crate::stop::stop_generation(
        state_dir,
        Duration::from_secs(10),
        component_names,
        generation,
    )
    .map(|_| ())
}

/// Terminate and make a bounded collection attempt for the supervisor child.
fn terminate_detached_supervisor(supervisor: &mut std::process::Child) {
    let target =
        TerminationTarget::for_leader(firma_runtime_state::ChildExt::process_id(supervisor));
    let _ = target.signal_hard();
    let _ = supervisor.kill();
    let _ = collect_child_until(supervisor, Instant::now() + Duration::from_secs(2));
}

/// Reconstruct an informational [`StackHandle`] after supervisor-owned startup.
///
/// The caller supplies the component names in startup order; this does not grant
/// component collection, termination, or cleanup authority.
fn read_stack_handle(state_dir: &Path, names: &[&str]) -> Result<StackHandle> {
    let mut component_pids = Vec::with_capacity(names.len());
    for name in names {
        let pid = pidfile::read(&state_dir.join(format!("{name}.pid")))?
            .ok_or_else(|| StackError::Platform(format!("{name}.pid missing after startup")))?;
        component_pids.push(((*name).to_string(), pid));
    }
    Ok(StackHandle { component_pids })
}

/// Remove rollback-owned state through [`crate::stop::cleanup_generation`].
///
/// A missing [`StateTransaction`] cannot safely authorize deletion, so this
/// destructor path retains state for a later [`crate::stop::stop_components()`].
fn remove_startup_state(
    state_dir: &Path,
    component_names: &[&str],
    state_lease: StateLease,
    transaction: Option<&StateTransaction>,
) {
    let Some(transaction) = transaction else {
        debug!("startup rollback lost state transaction; retaining runtime state");
        return;
    };
    if let Err(error) =
        crate::stop::cleanup_generation(state_dir, component_names, Some(state_lease), transaction)
    {
        debug!(%error, "startup rollback retained runtime state");
    }
}

/// Preserve the initiating failure together with any required rollback failure.
fn with_rollback<T>(operation: StackError, rollback: Result<T>) -> StackError {
    match rollback {
        Ok(_) => operation,
        Err(rollback) => StackError::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        },
    }
}

/// Spawn and own a detached stack for a launcher-assigned generation.
///
/// [`StopSignal`] is installed before component readiness and reused by
/// [`supervise_running_stack_with_signal`] for the two-phase handoff and
/// supervision.
///
/// # Errors
///
/// Returns startup, readiness, supervision, termination, or cleanup errors.
#[doc(hidden)]
pub fn supervise_owned_generation_from_plan(
    component_names: &[&str],
    build_plan: impl FnOnce() -> Result<Vec<ComponentSpec>>,
    exe: Option<&Path>,
    state_dir: &Path,
    generation: StackGeneration,
) -> Result<()> {
    let stop_signal = StopSignal::install()?;
    let stack = spawn_stack_from_plan_with_phase(
        component_names,
        build_plan,
        exe,
        state_dir,
        false,
        generation,
        Some(&stop_signal),
    )?;
    supervise_running_stack_with_signal(stack, state_dir, Duration::from_secs(10), &stop_signal)
}

/// Supervise an already-owned stack after installing [`StopSignal`].
#[cfg(feature = "test-support")]
pub(crate) fn supervise_running_stack(
    mut stack: RunningStack,
    state_dir: &Path,
    timeout: Duration,
) -> Result<()> {
    let stop_signal = match StopSignal::install() {
        Ok(stop_signal) => stop_signal,
        Err(error) => {
            let rollback = stack.shutdown(Duration::from_secs(10));
            return Err(with_rollback(error, rollback));
        }
    };
    supervise_running_stack_with_signal(stack, state_dir, timeout, &stop_signal)
}

/// Execute the supervisor side of [`LauncherAttachmentState`] and own teardown.
///
/// Attachment state is written while the startup [`StateTransaction`] remains
/// held. Any publication or acknowledgement failure invokes
/// [`RunningStack::shutdown`] before returning.
fn supervise_running_stack_with_signal(
    mut stack: RunningStack,
    state_dir: &Path,
    timeout: Duration,
    stop_signal: &StopSignal,
) -> Result<()> {
    let supervisor_pid = UserProcessId::new(std::process::id()).ok_or_else(|| {
        StackError::Platform("current process returned invalid process id".into())
    })?;
    let attachment_result = (|| {
        let ready_path = supervisor_ready_path(state_dir, supervisor_pid);
        pidfile::write(&state_dir.join("stack.pid"), supervisor_pid)?;
        pidfile::write(&ready_path, supervisor_pid)?;
        wait_for_launcher_ack(&ready_path, stop_signal, Duration::from_mins(4))?;
        pidfile::write(
            &supervisor_attached_path(state_dir, supervisor_pid),
            supervisor_pid,
        )?;
        stack.mark_ready()?;
        Ok(())
    })();
    if let Err(error) = attachment_result {
        let _ = stack.mark_ready();
        let rollback = stack.shutdown(Duration::from_secs(10));
        return Err(with_rollback(error, rollback));
    }

    info!(supervisor_pid = %supervisor_pid, state_dir = %state_dir.display(), "detached supervisor owns ready stack");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit_with(stop_signal, &mut owned.components)
    };
    info!("detached supervisor tearing down owned components");
    let teardown_result = stack.shutdown(timeout);
    if let Err(error) = supervision_result {
        return Err(with_rollback(error, teardown_result));
    }
    teardown_result.map(|_| ())
}

/// Execute the launcher side of [`LauncherAttachmentState`].
///
/// Child exit, identity mismatch, or timeout leaves the launcher responsible for
/// terminating and collecting the supervisor.
pub(crate) fn wait_for_supervisor_attachment(
    state_dir: &Path,
    supervisor: &mut std::process::Child,
    timeout: Duration,
) -> Result<()> {
    let expected_pid = UserProcessId::new(supervisor.id()).ok_or_else(|| {
        StackError::Platform("detached supervisor returned invalid process id".into())
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
                return Err(StackError::Platform(format!(
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
                return Err(StackError::Platform(format!(
                    "detached supervisor attachment belongs to pid {attached_pid}, expected {expected_pid}"
                )));
            }
            pidfile::remove(&attached_path)?;
            if supervisor.try_wait()?.is_some() {
                return Err(StackError::Platform(
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
            return Err(StackError::Platform(format!(
                "detached supervisor exited {phase}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(StackError::Readiness {
                component: "detached supervisor".into(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
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
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while ready_path.try_exists()? {
        if stop_signal.requested() {
            return Err(StackError::Platform(
                "termination requested before launcher attachment".into(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(StackError::Readiness {
                component: "detached launcher acknowledgement".into(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Spawn one named component into the group with caller-supplied arguments.
fn spawn_into_group(
    group: &crate::platform::Group,
    state_dir: &Path,
    name: ComponentName,
    args: &[&str],
    exe: Option<&Path>,
) -> Result<OwnedComponent> {
    spawn_component(
        group,
        &SpawnRequest {
            name,
            args,
            state_dir,
            exe,
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
    component_names: &[&str],
) -> Result<StateLease> {
    let lock = state_dir.join("stack.lock");
    loop {
        if !is_stack_stale(state_dir, component_names)? {
            return Err(StackError::AlreadyRunning { path: lock });
        }
        if let Some(state_lease) = StateLease::try_claim(state_dir, generation)? {
            return Ok(state_lease);
        }
        std::fs::remove_file(&lock)?;
    }
}

/// Prove that no persisted supervisor or component target remains live.
fn is_stack_stale(state_dir: &Path, component_names: &[&str]) -> Result<bool> {
    if let Some(pid) = pidfile::read(&state_dir.join("stack.pid"))?
        && process_exists(pid)?
    {
        return Ok(false);
    }
    for name in component_names {
        if let Some(id) = pidfile::read(&state_dir.join(format!("{name}.pid")))?
            && TerminationTarget::from_stored_id(id).exists()?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Remove process records only after their targets are proven absent.
fn reap_stale(state_dir: &Path, component_names: &[&str]) -> Result<()> {
    for name in component_names {
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

/// Map a supervisor liveness probe into the stack error contract.
fn process_exists(pid: UserProcessId) -> Result<bool> {
    pid.process_exists().map_err(StackError::Io)
}
