//! `start` and `supervise` entry points.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::component::{ComponentRole, OwnedComponent};
use crate::config::StackConfig;
use crate::error::{Result, StackError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::{FirmaToml, wait_for_ca_material, wait_for_tcp};
use crate::spawn::{SpawnRequest, spawn_component};
use crate::state_lease::{StackGeneration, StateLease, StateTransaction};
use crate::supervisor::{
    StopSignal, block_until_owned_exit, block_until_owned_exit_with, collect_child_in_background,
    collect_child_until, collect_in_background,
};
use firma_runtime_state::{UserProcessId, pidfile};

/// Mode in which [`start`] manages the stack after readiness.
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

/// Informational handle returned by [`start`] once the stack is ready.
///
/// The handle is informational only: it does not own the children's lifecycle
/// (runtime-state files on disk are the source of truth). Callers tear the stack down
/// via [`crate::stop()`].
#[derive(Clone, Copy)]
pub struct StackHandle {
    /// PID of the authority component.
    authority_pid: UserProcessId,
    /// PID of the sidecar component.
    sidecar_pid: UserProcessId,
}

/// An in-process stack whose component child handles are owned by the caller.
///
/// Call [`RunningStack::shutdown`] for an orderly teardown. Successful shutdown
/// disarms the stored termination targets, so repeated calls are no-ops.
/// Dropping this value does not terminate the stack; it transfers the child
/// handles to a background collector so later exits cannot remain zombies.
pub struct RunningStack {
    handle: StackHandle,
    state: RunningStackState,
}

/// Process capabilities and state lease held while this process owns the stack.
struct OwnedStack {
    authority: OwnedComponent,
    sidecar: OwnedComponent,
    state_dir: PathBuf,
    state_lease: StateLease,
    startup_transaction: Option<StateTransaction>,
}

/// Ownership states for an in-process stack.
///
/// Only `Owned` authorizes process collection, termination, and state cleanup.
/// A successful shutdown or ownership transfer moves permanently to `Stopped`.
enum RunningStackState {
    /// This process may supervise, terminate, collect, and clean up the stack.
    Owned(Box<OwnedStack>),
    /// Process authority has been consumed by shutdown or transferred away.
    Stopped,
}

/// Rollback guard for the ordered component-startup state machine.
///
/// Dropping an unfinished guard terminates and collects exactly the components
/// represented by its current state, then removes this generation's state.
struct StartupGuard {
    state: StartupState,
    state_dir: PathBuf,
    state_lease: StateLease,
    transaction: Option<StateTransaction>,
}

/// Valid ownership states while the Authority and Sidecar are starting.
///
/// The enum makes impossible combinations, such as a Sidecar without an owned
/// Authority or a finished guard that still owns children, unrepresentable.
enum StartupState {
    /// The generation is claimed, but no component has been spawned.
    Empty,
    /// The Authority was spawned and remains exclusively owned by the guard.
    AuthorityStarted { authority: OwnedComponent },
    /// Both components were spawned and remain exclusively owned by the guard.
    ComponentsStarted {
        authority: OwnedComponent,
        sidecar: OwnedComponent,
    },
    /// Ownership was transferred to `RunningStack`; rollback is disarmed.
    Finished,
}

/// Launcher states in the two-phase detached-supervisor handoff.
enum LauncherAttachmentState {
    /// Waiting for the supervisor to publish component readiness.
    AwaitingReadiness,
    /// Readiness was acknowledged; waiting for supervisor confirmation.
    AwaitingConfirmation,
}

impl StartupGuard {
    /// Begin an empty startup generation with an atomically acquired lease.
    fn new(state_dir: &Path, state_lease: StateLease, transaction: StateTransaction) -> Self {
        Self {
            state: StartupState::Empty,
            state_dir: state_dir.to_path_buf(),
            state_lease,
            transaction: Some(transaction),
        }
    }

    /// Transition from `Empty` to `AuthorityStarted`.
    ///
    /// # Errors
    ///
    /// Returns an error without changing state if Authority ownership was
    /// already recorded or startup has finished.
    fn record_authority(&mut self, authority: OwnedComponent) -> Result<()> {
        match std::mem::replace(&mut self.state, StartupState::Finished) {
            StartupState::Empty => {
                self.state = StartupState::AuthorityStarted { authority };
                Ok(())
            }
            state => {
                self.state = state;
                Err(StackError::Platform(
                    "authority child recorded outside empty startup state".into(),
                ))
            }
        }
    }

    /// Transition from `AuthorityStarted` to `ComponentsStarted`.
    ///
    /// # Errors
    ///
    /// Returns an error without changing state if no Authority is owned or the
    /// Sidecar was already recorded.
    fn record_sidecar(&mut self, sidecar: OwnedComponent) -> Result<()> {
        match std::mem::replace(&mut self.state, StartupState::Finished) {
            StartupState::AuthorityStarted { authority } => {
                self.state = StartupState::ComponentsStarted { authority, sidecar };
                Ok(())
            }
            state => {
                self.state = state;
                Err(StackError::Platform(
                    "sidecar child recorded before authority ownership".into(),
                ))
            }
        }
    }

    /// Transfer complete component ownership into a running stack.
    ///
    /// # Errors
    ///
    /// Returns an error and leaves rollback armed unless both components are
    /// present in startup order.
    fn finish(mut self) -> Result<RunningStack> {
        match std::mem::replace(&mut self.state, StartupState::Finished) {
            StartupState::ComponentsStarted { authority, sidecar } => {
                Ok(RunningStack::from_components(
                    authority,
                    sidecar,
                    self.state_dir.clone(),
                    self.state_lease,
                    self.transaction.take(),
                ))
            }
            state => {
                self.state = state;
                Err(StackError::Platform(
                    "both component children must be owned before startup finishes".into(),
                ))
            }
        }
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        let state = std::mem::replace(&mut self.state, StartupState::Finished);
        let components = match state {
            StartupState::Empty => {
                remove_startup_state(&self.state_dir, self.state_lease, self.transaction.as_ref());
                return;
            }
            StartupState::AuthorityStarted { authority } => vec![authority],
            StartupState::ComponentsStarted { authority, sidecar } => {
                vec![authority, sidecar]
            }
            StartupState::Finished => return,
        };
        rollback_startup_components(
            components,
            &self.state_dir,
            self.state_lease,
            self.transaction.as_ref(),
        );
    }
}

fn rollback_startup_components(
    mut components: Vec<OwnedComponent>,
    state_dir: &Path,
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
            remove_startup_state(state_dir, state_lease, transaction);
            return;
        }
        if probe_failed || Instant::now() >= deadline {
            debug!("startup rollback retained runtime state for a later cleanup attempt");
            if let Err(error) = collect_in_background(components) {
                debug!(error = %error.source(), "could not start rollback component reaper");
                error.terminate_and_collect(Duration::from_secs(2));
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl RunningStack {
    /// Construct the sole running owner from complete component capabilities.
    pub(crate) fn from_components(
        authority: OwnedComponent,
        sidecar: OwnedComponent,
        state_dir: PathBuf,
        state_lease: StateLease,
        startup_transaction: Option<StateTransaction>,
    ) -> Self {
        let handle = StackHandle {
            authority_pid: authority.leader_pid(),
            sidecar_pid: sidecar.leader_pid(),
        };
        Self {
            handle,
            state: RunningStackState::Owned(Box::new(OwnedStack {
                authority,
                sidecar,
                state_dir,
                state_lease,
                startup_transaction,
            })),
        }
    }

    /// Borrow the process capabilities while the stack remains owned.
    fn owned_mut(&mut self) -> Result<&mut OwnedStack> {
        match &mut self.state {
            RunningStackState::Owned(owned) => Ok(owned),
            RunningStackState::Stopped => Err(StackError::Platform(
                "stack process ownership is no longer available".into(),
            )),
        }
    }

    /// Release exclusive state mutation after detached attachment is published.
    fn mark_ready(&mut self) -> Result<()> {
        let owned = self.owned_mut()?;
        owned.startup_transaction = None;
        Ok(())
    }

    /// Return an informational handle containing the component process IDs.
    #[must_use]
    fn handle(&self) -> StackHandle {
        self.handle
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
        let result = crate::stop::stop_owned(
            &owned.state_dir,
            timeout,
            &mut owned.authority,
            &mut owned.sidecar,
            owned.state_lease,
        );
        if result.is_ok() {
            let _ = owned.sidecar.wait();
            let _ = owned.authority.wait();
            self.state = RunningStackState::Stopped;
        }
        result
    }

    /// Transfer child collection to a background owner and disarm this value.
    fn transfer_to_observer(&mut self) -> bool {
        let state = std::mem::replace(&mut self.state, RunningStackState::Stopped);
        if let RunningStackState::Owned(owned) = state {
            let owned = *owned;
            return match collect_in_background(vec![owned.authority, owned.sidecar]) {
                Ok(_) => true,
                Err(error) => {
                    debug!(error = %error.source(), "could not transfer components to background reaper");
                    error.terminate_and_collect(Duration::from_secs(2));
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
/// Returns ownership of the component child handles once both components are
/// listening and the sidecar CA material is on disk. The caller must eventually
/// call [`RunningStack::shutdown`] to tear the stack down and collect its
/// children.
///
/// Used by `firma-demo-tui` and as the first step of [`start`].
///
/// # Errors
///
/// Returns state-directory, lock, spawn, or readiness errors. On failure
/// after children have been spawned, this function tears them down. Runtime
/// state is retained when target disappearance cannot be confirmed so callers
/// can retry cleanup.
pub fn spawn_stack(cfg: &StackConfig, state_dir: &Path) -> Result<RunningStack> {
    spawn_stack_with_phase(cfg, state_dir, true, StackGeneration::new())
}

/// Spawn a stack while optionally deferring complete-state publication.
fn spawn_stack_with_phase(
    cfg: &StackConfig,
    state_dir: &Path,
    publish_ready: bool,
    generation: StackGeneration,
) -> Result<RunningStack> {
    info!(state_dir = %state_dir.display(), "spawning firma stack");
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    let transaction = StateTransaction::acquire(state_dir)?;
    debug!("acquiring stack lock");
    let state_lease = acquire_lock(state_dir, &transaction, generation)?;
    let mut startup = StartupGuard::new(state_dir, state_lease, transaction);
    debug!("reaping stale pidfiles");
    reap_stale(state_dir)?;

    match spawn_stack_inner(cfg, state_dir, &mut startup) {
        Ok(()) => {
            let mut stack = startup.finish()?;
            if publish_ready {
                stack.mark_ready()?;
            }
            let handle = stack.handle();
            info!(
                authority_pid = %handle.authority_pid,
                sidecar_pid = %handle.sidecar_pid,
                "firma stack ready"
            );
            Ok(stack)
        }
        Err(error) => {
            debug!(%error, "spawn failed; startup guard will roll back");
            Err(error)
        }
    }
}

fn spawn_stack_inner(
    cfg: &StackConfig,
    state_dir: &Path,
    startup: &mut StartupGuard,
) -> Result<()> {
    let group = SystemPlatform::new_group()?;
    SystemPlatform::arm_group_termination(&group)?;
    let exe = cfg.firma_bin.as_deref();
    // Parse the unified firma.toml once; the probes below share it.
    let config = FirmaToml::read(&cfg.config_file)?;
    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning authority");
    let auth = spawn_with_config(
        &group,
        state_dir,
        ComponentRole::Authority,
        &cfg.config_file,
        exe,
    )?;
    let authority_pid = auth.leader_pid();
    startup.record_authority(auth)?;
    info!(pid = %authority_pid, "authority spawned");
    let auth_addr = config.authority_listen_addr()?;
    std::fs::write(
        state_dir.join(ComponentRole::Authority.listen_file_name()),
        format!("{auth_addr}\n"),
    )?;
    debug!(addr = %auth_addr, "waiting for authority TCP listen");
    wait_for_tcp("authority", auth_addr, Duration::from_mins(1))?;
    info!(addr = %auth_addr, "authority listening");

    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning sidecar");
    let side = spawn_with_config(
        &group,
        state_dir,
        ComponentRole::Sidecar,
        &cfg.config_file,
        exe,
    )?;
    let sidecar_pid = side.leader_pid();
    startup.record_sidecar(side)?;
    info!(pid = %sidecar_pid, "sidecar spawned");
    let sidecar = config.sidecar_config()?;
    let side_addr = sidecar.interceptor.listen_addr;
    std::fs::write(
        state_dir.join(ComponentRole::Sidecar.listen_file_name()),
        format!("{side_addr}\n"),
    )?;
    debug!(addr = %side_addr, "waiting for sidecar TCP listen");
    wait_for_tcp("sidecar", side_addr, Duration::from_mins(1))?;
    info!(addr = %side_addr, "sidecar listening");
    // CA material is only written when HTTPS MITM is active. A sidecar with
    // MITM inactive (e.g. an Anthropic-only scaffold) never produces it, so
    // gating readiness on it would spuriously time out daemon startup.
    if sidecar.interceptor.https_mitm.is_active() {
        debug!("waiting for sidecar CA material");
        wait_for_ca_material(
            &state_dir.join("generated-firma-ca"),
            Duration::from_mins(1),
        )?;
        debug!("CA material present");
    } else {
        debug!("sidecar HTTPS MITM inactive; skipping CA material readiness probe");
    }

    // The Group goes out of scope at the end of this function. On Unix that is
    // a no-op because children sit in their own process groups. On Windows,
    // each OwnedComponent retains a duplicate of the shared Job Object handle,
    // so closing the original handle does not terminate the ready stack.
    let _ = group;

    Ok(())
}

/// Start the authority and sidecar stack.
///
/// # Errors
///
/// Returns state directory, spawn, readiness, or detach errors. On failure
/// after children have been spawned, this function tears them down. Runtime
/// state is retained when hard termination fails so callers can retry cleanup.
pub fn start(cfg: &StackConfig, state_dir: &Path, mode: StartMode) -> Result<StackHandle> {
    match mode {
        StartMode::Foreground => start_foreground(cfg, state_dir),
        StartMode::Detached => start_detached(cfg, state_dir),
    }
}

fn start_foreground(cfg: &StackConfig, state_dir: &Path) -> Result<StackHandle> {
    let mut stack = spawn_stack(cfg, state_dir)?;
    let handle = stack.handle();
    info!("entering foreground supervisor loop");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit(&mut owned.authority, &mut owned.sidecar)
    };
    info!("foreground supervisor exiting; tearing down stack");
    let teardown_result = stack.shutdown(Duration::from_secs(10));
    if let Err(error) = supervision_result {
        return Err(with_rollback(error, teardown_result));
    }
    teardown_result?;
    Ok(handle)
}

fn start_detached(cfg: &StackConfig, state_dir: &Path) -> Result<StackHandle> {
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    let generation = StackGeneration::new();
    info!("forking detached supervisor owner");
    let mut supervisor = crate::detach::spawn_supervisor(state_dir, cfg, generation)?;
    if let Err(error) =
        wait_for_supervisor_attachment(state_dir, &mut supervisor, Duration::from_mins(4))
    {
        terminate_detached_supervisor(&mut supervisor);
        let rollback = rollback_detached_start(state_dir, generation);
        return Err(with_rollback(error, rollback));
    }
    let handle = match read_stack_handle(state_dir) {
        Ok(handle) => handle,
        Err(error) => {
            terminate_detached_supervisor(&mut supervisor);
            let rollback = rollback_detached_start(state_dir, generation);
            return Err(with_rollback(error, rollback));
        }
    };
    if collect_child_in_background(supervisor).is_none() {
        let error = StackError::Platform("could not start detached supervisor collector".into());
        let rollback = rollback_detached_start(state_dir, generation);
        return Err(with_rollback(error, rollback));
    }
    Ok(handle)
}

fn rollback_detached_start(state_dir: &Path, generation: StackGeneration) -> Result<()> {
    crate::stop::stop_generation(state_dir, Duration::from_secs(10), generation).map(|_| ())
}

fn terminate_detached_supervisor(supervisor: &mut std::process::Child) {
    let target =
        TerminationTarget::for_leader(firma_runtime_state::ChildExt::process_id(supervisor));
    let _ = target.signal_hard();
    let _ = supervisor.kill();
    let _ = collect_child_until(supervisor, Instant::now() + Duration::from_secs(2));
}

fn read_stack_handle(state_dir: &Path) -> Result<StackHandle> {
    let authority_pid = pidfile::read(&state_dir.join("authority.pid"))?
        .ok_or_else(|| StackError::Platform("authority.pid missing after startup".into()))?;
    let sidecar_pid = pidfile::read(&state_dir.join("sidecar.pid"))?
        .ok_or_else(|| StackError::Platform("sidecar.pid missing after startup".into()))?;
    Ok(StackHandle {
        authority_pid,
        sidecar_pid,
    })
}

fn remove_startup_state(
    state_dir: &Path,
    state_lease: StateLease,
    transaction: Option<&StateTransaction>,
) {
    let Some(transaction) = transaction else {
        debug!("startup rollback lost state transaction; retaining runtime state");
        return;
    };
    if let Err(error) = crate::stop::cleanup_generation(state_dir, Some(state_lease), transaction) {
        debug!(%error, "startup rollback retained runtime state");
    }
}

fn with_rollback<T>(operation: StackError, rollback: Result<T>) -> StackError {
    match rollback {
        Ok(_) => operation,
        Err(rollback) => StackError::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        },
    }
}

/// Spawn and own the detached stack, acknowledging readiness to its launcher.
///
/// # Errors
///
/// Returns startup, readiness, supervision, termination, or cleanup errors.
pub fn supervise_owned(cfg: &StackConfig, state_dir: &Path) -> Result<()> {
    supervise_owned_generation(cfg, state_dir, StackGeneration::new())
}

/// Spawn and own a detached stack for a launcher-assigned generation.
///
/// # Errors
///
/// Returns startup, readiness, supervision, termination, or cleanup errors.
pub fn supervise_owned_generation(
    cfg: &StackConfig,
    state_dir: &Path,
    generation: StackGeneration,
) -> Result<()> {
    let stop_signal = StopSignal::install()?;
    let stack = spawn_stack_with_phase(cfg, state_dir, false, generation)?;
    supervise_running_stack_with_signal(stack, state_dir, Duration::from_secs(10), &stop_signal)
}

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

/// Attach and run a stack after its process-wide signal guard is installed.
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
        block_until_owned_exit_with(stop_signal, &mut owned.authority, &mut owned.sidecar)
    };
    info!("detached supervisor tearing down owned components");
    let teardown_result = stack.shutdown(timeout);
    if let Err(error) = supervision_result {
        return Err(with_rollback(error, teardown_result));
    }
    teardown_result.map(|_| ())
}

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

pub(crate) fn supervisor_ready_path(state_dir: &Path, supervisor_pid: UserProcessId) -> PathBuf {
    state_dir.join(format!("stack.{supervisor_pid}.ready"))
}

/// Return the second-phase attachment confirmation scoped to one supervisor.
pub(crate) fn supervisor_attached_path(state_dir: &Path, supervisor_pid: UserProcessId) -> PathBuf {
    state_dir.join(format!("stack.{supervisor_pid}.attached"))
}

/// Wait for the launcher to acknowledge the first handshake phase.
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

fn spawn_with_config(
    group: &crate::platform::Group,
    state_dir: &Path,
    role: ComponentRole,
    cfg_path: &Path,
    exe: Option<&Path>,
) -> Result<OwnedComponent> {
    let cfg_str = cfg_path
        .to_str()
        .ok_or_else(|| StackError::Platform("non-utf8 config path".into()))?;
    let subcmd = vec![role.name(), "--config", cfg_str];
    spawn_component(
        group,
        &SpawnRequest {
            role,
            args: &subcmd,
            state_dir,
            exe,
        },
    )
}

fn acquire_lock(
    state_dir: &Path,
    _transaction: &StateTransaction,
    generation: StackGeneration,
) -> Result<StateLease> {
    let lock = state_dir.join("stack.lock");
    loop {
        if !is_stack_stale(state_dir)? {
            return Err(StackError::AlreadyRunning { path: lock });
        }
        if let Some(state_lease) = StateLease::try_claim(state_dir, generation)? {
            return Ok(state_lease);
        }
        std::fs::remove_file(&lock)?;
    }
}

fn is_stack_stale(state_dir: &Path) -> Result<bool> {
    if let Some(pid) = pidfile::read(&state_dir.join("stack.pid"))?
        && process_exists(pid)?
    {
        return Ok(false);
    }
    for name in ["authority.pid", "sidecar.pid"] {
        if let Some(id) = pidfile::read(&state_dir.join(name))?
            && TerminationTarget::from_stored_id(id).exists()?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reap_stale(state_dir: &Path) -> Result<()> {
    for name in ["authority.pid", "sidecar.pid"] {
        let path = state_dir.join(name);
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

fn process_exists(pid: UserProcessId) -> Result<bool> {
    pid.process_exists().map_err(StackError::Io)
}
