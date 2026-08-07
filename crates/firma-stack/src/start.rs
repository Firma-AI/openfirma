//! Stack startup, ownership, and supervision transitions.
//!
//! [`spawn_stack`] acquires runtime state and returns the sole [`RunningStack`]
//! owner after ordered readiness. [`StartupGuard`] owns every partial startup
//! until [`StartupGuard::finish`] commits that transition; its [`Drop`]
//! implementation rolls back uncommitted [`OwnedComponent`] capabilities.
//! [`start`] retains that owner in foreground mode. In detached mode,
//! [`start_detached`] owns only the supervisor child while [`supervise_owned`]
//! spawns and owns the components, so no component capability crosses a process
//! boundary. Failure paths retain runtime state unless target absence can be
//! proved, allowing [`crate::stop()`] to retry cleanup without losing process
//! authority.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::component::{ComponentRole, OwnedComponent};
use crate::config::StackConfig;
use crate::error::{Result, StackError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::{FirmaToml, wait_for_ca_material, wait_for_tcp};
use crate::spawn::{SpawnRequest, spawn_component};
use crate::supervisor::{
    ReaperLauncher, block_until_owned_exit, collect_child_in_background, collect_child_until,
    collect_in_background, collect_in_background_with, launch_reaper,
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

/// Informational handle returned by [`start`] or [`RunningStack::handle`] once
/// the stack has reached the ready state.
///
/// The handle does not own the children's lifecycle. [`RunningStack`] holds
/// in-process ownership; persisted runtime state supports external observation
/// through [`crate::status()`] and retryable teardown through [`crate::stop()`].
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

/// Component capabilities and runtime-state identity held by a [`RunningStack`].
///
/// Each [`OwnedComponent`] couples direct-child collection with its
/// [`TerminationTarget`]. Keeping both components in this value makes stack
/// ownership exclusive until [`RunningStack::shutdown`] consumes it or
/// [`RunningStack::transfer_to_observer`] transfers collection responsibility.
struct OwnedStack {
    authority: OwnedComponent,
    sidecar: OwnedComponent,
    state_dir: PathBuf,
    reaper_launcher: ReaperLauncher,
    state_owner: Option<UserProcessId>,
}

/// Ownership states for an in-process stack.
///
/// Only [`RunningStackState::Owned`] authorizes process collection, termination,
/// and state cleanup. Successful shutdown or ownership transfer moves
/// permanently to [`RunningStackState::Stopped`], making repeated transitions
/// harmless rather than duplicating authority.
enum RunningStackState {
    /// This process may supervise, terminate, collect, and clean up the stack.
    Owned(Box<OwnedStack>),
    /// Process authority has been consumed by shutdown or transferred away.
    Stopped,
}

/// Rollback guard for the ordered component-startup state machine.
///
/// Every spawned [`OwnedComponent`] is recorded before startup performs another
/// fallible operation. Unless [`StartupGuard::finish`] commits
/// [`StartupState::ComponentsStarted`] to a [`RunningStack`], [`Drop`] delegates
/// rollback to [`rollback_startup_components`]. Runtime state is removed only
/// after every [`TerminationTarget`] is proven absent and every leader is
/// collected; uncertainty preserves the state for a later [`crate::stop()`].
struct StartupGuard {
    state: StartupState,
    state_dir: PathBuf,
}

/// Valid process-ownership phases while the Authority and Sidecar are starting.
///
/// The enum makes invalid startup phases, such as recording the second
/// component before ownership of the first or retaining children after
/// ownership transfer, unrepresentable. [`ComponentRole`] assignment remains in
/// the crate-internal spawn path, so transitions cannot relabel capabilities.
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
    /// Ownership was transferred to [`RunningStack`]; rollback is disarmed.
    Finished,
}

impl StartupGuard {
    /// Begin an armed [`StartupState::Empty`] transaction after lock acquisition.
    fn new(state_dir: &Path) -> Self {
        Self {
            state: StartupState::Empty,
            state_dir: state_dir.to_path_buf(),
        }
    }

    /// Record Authority ownership as [`StartupState::AuthorityStarted`].
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

    /// Add Sidecar ownership as [`StartupState::ComponentsStarted`].
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
            StartupState::ComponentsStarted { authority, sidecar } => Ok(
                RunningStack::from_components(authority, sidecar, self.state_dir.clone()),
            ),
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
    /// Roll back the exact capability set represented by [`StartupState`].
    ///
    /// [`StartupState::Finished`] is the only disarmed state. Destruction cannot
    /// report cleanup errors, so [`rollback_startup_components`] preserves
    /// retryable runtime state when rollback cannot prove completion.
    fn drop(&mut self) {
        let state = std::mem::replace(&mut self.state, StartupState::Finished);
        let components = match state {
            StartupState::Empty => {
                remove_startup_state(&self.state_dir);
                return;
            }
            StartupState::AuthorityStarted { authority } => vec![authority],
            StartupState::ComponentsStarted { authority, sidecar } => {
                vec![authority, sidecar]
            }
            StartupState::Finished => return,
        };
        rollback_startup_components(components, &self.state_dir);
    }
}

/// Terminate and collect an incomplete startup without losing retry evidence.
///
/// All component [`TerminationTarget`] values receive a forced request before
/// bounded collection begins. If target absence or child collection cannot be
/// established, ownership moves to [`collect_in_background`]; reaper startup
/// failure uses [`crate::supervisor::ReaperStartError::terminate_and_collect`].
fn rollback_startup_components(mut components: Vec<OwnedComponent>, state_dir: &Path) {
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
            remove_startup_state(state_dir);
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
    /// Construct the sole running owner from complete component capabilities.
    pub(crate) fn from_components(
        authority: OwnedComponent,
        sidecar: OwnedComponent,
        state_dir: PathBuf,
    ) -> Self {
        Self::from_components_with_reaper_launcher(authority, sidecar, state_dir, launch_reaper)
    }

    /// Construct the sole running owner with a caller-supplied reaper launcher.
    pub(crate) fn from_components_with_reaper_launcher(
        authority: OwnedComponent,
        sidecar: OwnedComponent,
        state_dir: PathBuf,
        reaper_launcher: ReaperLauncher,
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
                reaper_launcher,
                state_owner: None,
            })),
        }
    }

    /// Scope runtime-state cleanup to the owning detached supervisor.
    ///
    /// This identity changes only which published state [`RunningStack::shutdown`]
    /// may remove; [`OwnedComponent`] values remain the process capabilities.
    pub(crate) fn set_state_owner(&mut self, state_owner: UserProcessId) {
        if let RunningStackState::Owned(owned) = &mut self.state {
            owned.state_owner = Some(state_owner);
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
        let result = crate::stop::stop_owned(
            &owned.state_dir,
            timeout,
            &mut owned.authority,
            &mut owned.sidecar,
            owned.state_owner,
        );
        if result.is_ok() {
            let _ = owned.sidecar.wait();
            let _ = owned.authority.wait();
            self.state = RunningStackState::Stopped;
        }
        result
    }

    /// Transfer component collection to a background owner and disarm this value.
    ///
    /// [`collect_in_background`] either accepts every [`OwnedComponent`] or
    /// returns a [`crate::supervisor::ReaperStartError`] that still owns all of
    /// them. Failed transfer therefore terminates and collects synchronously
    /// rather than discarding process capabilities.
    fn transfer_to_observer(&mut self) -> bool {
        let state = std::mem::replace(&mut self.state, RunningStackState::Stopped);
        if let RunningStackState::Owned(owned) = state {
            return match collect_in_background_with(
                vec![owned.authority, owned.sidecar],
                owned.reaper_launcher,
            ) {
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
    info!(state_dir = %state_dir.display(), "spawning firma stack");
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    debug!("acquiring stack lock");
    acquire_lock(state_dir)?;
    debug!("reaping stale pidfiles");
    reap_stale(state_dir)?;

    let mut startup = StartupGuard::new(state_dir);
    match spawn_stack_inner(cfg, state_dir, &mut startup) {
        Ok(()) => {
            let stack = startup.finish()?;
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

/// Perform the ordered, rollback-protected component startup sequence.
///
/// The Authority must be reachable before the Sidecar is spawned, and the
/// Sidecar's TCP endpoint must be reachable before any required CA material is
/// accepted. Each successful [`spawn_with_config`] call transitions
/// [`StartupGuard`] before the next fallible step. These probes establish
/// bounded startup readiness only; ongoing health belongs to supervision.
fn spawn_stack_inner(
    cfg: &StackConfig,
    state_dir: &Path,
    startup: &mut StartupGuard,
) -> Result<()> {
    let group = SystemPlatform::new_group()?;
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

    // The Group goes out of scope at the end of this function. On Unix that
    // is a no-op (children sit in their own pgrp). On Windows, the Drop impl
    // closes the Job Object handle; that is safe because we do NOT set
    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — children survive parent exit.
    let _ = group;

    Ok(())
}

/// Start the authority and sidecar stack.
///
/// [`StartMode::Foreground`] delegates to [`start_foreground`], where this
/// process owns the component capabilities. [`StartMode::Detached`] delegates
/// to [`start_detached`], where the launcher owns only the supervisor child and
/// the supervisor creates and owns the component capabilities.
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

/// Spawn, supervise, and tear down components in the calling process.
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

/// Launch a supervisor that becomes the concrete component owner.
///
/// The launcher retains the supervisor child handle until
/// [`wait_for_supervisor_attachment`] confirms readiness and
/// [`read_stack_handle`] captures informational component identities. Failure
/// before handoff terminates and collects that supervisor, then delegates
/// state-aware component rollback to [`rollback_detached_start`].
fn start_detached(cfg: &StackConfig, state_dir: &Path) -> Result<StackHandle> {
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    info!("forking detached supervisor owner");
    let mut supervisor = crate::detach::spawn_supervisor(state_dir, cfg)?;
    let supervisor_pid = UserProcessId::new(supervisor.id()).ok_or_else(|| {
        StackError::Platform("detached supervisor returned invalid process id".into())
    })?;
    if let Err(error) =
        wait_for_supervisor_attachment(state_dir, &mut supervisor, Duration::from_mins(4))
    {
        terminate_detached_supervisor(&mut supervisor);
        let rollback = rollback_detached_start(
            state_dir,
            supervisor_pid,
            matches!(&error, StackError::Readiness { .. }),
        );
        return Err(with_rollback(error, rollback));
    }
    let handle = match read_stack_handle(state_dir) {
        Ok(handle) => handle,
        Err(error) => {
            terminate_detached_supervisor(&mut supervisor);
            let rollback = rollback_detached_start(state_dir, supervisor_pid, false);
            return Err(with_rollback(error, rollback));
        }
    };
    if collect_child_in_background(supervisor).is_none() {
        let error = StackError::Platform("could not start detached supervisor collector".into());
        let rollback = rollback_detached_start(state_dir, supervisor_pid, false);
        return Err(with_rollback(error, rollback));
    }
    Ok(handle)
}

/// Tear down detached startup only when its supervisor still owns runtime state.
///
/// A missing ownership match is a no-op unless the caller requests forced
/// rollback after readiness timeout. This prevents an old launcher from
/// cleaning state it cannot attribute to its supervisor child.
fn rollback_detached_start(
    state_dir: &Path,
    supervisor_pid: UserProcessId,
    force: bool,
) -> Result<()> {
    let owns_state = pidfile::read(&state_dir.join("stack.pid"))? == Some(supervisor_pid);
    if !force && !owns_state {
        return Ok(());
    }
    crate::stop::stop(state_dir, Duration::from_secs(10)).map(|_| ())
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
/// This does not grant component collection, termination, or cleanup authority.
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

/// Remove rollback-owned runtime state after [`StartupGuard`] proves absence.
///
/// Unlike normal [`crate::stop()`] cleanup, this best-effort destructor path
/// cannot return removal errors.
fn remove_startup_state(state_dir: &Path) {
    for name in [
        "authority.pid",
        "authority.listen",
        "sidecar.pid",
        "sidecar.listen",
        "stack.pid",
        "stack.lock",
    ] {
        let _ = pidfile::remove(&state_dir.join(name));
    }
}

/// Preserve the initiating failure together with any required rollback failure.
///
/// Successful rollback returns the original error unchanged. Failed rollback
/// produces [`StackError::Rollback`] so cleanup failure never obscures why the
/// operation first failed.
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
    let stack = spawn_stack(cfg, state_dir)?;
    supervise_running_stack(stack, state_dir, Duration::from_secs(10))
}

/// Publish attachment, supervise owned components, and guarantee final teardown.
///
/// Publication occurs only after [`RunningStack`] owns both ready components.
/// A publication or supervision failure still invokes [`RunningStack::shutdown`]
/// and preserves both failures through [`with_rollback`].
pub(crate) fn supervise_running_stack(
    mut stack: RunningStack,
    state_dir: &Path,
    timeout: Duration,
) -> Result<()> {
    let supervisor_pid = UserProcessId::new(std::process::id()).ok_or_else(|| {
        StackError::Platform("current process returned invalid process id".into())
    })?;
    stack.set_state_owner(supervisor_pid);
    let attachment_result = pidfile::write(&state_dir.join("stack.pid"), supervisor_pid)
        .and_then(|()| {
            pidfile::write(
                &supervisor_ready_path(state_dir, supervisor_pid),
                supervisor_pid,
            )
        })
        .map_err(StackError::from);
    if let Err(error) = attachment_result {
        let rollback = stack.shutdown(Duration::from_secs(10));
        return Err(with_rollback(error, rollback));
    }

    info!(supervisor_pid = %supervisor_pid, state_dir = %state_dir.display(), "detached supervisor owns ready stack");
    let supervision_result = {
        let owned = stack.owned_mut()?;
        block_until_owned_exit(&mut owned.authority, &mut owned.sidecar)
    };
    info!("detached supervisor tearing down owned components");
    let teardown_result = stack.shutdown(timeout);
    if let Err(error) = supervision_result {
        return Err(with_rollback(error, teardown_result));
    }
    teardown_result.map(|_| ())
}

/// Wait for the detached supervisor to prove attachment before handoff.
///
/// The readiness identity must match the direct child retained by the launcher.
/// Child exit, identity mismatch, or timeout leaves the launcher responsible for
/// terminating and collecting the supervisor.
///
/// # Errors
///
/// Returns runtime-state, child-collection, identity, or readiness errors.
pub(crate) fn wait_for_supervisor_attachment(
    state_dir: &Path,
    supervisor: &mut std::process::Child,
    timeout: Duration,
) -> Result<()> {
    let expected_pid = UserProcessId::new(supervisor.id()).ok_or_else(|| {
        StackError::Platform("detached supervisor returned invalid process id".into())
    })?;
    let ready_path = supervisor_ready_path(state_dir, expected_pid);
    let deadline = Instant::now() + timeout;
    loop {
        if supervisor.try_wait()?.is_some() {
            return Err(StackError::Platform(
                "detached supervisor exited before attaching".into(),
            ));
        }
        if let Some(ready_pid) = pidfile::read(&ready_path)? {
            if ready_pid != expected_pid {
                return Err(StackError::Platform(format!(
                    "detached supervisor readiness belongs to pid {ready_pid}, expected {expected_pid}"
                )));
            }
            pidfile::remove(&ready_path)?;
            if supervisor.try_wait()?.is_some() {
                return Err(StackError::Platform(
                    "detached supervisor exited after acknowledging attachment".into(),
                ));
            }
            return Ok(());
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

/// Return the readiness path scoped to one detached supervisor identity.
///
/// Scoping publication prevents one supervisor attempt from acknowledging or
/// removing another attempt's readiness state. Cleanup authorization remains
/// governed separately by [`RunningStack::set_state_owner`].
pub(crate) fn supervisor_ready_path(state_dir: &Path, supervisor_pid: UserProcessId) -> PathBuf {
    state_dir.join(format!("stack.{supervisor_pid}.ready"))
}

/// Map one [`ComponentRole`] to a unified-config [`SpawnRequest`].
///
/// Centralizing this conversion keeps command selection and runtime-state
/// naming within the closed component identity model.
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

/// Claim startup authority unless live runtime state proves another owner.
///
/// The lock file alone is insufficient evidence: a newly created or existing
/// lock is rejected while [`is_stack_stale`] finds a live supervisor or
/// component [`TerminationTarget`]. Probe errors fail closed rather than
/// authorizing stale-state removal.
fn acquire_lock(state_dir: &Path) -> Result<()> {
    let lock = state_dir.join("stack.lock");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
    {
        Ok(_) if is_stack_stale(state_dir)? => Ok(()),
        Ok(_) => Err(StackError::AlreadyRunning { path: lock }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if is_stack_stale(state_dir)? {
                std::fs::remove_file(&lock)?;
                return acquire_lock(state_dir);
            }
            Err(StackError::AlreadyRunning { path: lock })
        }
        Err(error) => Err(error.into()),
    }
}

/// Return whether no persisted supervisor or component target remains live.
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

/// Remove target files only after their persisted identities prove absent.
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
