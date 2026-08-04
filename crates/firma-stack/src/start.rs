//! `start` and `supervise` entry points.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::config::StackConfig;
use crate::error::{Result, StackError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::{FirmaToml, wait_for_ca_material, wait_for_tcp};
use crate::spawn::{SpawnRequest, spawn_component};
use crate::supervisor::{
    ObservedChildren, block_until_observed_exit, block_until_owned_exit, collect_in_background,
};
use firma_runtime_state::{UserProcessId, pidfile};

/// Mode in which [`start`] manages the stack after readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// Block in the calling thread, forwarding `SIGINT` / `SIGTERM` /
    /// `Ctrl-C` to children until any child exits or the user interrupts.
    /// Suitable for `systemd`-style or Docker `CMD` invocation.
    Foreground,
    /// Fork a hidden `__supervise` child that takes over supervision and
    /// return immediately. The original process exits after printing a
    /// one-line summary; the supervisor stays attached to the children.
    Detached,
}

/// Informational handle returned by [`start`] or [`RunningStack::handle`] once
/// the stack has reached the ready state.
///
/// The handle is informational only: it does not own the children's lifecycle
/// (pid files on disk are the source of truth). Callers tear the stack down
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
    owned: Option<OwnedStack>,
}

struct OwnedStack {
    authority: crate::spawn::SpawnedComponent,
    sidecar: crate::spawn::SpawnedComponent,
    state_dir: PathBuf,
}

struct StartupGuard {
    authority: Option<crate::spawn::SpawnedComponent>,
    sidecar: Option<crate::spawn::SpawnedComponent>,
    state_dir: PathBuf,
    disarmed: bool,
}

impl StartupGuard {
    fn new(state_dir: &Path) -> Self {
        Self {
            authority: None,
            sidecar: None,
            state_dir: state_dir.to_path_buf(),
            disarmed: false,
        }
    }

    fn finish(mut self) -> Result<RunningStack> {
        let authority = self
            .authority
            .take()
            .ok_or_else(|| StackError::Platform("authority child missing after startup".into()))?;
        let sidecar = self
            .sidecar
            .take()
            .ok_or_else(|| StackError::Platform("sidecar child missing after startup".into()))?;
        self.disarmed = true;
        Ok(RunningStack::from_components(
            authority,
            sidecar,
            self.state_dir.clone(),
        ))
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }

        debug!(state_dir = %self.state_dir.display(), "startup failed; collecting owned children");
        for component in [&mut self.sidecar, &mut self.authority]
            .into_iter()
            .flatten()
        {
            if let Err(error) = component.termination_target.signal_hard() {
                debug!(
                    target = %component.termination_target.stored_id(),
                    %error,
                    "startup rollback hard termination failed"
                );
            }
            let _ = component.child.kill();
            let _ = component.child.wait();
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut all_absent = true;
            let mut probe_failed = false;
            for component in [&self.sidecar, &self.authority].into_iter().flatten() {
                match component.termination_target.exists() {
                    Ok(false) => {}
                    Ok(true) => all_absent = false,
                    Err(error) => {
                        debug!(
                            target = %component.termination_target.stored_id(),
                            %error,
                            "startup rollback target probe failed"
                        );
                        probe_failed = true;
                        all_absent = false;
                    }
                }
            }
            if all_absent {
                remove_startup_state(&self.state_dir);
                return;
            }
            if probe_failed || Instant::now() >= deadline {
                debug!("startup rollback retained runtime state for a later cleanup attempt");
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl RunningStack {
    pub(crate) fn from_components(
        authority: crate::spawn::SpawnedComponent,
        sidecar: crate::spawn::SpawnedComponent,
        state_dir: PathBuf,
    ) -> Self {
        let handle = StackHandle {
            authority_pid: authority.leader_pid,
            sidecar_pid: sidecar.leader_pid,
        };
        Self {
            handle,
            owned: Some(OwnedStack {
                authority,
                sidecar,
                state_dir,
            }),
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
        let Some(owned) = self.owned.as_mut() else {
            return Ok(crate::stop::StopOutcome { forced: false });
        };
        let result = crate::stop::stop_owned(
            &owned.state_dir,
            timeout,
            &mut owned.authority,
            &mut owned.sidecar,
        );
        if result.is_ok() {
            let _ = owned.sidecar.child.wait();
            let _ = owned.authority.child.wait();
            self.owned = None;
        }
        result
    }

    fn transfer_to_observer(&mut self) {
        if let Some(owned) = self.owned.take() {
            let _ = collect_in_background(owned.authority.child, owned.sidecar.child);
        }
    }
}

impl Drop for RunningStack {
    fn drop(&mut self) {
        self.transfer_to_observer();
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
    let auth = spawn_with_config(&group, state_dir, "authority", &cfg.config_file, exe)?;
    let authority_pid = auth.leader_pid;
    startup.authority = Some(auth);
    info!(pid = %authority_pid, "authority spawned");
    let auth_addr = config.authority_listen_addr()?;
    std::fs::write(state_dir.join("authority.listen"), format!("{auth_addr}\n"))?;
    debug!(addr = %auth_addr, "waiting for authority TCP listen");
    wait_for_tcp("authority", auth_addr, Duration::from_mins(1))?;
    info!(addr = %auth_addr, "authority listening");

    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning sidecar");
    let side = spawn_with_config(&group, state_dir, "sidecar", &cfg.config_file, exe)?;
    let sidecar_pid = side.leader_pid;
    startup.sidecar = Some(side);
    info!(pid = %sidecar_pid, "sidecar spawned");
    let sidecar = config.sidecar_config()?;
    let side_addr = sidecar.interceptor.listen_addr;
    std::fs::write(state_dir.join("sidecar.listen"), format!("{side_addr}\n"))?;
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
/// # Errors
///
/// Returns state directory, spawn, readiness, or detach errors. On failure
/// after children have been spawned, this function tears them down. Runtime
/// state is retained when hard termination fails so callers can retry cleanup.
pub fn start(cfg: &StackConfig, state_dir: &Path, mode: StartMode) -> Result<StackHandle> {
    let mut stack = spawn_stack(cfg, state_dir)?;
    let handle = stack.handle();
    match mode {
        StartMode::Foreground => {
            info!("entering foreground supervisor loop");
            let supervision_result = {
                let owned = stack.owned.as_mut().ok_or_else(|| {
                    StackError::Platform("stack ownership missing before supervision".into())
                })?;
                block_until_owned_exit(&mut owned.authority, &mut owned.sidecar)
            };
            info!("foreground supervisor exiting; tearing down stack");
            // Foreground exit (Ctrl-C, child died): caller is leaving. Tear
            // children down and remove pid/listen/lock files so the next
            // `start` does not trip on stale state.
            let teardown_result = stack.shutdown(Duration::from_secs(10));
            supervision_result?;
            teardown_result?;
        }
        StartMode::Detached => {
            info!("forking detached supervisor");
            if let Err(error) = crate::detach::spawn_supervisor(state_dir) {
                let _ = stack.shutdown(Duration::from_secs(10));
                return Err(error);
            }
            stack.transfer_to_observer();
        }
    }
    Ok(handle)
}

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

/// Run the detached supervisor loop.
///
/// # Errors
///
/// Returns pidfile or supervision errors.
pub fn supervise(state_dir: &Path) -> Result<()> {
    supervise_with_timeout(state_dir, Duration::from_secs(10))
}

pub(crate) fn supervise_with_timeout(state_dir: &Path, timeout: Duration) -> Result<()> {
    let supervisor_pid = UserProcessId::new(std::process::id()).ok_or_else(|| {
        StackError::Platform("current process returned invalid process id".into())
    })?;
    info!(supervisor_pid = %supervisor_pid, state_dir = %state_dir.display(), "supervisor attaching");
    pidfile::write(&state_dir.join("stack.pid"), supervisor_pid)?;
    let authority_pid = pidfile::read(&state_dir.join("authority.pid"))?
        .ok_or_else(|| StackError::Platform("authority.pid missing".into()))?;
    let sidecar_pid = pidfile::read(&state_dir.join("sidecar.pid"))?
        .ok_or_else(|| StackError::Platform("sidecar.pid missing".into()))?;
    debug!(
        authority_pid = %authority_pid,
        sidecar_pid = %sidecar_pid,
        "supervisor re-attached to children"
    );
    let observe_result = block_until_observed_exit(ObservedChildren {
        authority_pid,
        sidecar_pid,
    });
    info!("detached supervisor tearing down components");
    let teardown_result = crate::stop::stop_observed_components(state_dir, timeout);
    info!("supervisor leaving");
    match observe_result {
        Err(error) => Err(error),
        Ok(()) => teardown_result.map(|_| ()),
    }
}

fn spawn_with_config(
    group: &crate::platform::Group,
    state_dir: &Path,
    name: &str,
    cfg_path: &Path,
    exe: Option<&Path>,
) -> Result<crate::spawn::SpawnedComponent> {
    let cfg_str = cfg_path
        .to_str()
        .ok_or_else(|| StackError::Platform("non-utf8 config path".into()))?;
    let subcmd = match name {
        "authority" => vec!["authority", "--config", cfg_str],
        "sidecar" => vec!["sidecar", "--config", cfg_str],
        other => return Err(StackError::Platform(format!("unknown component '{other}'"))),
    };
    spawn_component(
        group,
        &SpawnRequest {
            name,
            args: &subcmd,
            state_dir,
            exe,
        },
    )
}

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
