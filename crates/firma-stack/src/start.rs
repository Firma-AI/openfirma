//! `start` and `supervise` entry points.

use std::path::Path;
use std::time::Duration;

use tracing::{debug, info};

use crate::config::StackConfig;
use crate::error::{Result, StackError};
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::readiness::{FirmaToml, wait_for_ca_material, wait_for_tcp};
use crate::spawn::{SpawnRequest, spawn_component};
use crate::supervisor::{Children, block_until_exit};
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

/// Handle returned by [`spawn_stack`] and [`start`] once the stack has
/// reached the ready state.
///
/// The handle is informational only: it does not own the children's lifecycle
/// (pid files on disk are the source of truth). Callers tear the stack down
/// via [`crate::stop()`].
pub struct StackHandle {
    /// PID of the authority component.
    authority_pid: UserProcessId,
    /// PID of the sidecar component.
    sidecar_pid: UserProcessId,
}

/// Spawn the stack and wait for readiness without blocking on supervision.
///
/// Returns once both components are listening and the sidecar CA material is
/// on disk. The caller owns lifecycle: it must eventually call
/// [`crate::stop()`] to tear the stack down (or rely on the OS reaping pids when
/// the parent process exits).
///
/// Used by `firma-demo-tui` and as the first step of [`start`].
///
/// # Errors
///
/// Returns state-directory, lock, spawn, or readiness errors. On failure
/// after children have been spawned, this function tears them down. Runtime
/// state is retained when hard termination fails so callers can retry cleanup.
pub fn spawn_stack(cfg: &StackConfig, state_dir: &Path) -> Result<StackHandle> {
    info!(state_dir = %state_dir.display(), "spawning firma stack");
    firma_fs::create_private_dir_all(state_dir).map_err(StackError::StateDir)?;
    debug!("acquiring stack lock");
    acquire_lock(state_dir)?;
    debug!("reaping stale pidfiles");
    reap_stale(state_dir)?;

    match spawn_stack_inner(cfg, state_dir) {
        Ok(handle) => {
            info!(
                authority_pid = %handle.authority_pid,
                sidecar_pid = %handle.sidecar_pid,
                "firma stack ready"
            );
            Ok(handle)
        }
        Err(error) => {
            debug!(%error, "spawn failed; rolling back");
            rollback(state_dir);
            Err(error)
        }
    }
}

fn spawn_stack_inner(cfg: &StackConfig, state_dir: &Path) -> Result<StackHandle> {
    let group = SystemPlatform::new_group()?;
    let exe = cfg.firma_bin.as_deref();
    // Parse the unified firma.toml once; the probes below share it.
    let config = FirmaToml::read(&cfg.config_file)?;
    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning authority");
    let auth = spawn_with_config(&group, state_dir, "authority", &cfg.config_file, exe)?;
    info!(pid = %auth.leader_pid, "authority spawned");
    let auth_addr = config.authority_listen_addr()?;
    std::fs::write(state_dir.join("authority.listen"), format!("{auth_addr}\n"))?;
    debug!(addr = %auth_addr, "waiting for authority TCP listen");
    wait_for_tcp("authority", auth_addr, Duration::from_mins(1))?;
    info!(addr = %auth_addr, "authority listening");

    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning sidecar");
    let side = spawn_with_config(&group, state_dir, "sidecar", &cfg.config_file, exe)?;
    info!(pid = %side.leader_pid, "sidecar spawned");
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

    Ok(StackHandle {
        authority_pid: auth.leader_pid,
        sidecar_pid: side.leader_pid,
    })
}

/// Start the authority and sidecar stack.
///
/// # Errors
///
/// Returns state directory, spawn, readiness, or detach errors. On failure
/// after children have been spawned, this function tears them down. Runtime
/// state is retained when hard termination fails so callers can retry cleanup.
pub fn start(cfg: &StackConfig, state_dir: &Path, mode: StartMode) -> Result<StackHandle> {
    let handle = spawn_stack(cfg, state_dir)?;
    match mode {
        StartMode::Foreground => {
            info!("entering foreground supervisor loop");
            block_until_exit(Children {
                authority_pid: handle.authority_pid,
                sidecar_pid: handle.sidecar_pid,
            })?;
            info!("foreground supervisor exiting; tearing down stack");
            // Foreground exit (Ctrl-C, child died): caller is leaving. Tear
            // children down and remove pid/listen/lock files so the next
            // `start` does not trip on stale state.
            crate::stop::stop(state_dir, Duration::from_secs(10))?;
        }
        StartMode::Detached => {
            info!("forking detached supervisor");
            crate::detach::spawn_supervisor(state_dir)?;
        }
    }
    Ok(handle)
}

fn rollback(state_dir: &Path) {
    // Best-effort teardown: kill any spawned children and remove the artifacts
    // we wrote. Errors during rollback are ignored — they would mask the
    // original failure that triggered this path.
    let mut cleanup_safe = true;
    for name in ["authority.pid", "sidecar.pid"] {
        let path = state_dir.join(name);
        match pidfile::read(&path) {
            Ok(Some(id)) => {
                let target = TerminationTarget::from_stored_id(id);
                if !matches!(target.exists(), Ok(false))
                    && let Err(error) = target.signal_hard()
                {
                    debug!(target = %id, %error, "rollback hard termination failed");
                    cleanup_safe = false;
                }
            }
            Ok(None) => {}
            Err(error) => {
                debug!(path = %path.display(), %error, "rollback could not read termination target");
                cleanup_safe = false;
            }
        }
    }
    if !cleanup_safe {
        debug!("rollback retained runtime state for a later cleanup attempt");
        return;
    }
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
    block_until_exit(Children {
        authority_pid,
        sidecar_pid,
    })?;
    info!("supervisor leaving");
    Ok(())
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
    if pid.reap_if_exited() {
        return Ok(false);
    }
    pid.process_exists().map_err(StackError::Io)
}
