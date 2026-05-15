//! `start` and `supervise` entry points.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::{debug, info};

use crate::config::StackConfig;
use crate::error::{Result, StackError};
use crate::pidfile;
use crate::platform::{Platform, SystemPlatform};
use crate::readiness::{
    read_authority_listen_addr, read_sidecar_listen_addr, wait_for_ca_material, wait_for_tcp,
};
use crate::spawn::{SpawnRequest, spawn_component};
use crate::supervisor::{Children, block_until_exit};

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
/// via [`crate::stop`].
pub struct StackHandle {
    /// PID of the authority component.
    pub authority_pid: u32,
    /// PID of the sidecar component.
    pub sidecar_pid: u32,
    /// Resolved state directory the stack is writing to.
    pub state_dir: PathBuf,
}

/// Spawn the stack and wait for readiness without blocking on supervision.
///
/// Returns once both components are listening and the sidecar CA material is
/// on disk. The caller owns lifecycle: it must eventually call
/// [`crate::stop`] to tear the stack down (or rely on the OS reaping pids when
/// the parent process exits).
///
/// Used by `firma-demo-tui` and as the first step of [`start`].
///
/// # Errors
///
/// Returns state-directory, lock, spawn, or readiness errors. On failure
/// after children have been spawned, this function tears them down and
/// removes any pid/listen/lock files it created before returning the error.
pub fn spawn_stack(cfg: &StackConfig, state_dir: &Path) -> Result<StackHandle> {
    info!(state_dir = %state_dir.display(), "spawning firma stack");
    std::fs::create_dir_all(state_dir).map_err(|source| StackError::StateDirCreate {
        path: state_dir.to_path_buf(),
        source,
    })?;
    debug!("acquiring stack lock");
    acquire_lock(state_dir)?;
    debug!("reaping stale pidfiles");
    reap_stale(state_dir)?;

    match spawn_stack_inner(cfg, state_dir) {
        Ok(handle) => {
            info!(
                authority_pid = handle.authority_pid,
                sidecar_pid = handle.sidecar_pid,
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
    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning authority");
    let auth = spawn_with_config(&group, state_dir, "authority", &cfg.config_file, exe)?;
    info!(pid = auth.pid, "authority spawned");
    let auth_addr = read_authority_listen_addr(&cfg.config_file)?;
    std::fs::write(state_dir.join("authority.listen"), format!("{auth_addr}\n"))?;
    debug!(addr = %auth_addr, "waiting for authority TCP listen");
    wait_for_tcp("authority", auth_addr, Duration::from_secs(60))?;
    info!(addr = %auth_addr, "authority listening");

    debug!(config = %cfg.config_file.display(), exe = ?exe, "spawning sidecar");
    let side = spawn_with_config(&group, state_dir, "sidecar", &cfg.config_file, exe)?;
    info!(pid = side.pid, "sidecar spawned");
    let side_addr = read_sidecar_listen_addr(&cfg.config_file)?;
    std::fs::write(state_dir.join("sidecar.listen"), format!("{side_addr}\n"))?;
    debug!(addr = %side_addr, "waiting for sidecar TCP listen");
    wait_for_tcp("sidecar", side_addr, Duration::from_secs(60))?;
    info!(addr = %side_addr, "sidecar listening");
    debug!("waiting for sidecar CA material");
    wait_for_ca_material(
        &state_dir.join("generated-firma-ca"),
        Duration::from_secs(60),
    )?;
    debug!("CA material present");

    // The Group goes out of scope at the end of this function. On Unix that
    // is a no-op (children sit in their own pgrp). On Windows, the Drop impl
    // closes the Job Object handle; that is safe because we do NOT set
    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — children survive parent exit.
    let _ = group;

    Ok(StackHandle {
        authority_pid: auth.pid,
        sidecar_pid: side.pid,
        state_dir: state_dir.to_path_buf(),
    })
}

/// Start the authority and sidecar stack.
///
/// # Errors
///
/// Returns state directory, spawn, readiness, or detach errors. On failure
/// after children have been spawned, this function tears them down and
/// removes any pid/listen/lock files it created before returning the error.
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
            let _ = crate::stop::stop(state_dir, Duration::from_secs(10));
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
    for name in ["authority.pid", "sidecar.pid"] {
        if let Ok(Some(pid)) = pidfile::read(&state_dir.join(name))
            && SystemPlatform::is_alive(pid)
        {
            let _ = SystemPlatform::signal_hard(pid);
        }
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
    let supervisor_pid = std::process::id();
    info!(supervisor_pid, state_dir = %state_dir.display(), "supervisor attaching");
    pidfile::write(&state_dir.join("stack.pid"), supervisor_pid)?;
    let authority_pid = pidfile::read(&state_dir.join("authority.pid"))?
        .ok_or_else(|| StackError::Platform("authority.pid missing".into()))?;
    let sidecar_pid = pidfile::read(&state_dir.join("sidecar.pid"))?
        .ok_or_else(|| StackError::Platform("sidecar.pid missing".into()))?;
    debug!(
        authority_pid,
        sidecar_pid, "supervisor re-attached to children"
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
        Ok(_) => Ok(()),
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
    // Stale when no recorded supervisor or component pid is still alive.
    for name in ["stack.pid", "authority.pid", "sidecar.pid"] {
        if let Some(pid) = pidfile::read(&state_dir.join(name))?
            && SystemPlatform::is_alive(pid)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reap_stale(state_dir: &Path) -> Result<()> {
    for name in ["authority.pid", "sidecar.pid", "stack.pid"] {
        let path = state_dir.join(name);
        if let Some(pid) = pidfile::read(&path)?
            && !SystemPlatform::is_alive(pid)
        {
            pidfile::remove(&path)?;
        }
    }
    Ok(())
}
