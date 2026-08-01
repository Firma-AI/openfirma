//! Cross-platform spawn helpers used by `start`.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::component::{ComponentRole, OwnedComponent};
use crate::error::Result;
use crate::platform::{Group, Platform, SpawnedChild, SystemPlatform};
use crate::supervisor::{collect_child_until, collect_target_in_background};
use firma_runtime_state::pidfile;

/// Immutable inputs required to spawn one managed stack component.
#[derive(Clone, Copy)]
pub struct SpawnRequest<'a> {
    /// Stack role assigned to the new process.
    pub role: ComponentRole,
    /// Command-line arguments passed to the component executable.
    pub args: &'a [&'a str],
    /// Directory in which role-specific runtime state is recorded.
    pub state_dir: &'a Path,
    /// Override for the binary to invoke. When `None`, `current_exe()`
    /// is used.
    pub exe: Option<&'a Path>,
}

/// Spawn one component and return its exclusive process capabilities.
///
/// # Errors
///
/// Returns executable discovery, process spawn, or pidfile errors. A process
/// whose pidfile cannot be written is terminated and collected before return.
pub fn spawn_component(group: &Group, req: &SpawnRequest<'_>) -> Result<OwnedComponent> {
    let exe: std::path::PathBuf = match req.exe {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe()?,
    };
    let name = req.role.name();
    let log_path = req.state_dir.join(format!("{name}.log"));
    let pidfile_path = req.state_dir.join(req.role.pidfile_name());
    debug!(
        name,
        exe = %exe.display(),
        args = ?req.args,
        log = %log_path.display(),
        "spawning component"
    );

    let mut cmd = Command::new(exe);
    cmd.args(req.args);
    let spawned = SystemPlatform::spawn_in_group(group, &mut cmd, &log_path)?;
    if let Err(error) = pidfile::write(&pidfile_path, spawned.termination_target.stored_id()) {
        cleanup_failed_spawn(spawned);
        return Err(error.into());
    }
    let leader_pid = spawned.leader_pid;
    debug!(name, pid = %leader_pid, pidfile = %pidfile_path.display(), "pidfile written");
    Ok(OwnedComponent::from_spawned(req.role, spawned))
}

/// Terminate and collect a process whose post-spawn setup failed.
pub fn cleanup_failed_spawn(mut spawned: SpawnedChild) {
    let _ = spawned.termination_target.signal_hard();
    let _ = spawned.child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    if !collect_child_until(&mut spawned.child, deadline) {
        let _ = collect_target_in_background(spawned.child, spawned.termination_target);
    }
}
