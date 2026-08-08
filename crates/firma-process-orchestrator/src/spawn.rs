//! Cross-platform component creation for [`mod@crate::start`].
//!
//! [`spawn_component`] is the commit boundary between an untracked child and an
//! [`OwnedComponent`]: it does not return until the process-tree
//! [`crate::platform::TerminationTarget`] has been persisted. Until then, this
//! module retains both termination and direct-child collection responsibility.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::collect::{collect_child_until, collect_target_in_background};
use crate::component::{ComponentName, OwnedComponent};
use crate::error::OrchestratorError;
use crate::platform::{Group, Platform, SpawnedChild, SystemPlatform};
use firma_runtime_state::pidfile;

/// Immutable inputs required to spawn one managed stack component.
#[derive(Clone)]
pub struct SpawnRequest<'a> {
    /// Identity assigned to the new process.
    pub name: ComponentName,
    /// Command-line arguments passed to the component executable.
    pub args: &'a [&'a str],
    /// Directory in which per-component runtime state is recorded.
    pub state_dir: &'a Path,
    /// Executable override; [`std::env::current_exe`] is used when absent.
    pub exe: Option<&'a Path>,
}

/// Spawn one component and return its exclusive process capabilities.
///
/// The returned [`OwnedComponent`] is committed only after [`pidfile::write`]
/// records its termination target. If publication fails,
/// [`cleanup_failed_spawn`] prevents an ungoverned process from escaping the
/// startup transaction.
///
/// # Errors
///
/// Returns executable discovery, process spawn, or pidfile errors. A process
/// whose pidfile cannot be written is terminated and collected before return.
pub fn spawn_component(
    group: &Group,
    req: &SpawnRequest<'_>,
) -> Result<OwnedComponent, OrchestratorError> {
    let exe: std::path::PathBuf = match req.exe {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe()?,
    };
    let name = req.name.as_str();
    let log_path = req.state_dir.join(format!("{name}.log"));
    let pidfile_path = req.state_dir.join(req.name.pidfile_name());
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
    Ok(OwnedComponent::from_spawned(req.name.clone(), spawned))
}

/// Recover process ownership after post-spawn publication fails.
///
/// This function requests process-tree and leader termination, then attempts
/// bounded direct-child collection. If collection is not yet possible, it
/// transfers the paired child and target to
/// [`collect_target_in_background`] rather than dropping the only collector.
pub fn cleanup_failed_spawn(mut spawned: SpawnedChild) {
    let _ = spawned.termination_target.signal_hard();
    let _ = spawned.child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    if !collect_child_until(&mut spawned.child, deadline) {
        let _ = collect_target_in_background(spawned.child, spawned.termination_target);
    }
}
