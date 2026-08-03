//! Cross-platform component creation for [`mod@crate::start`].
//!
//! [`spawn_component`] is the commit boundary between an untracked child and a
//! governed stack component: it does not return until the process-tree
//! [`TerminationTarget`] has been persisted. Until then, this module retains
//! both termination and direct-child collection responsibility.

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::error::Result;
use crate::platform::{Group, Platform, SpawnedChild, SystemPlatform, TerminationTarget};
use crate::supervisor::{collect_child_until, collect_target_in_background};
use firma_runtime_state::{UserProcessId, pidfile};

/// Immutable inputs for one managed component spawn attempt.
#[derive(Clone, Copy)]
pub struct SpawnRequest<'a> {
    /// Logical identity used for runtime-state and log file names.
    pub name: &'a str,
    /// Command-line arguments passed to the selected executable.
    pub args: &'a [&'a str],
    /// Directory in which governed runtime state is published.
    pub state_dir: &'a Path,
    /// Executable override; [`std::env::current_exe`] is used when absent.
    pub exe: Option<&'a Path>,
}

/// Coupled ownership of one component's direct child and termination scope.
///
/// [`child`](Self::child) must remain available to collect the leader, while
/// [`termination_target`](Self::termination_target) governs the complete
/// platform scope. [`leader_pid`](Self::leader_pid) is informational and must
/// not substitute for the [`TerminationTarget`] when descendants may exist.
pub struct SpawnedComponent {
    /// Direct-child handle required for exit collection.
    pub child: Child,
    /// Original component leader identity for diagnostics.
    pub leader_pid: UserProcessId,
    /// Platform authority for probing and terminating the component scope.
    pub termination_target: TerminationTarget,
}

/// Spawn and publish one governed component.
///
/// The returned [`SpawnedComponent`] is committed only after [`pidfile::write`]
/// records its [`TerminationTarget`]. If publication fails, this function
/// requests process-tree termination and collects the direct child before
/// returning, preventing an ungoverned process from escaping startup rollback.
///
/// # Errors
///
/// Returns executable discovery, log creation, platform spawn, group
/// assignment, or runtime-state publication errors.
pub fn spawn_component(group: &Group, req: &SpawnRequest<'_>) -> Result<SpawnedComponent> {
    let exe: std::path::PathBuf = match req.exe {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe()?,
    };
    let log_path = req.state_dir.join(format!("{}.log", req.name));
    let pidfile_path = req.state_dir.join(format!("{}.pid", req.name));
    debug!(
        name = req.name,
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
    debug!(name = req.name, pid = %leader_pid, pidfile = %pidfile_path.display(), "pidfile written");
    Ok(SpawnedComponent {
        child: spawned.child,
        leader_pid,
        termination_target: spawned.termination_target,
    })
}

/// Recover process ownership after post-spawn publication fails.
///
/// This function requests process-tree and leader termination, then attempts
/// bounded direct-child collection. If collection is not yet possible, it
/// transfers the paired child and [`TerminationTarget`] to
/// [`collect_target_in_background`] rather than dropping the only collector.
pub fn cleanup_failed_spawn(mut spawned: SpawnedChild) {
    let _ = spawned.termination_target.signal_hard();
    let _ = spawned.child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    if !collect_child_until(&mut spawned.child, deadline) {
        let _ = collect_target_in_background(spawned.child, spawned.termination_target);
    }
}
