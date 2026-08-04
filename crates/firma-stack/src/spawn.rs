//! Cross-platform spawn helpers used by `start`.

use std::path::Path;
use std::process::{Child, Command};

use tracing::debug;

use crate::error::Result;
use crate::platform::{Group, Platform, SystemPlatform, TerminationTarget};
use firma_runtime_state::{UserProcessId, pidfile};

#[derive(Clone, Copy)]
pub struct SpawnRequest<'a> {
    pub name: &'a str,
    pub args: &'a [&'a str],
    pub state_dir: &'a Path,
    /// Override for the binary to invoke. When `None`, `current_exe()`
    /// is used.
    pub exe: Option<&'a Path>,
}

pub struct SpawnedComponent {
    pub child: Child,
    pub leader_pid: UserProcessId,
    pub termination_target: TerminationTarget,
}

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
    let mut spawned = SystemPlatform::spawn_in_group(group, &mut cmd, &log_path)?;
    if let Err(error) = pidfile::write(&pidfile_path, spawned.termination_target.stored_id()) {
        let _ = spawned.termination_target.signal_hard();
        let _ = spawned.child.kill();
        let _ = spawned.child.wait();
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
