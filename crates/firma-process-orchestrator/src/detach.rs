//! Spawn the detached supervisor without transferring component ownership.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use tracing::{debug, info};

use crate::error::OrchestratorError;
use crate::platform::{Platform, SystemPlatform};

/// Spawn a caller-described supervisor with orchestrator-owned detachment and logs.
///
/// The launcher-assigned [`crate::StackGeneration`] binds this child to the
/// state it may publish and later roll back. The child creates and owns the
/// actual components; the launcher receives only the handle needed to validate
/// or abort handoff.
pub fn spawn_supervisor(state_dir: &Path, cmd: &mut Command) -> Result<Child, OrchestratorError> {
    debug!(program = ?cmd.get_program(), state_dir = %state_dir.display(), "preparing detached supervisor");

    // The stdio handles are moved into the `Command` and consumed by the spawn
    // attempt, so build the command fresh immediately before spawning.
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir.join("supervisor.log"))?;
    let stderr_log = log.try_clone()?;

    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr_log));
    let child = SystemPlatform::spawn_detached(cmd)?;
    info!(pid = child.id(), "supervisor spawned");
    Ok(child)
}
