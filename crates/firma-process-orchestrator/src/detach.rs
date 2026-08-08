//! Spawn the detached supervisor without transferring component ownership.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use tracing::{debug, info};

use crate::error::Result;
use crate::platform::{Platform, SystemPlatform};

/// Spawn the supervisor child retained by detached [`crate::start::start_from_plan`].
///
/// The launcher-assigned [`crate::StackGeneration`] binds this child to the
/// state it may publish and later roll back. The child creates and owns the
/// actual components; the launcher receives only the handle needed to validate
/// or abort handoff.
///
/// `config_file` is re-passed to the child through `--config` so it re-derives
/// the same plan; `firma_bin`, when present, is forwarded through `--firma-bin`
/// so the child spawns components from the same executable as the launcher.
pub fn spawn_supervisor(
    state_dir: &Path,
    config_file: &Path,
    firma_bin: Option<&Path>,
    generation: crate::StackGeneration,
) -> Result<Child> {
    let exe = std::env::current_exe()?;
    debug!(exe = %exe.display(), state_dir = %state_dir.display(), "preparing detached supervisor");

    // The stdio handles are moved into the `Command` and consumed by the spawn
    // attempt, so build the command fresh immediately before spawning.
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir.join("supervisor.log"))?;
    let stderr_log = log.try_clone()?;

    let mut cmd = Command::new(&exe);
    cmd.args(["__supervise", "--state-dir"])
        .arg(state_dir)
        .arg("--config")
        .arg(config_file)
        .arg("--generation")
        .arg(generation.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr_log));
    if let Some(firma_bin) = firma_bin {
        cmd.arg("--firma-bin").arg(firma_bin);
    }

    let child = SystemPlatform::spawn_detached(&mut cmd)?;
    info!(pid = child.id(), "supervisor spawned");
    Ok(child)
}
