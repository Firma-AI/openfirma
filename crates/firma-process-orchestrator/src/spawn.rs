//! Cross-platform component creation for [`mod@crate::start`].
//!
//! [`spawn_component`] creates the platform child and its process-tree
//! [`crate::platform::TerminationTarget`]. The startup owner must record those
//! capabilities before performing another fallible operation.

use std::path::Path;
use std::process::Command;

use tracing::debug;

use crate::component::ComponentName;
use crate::error::OrchestratorError;
use crate::platform::{Group, Platform, SpawnedChild, SystemPlatform};

/// Inputs required to spawn one managed stack component.
pub struct SpawnRequest<'a> {
    /// Identity assigned to the new process.
    pub name: ComponentName,
    /// Caller-owned command to mutate with orchestration settings and spawn.
    pub command: &'a mut Command,
    /// Directory in which per-component runtime state is recorded.
    pub state_dir: &'a Path,
}

/// Spawn one component and return its exclusive process capabilities.
///
/// # Errors
///
/// Returns process spawn or platform-setup errors.
pub fn spawn_component(
    group: &Group,
    req: &mut SpawnRequest<'_>,
) -> Result<SpawnedChild, OrchestratorError> {
    let name = req.name.as_str();
    let log_path = req.state_dir.join(format!("{name}.log"));
    debug!(
        name,
        program = ?req.command.get_program(),
        log = %log_path.display(),
        "spawning component"
    );

    SystemPlatform::spawn_in_group(group, req.command, &log_path)
}
