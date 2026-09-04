pub mod guard;
pub mod issue;
pub mod refresh;

use std::path::Path;

use crate::config::CapabilitySource;
use crate::error::RunError;

/// Read the operator-supplied capability token for a `firma run` session.
///
/// Only [`CapabilitySource::File`] carries an operator-provided seed. Run parses
/// the canonical [`firma_core::CapabilitySeed`] TOML and injects only its
/// `raw_token` into the agent process environment (see `build_execution_env`).
/// This is a one-shot Run read with no Run-managed background refresh. A local
/// Sidecar independently reads and watches the same file; a pre-managed
/// external Sidecar owns its seed configuration. The Firma-minted per-session
/// path uses [`refresh::CapabilityRefresher`] instead.
///
/// # Errors
///
/// Returns [`RunError::Capability`] when the file is unreadable, is not a
/// canonical capability seed, or contains an empty `raw_token`.
pub fn read_capability_token(source: &CapabilitySource) -> Result<Option<String>, RunError> {
    match source {
        CapabilitySource::Disabled => Ok(None),
        CapabilitySource::File { path } => read_token(path).map(Some),
    }
}

fn read_token(path: &Path) -> Result<String, RunError> {
    let body = std::fs::read_to_string(path)
        .map_err(|error| RunError::Capability(format!("{}: {error}", path.display())))?;
    let seed: firma_core::CapabilitySeed = toml::from_str(&body).map_err(|_| {
        RunError::Capability(format!(
            "capability seed '{}' is not canonical CapabilitySeed TOML",
            path.display()
        ))
    })?;

    if seed.raw_token.trim().is_empty() {
        return Err(RunError::Capability(format!(
            "capability seed '{}' has an empty raw_token",
            path.display()
        )));
    }

    Ok(seed.raw_token)
}
