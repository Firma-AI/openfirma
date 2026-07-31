pub mod guard;
pub mod issue;
pub mod refresh;

use std::path::Path;

use crate::config::CapabilitySource;
use crate::error::RunError;

/// Read the operator-supplied capability token for a `firma run` session.
///
/// Only [`CapabilitySource::File`] carries a bring-your-own token; the token is
/// injected into the agent process environment once at launch (see
/// `build_execution_env`). Rotation is delegated to the agent via the
/// `FIRMA_CAPABILITY_FILE` env var, so this is a one-shot read with no
/// background refresh — the firma-minted per-session path uses
/// [`refresh::CapabilityRefresher`] instead.
///
/// # Errors
///
/// Returns [`RunError::Capability`] when the file is unreadable or empty.
pub fn read_capability_token(source: &CapabilitySource) -> Result<Option<String>, RunError> {
    match source {
        CapabilitySource::Disabled => Ok(None),
        CapabilitySource::File { path } => read_token(path).map(Some),
    }
}

fn read_token(path: &Path) -> Result<String, RunError> {
    let value = std::fs::read_to_string(path)
        .map_err(|error| RunError::Capability(format!("{}: {error}", path.display())))?;

    let token = value.trim().to_string();
    if token.is_empty() {
        return Err(RunError::Capability(format!(
            "capability file {} is empty",
            path.display()
        )));
    }

    Ok(token)
}
