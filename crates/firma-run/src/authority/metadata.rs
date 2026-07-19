//! `authority/metadata.toml` builder for the per-run authority marker.

use std::path::Path;

use serde::Serialize;

use crate::error::RunError;
use firma_runtime_state::{SandboxId, UserProcessId};

#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    pub sandbox_id: SandboxId,
    pub agent_id: String,
    pub session_id: String,
    pub profile: String,
    pub listen_addr: String,
    pub pid: UserProcessId,
    pub started_at: String,
}

pub fn write(out: &Path, meta: &Metadata) -> Result<(), RunError> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", parent.display())))?;
    }
    let text = toml::to_string_pretty(meta)
        .map_err(|e| RunError::Internal(format!("serialize authority metadata: {e}")))?;
    let tmp = out.with_extension("toml.tmp");
    std::fs::write(&tmp, text)
        .map_err(|e| RunError::Internal(format!("write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, out).map_err(|e| {
        RunError::Internal(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            out.display()
        ))
    })?;
    Ok(())
}
