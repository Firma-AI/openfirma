//! `metadata.toml` builder for the per-run sidecar marker dir.
//!
//! Schema frozen by the FIR-103 plan — `firma sidecar status` reads
//! exactly these fields. Any change here must move in lockstep with
//! FIR-103's `sidecar_markers::MetadataFile`.

use std::path::Path;

use serde::Serialize;

use crate::error::RunError;

/// On-disk schema for `<marker_dir>/metadata.toml`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Metadata {
    pub sandbox_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub authority_url: String,
    pub policy_bundle_version: String,
    pub pid: u32,
    pub started_at: String,
}

/// Serialize `meta` and write it atomically to `out`. Creates parent
/// directories on demand.
pub(crate) fn write(out: &Path, meta: &Metadata) -> Result<(), RunError> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| RunError::Internal(format!("mkdir {}: {error}", parent.display())))?;
    }
    let text = toml::to_string_pretty(meta)
        .map_err(|error| RunError::Internal(format!("serialize metadata: {error}")))?;
    let tmp = out.with_extension("toml.tmp");
    std::fs::write(&tmp, text)
        .map_err(|error| RunError::Internal(format!("write {}: {error}", tmp.display())))?;
    std::fs::rename(&tmp, out).map_err(|error| {
        RunError::Internal(format!(
            "rename {} -> {}: {error}",
            tmp.display(),
            out.display()
        ))
    })?;
    Ok(())
}
