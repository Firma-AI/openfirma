//! `metadata.toml` builder for the per-run sidecar marker dir.
//!
//! `firma sidecar status` reads the same shared schema from
//! `firma-runtime-state`.

use std::path::Path;

use crate::error::RunError;

pub use firma_runtime_state::sidecar_markers::MetadataFile as Metadata;

/// Serialize `meta` and write it atomically to `out`. Creates parent
/// directories on demand.
pub fn write(out: &Path, meta: &Metadata) -> Result<(), RunError> {
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
