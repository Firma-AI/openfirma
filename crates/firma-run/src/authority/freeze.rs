//! Freeze authored mapping inputs before the agent starts.
//!
//! Mapping sources may sit in a workspace the agent can write, and a local
//! Authority hot-reloads them, so watching them in place would let the agent
//! widen its own governance. Each file is copied into the control-plane
//! runtime, which the sandbox backend seals, and the launched configuration
//! names only the copies. Policies keep their documented hot reload from the
//! configured directory.

use std::path::{Path, PathBuf};

use firma_config_schema::authority::AuthorityConfig;

use crate::error::RunError;

/// Copy every mapping input of `config` under `dir` and point `config` at the
/// copies.
///
/// # Errors
///
/// Returns [`RunError::ConfigValidation`] naming the authored source when an
/// input cannot be read, and [`RunError::Internal`] when a copy cannot be
/// written.
pub fn freeze_mapping_inputs(config: &mut AuthorityConfig, dir: &Path) -> Result<(), RunError> {
    for (index, path) in config.mapping_rules_paths.iter_mut().enumerate() {
        // Indexing preserves order and keeps same-named sources distinct; the
        // original name keeps Authority diagnostics recognizable.
        *path = freeze_file(path, dir, &index.to_string())?;
    }
    Ok(())
}

fn freeze_file(source: &Path, target_dir: &Path, prefix: &str) -> Result<PathBuf, RunError> {
    let content = std::fs::read(source).map_err(|error| unreadable(source, &error))?;
    create_dir(target_dir)?;
    let name = source
        .file_name()
        .map_or_else(|| "input".into(), |name| name.to_string_lossy());
    let target = target_dir.join(format!("{prefix}-{name}"));
    write(&target, &content)?;
    Ok(target)
}

fn unreadable(path: &Path, error: &std::io::Error) -> RunError {
    RunError::ConfigValidation(format!(
        "cannot read Authority input {}: {error}",
        path.display()
    ))
}

fn create_dir(dir: &Path) -> Result<(), RunError> {
    firma_fs::create_private_dir_all(dir).map_err(|error| RunError::Internal(error.to_string()))
}

fn write(path: &Path, content: &[u8]) -> Result<(), RunError> {
    firma_fs::write_private_file(path, content).map_err(|error| {
        RunError::Internal(format!(
            "freeze Authority input {}: {error}",
            path.display()
        ))
    })
}
