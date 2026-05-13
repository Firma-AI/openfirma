//! Stack config: TOML schema, file load, relative path resolution.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

use crate::error::{Result, StackError};

#[derive(Debug, Clone, Deserialize)]
struct RawConfig {
    state_dir: Option<PathBuf>,
    authority_config: Option<PathBuf>,
    sidecar_config: Option<PathBuf>,
}

/// Configuration needed to boot the authority and sidecar as one unit.
///
/// Constructed either programmatically (e.g. from `firma-demo-tui`) or by
/// parsing a TOML file with [`load_stack_config`]. Paths returned in this
/// struct are always absolute or resolved relative to the config file's
/// parent directory.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Optional override for the runtime state directory. When `None`, the
    /// caller resolves the state dir via [`crate::resolve_state_dir`].
    pub state_dir: Option<PathBuf>,
    /// Path to the authority component's TOML config file.
    pub authority_config: PathBuf,
    /// Path to the sidecar component's TOML config file.
    pub sidecar_config: PathBuf,
    /// Optional path to the `firma` binary used to spawn authority and
    /// sidecar children. When `None`, defaults to `std::env::current_exe()`.
    /// Callers whose own binary is not `firma` (e.g. `firma-demo-tui`) must
    /// set this to the `firma` binary path.
    pub firma_bin: Option<PathBuf>,
}

/// Load and normalize a stack configuration file.
///
/// # Errors
///
/// Returns read, TOML parse, or missing-field errors.
pub fn load_stack_config(path: &Path) -> Result<StackConfig> {
    debug!(path = %path.display(), "loading stack config");
    let text = std::fs::read_to_string(path).map_err(|source| StackError::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: RawConfig = toml::from_str(&text).map_err(|source| StackError::ConfigParse {
        path: path.to_path_buf(),
        source,
    })?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let authority_config = raw
        .authority_config
        .ok_or_else(|| StackError::ConfigMissing {
            path: path.to_path_buf(),
            field: "authority_config",
        })?;
    let sidecar_config = raw
        .sidecar_config
        .ok_or_else(|| StackError::ConfigMissing {
            path: path.to_path_buf(),
            field: "sidecar_config",
        })?;

    Ok(StackConfig {
        state_dir: raw.state_dir.map(|p| resolve_relative(parent, p)),
        authority_config: resolve_relative(parent, authority_config),
        sidecar_config: resolve_relative(parent, sidecar_config),
        firma_bin: None,
    })
}

fn resolve_relative(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}
