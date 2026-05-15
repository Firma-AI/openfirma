//! Stack config: resolve the unified `firma.toml` shared by every
//! subcommand. No separate per-component config files.

use std::path::{Path, PathBuf};

use tracing::debug;

use crate::error::{Result, StackError};

/// Configuration needed to boot the authority and sidecar as one unit.
///
/// `config_file` is the single resolved `firma.toml`; both children are
/// spawned with `--config <config_file>` so the parent and children
/// always read the exact same file.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Optional override for the runtime state directory. When `None`,
    /// the caller resolves it via [`crate::resolve_state_dir`].
    pub state_dir: Option<PathBuf>,
    /// The single unified `firma.toml` shared by both components.
    pub config_file: PathBuf,
    /// Optional path to the `firma` binary used to spawn children. When
    /// `None`, defaults to `std::env::current_exe()`. Callers whose own
    /// binary is not `firma` (e.g. `firma-demo-tui`) must set this.
    pub firma_bin: Option<PathBuf>,
}

/// Resolve the unified config for the stack.
///
/// `cli_override` is the explicit `--config` flag (if any); otherwise the
/// `firma-config` discovery precedence is used.
///
/// # Errors
///
/// Returns [`StackError::ConfigRead`] when no `firma.toml` can be
/// resolved.
pub fn resolve_stack_config(cli_override: Option<&Path>) -> Result<StackConfig> {
    let resolved = firma_config::resolve_config("stack", cli_override, &firma_config::SystemDirs)
        .map_err(|error| StackError::ConfigRead {
        path: cli_override.map_or_else(|| PathBuf::from("firma.toml"), Path::to_path_buf),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string()),
    })?;
    debug!(config = %resolved.config_file.display(), "resolved unified firma.toml");
    Ok(StackConfig {
        state_dir: None,
        config_file: resolved.config_file,
        firma_bin: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_with_explicit_override() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(&p, "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n").unwrap();
        let cfg = resolve_stack_config(Some(&p)).unwrap();
        assert_eq!(cfg.config_file, p);
        assert!(cfg.state_dir.is_none());
    }

    #[test]
    fn unresolvable_is_error() {
        let missing = Path::new("/definitely/not/here/firma.toml");
        let cfg = resolve_stack_config(Some(missing)).unwrap();
        assert_eq!(cfg.config_file, missing);
    }
}
