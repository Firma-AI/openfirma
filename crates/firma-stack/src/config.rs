//! Stack config: the resolved inputs needed to boot the stack as one unit.
//!
//! [`StackConfig`] is plain data with no dependency on the firma component
//! crates. Resolving it from the unified `firma.toml` lives in the
//! firma-specific plan module.

use std::path::PathBuf;

/// Configuration needed to boot the authority and sidecar as one unit.
///
/// [`StackConfig::config_file`] is the single resolved `firma.toml`; both
/// children receive that path through `--config` so the parent and children
/// always read the same file.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Optional runtime-state directory override. When absent, the caller uses
    /// [`firma_runtime_state::resolve_state_dir`].
    pub state_dir: Option<PathBuf>,
    /// The single unified `firma.toml` shared by both components.
    pub config_file: PathBuf,
    /// Optional path to the `firma` binary used to spawn children.
    /// [`std::env::current_exe`] is used when absent; callers whose executable
    /// is not `firma` must provide the binary explicitly.
    pub firma_bin: Option<PathBuf>,
}
