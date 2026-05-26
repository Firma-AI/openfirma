//! Platform config-path discovery for the unified `firma` CLI.
//!
//! Resolves a single `firma.toml` from a fixed precedence list and
//! reports which directory won so callers can re-base unset resource
//! paths. Fail-closed: no silent fallback to an empty config.

mod provider;
mod resolver;
mod schema;

/// Canonical config file name shared by every binary.
pub const CONFIG_FILE_NAME: &str = "firma.toml";
/// Application subdir under a platform config root (e.g. `~/.config/firma`).
pub const CONFIG_SUBDIR: &str = "firma";

pub use provider::{DirProvider, SystemDirs};
pub use resolver::{ConfigResolveError, ConfigSource, ResolvedConfig, resolve_config};
pub use schema::{FirmaConfig, load_section};
