//! Platform config-path discovery for the unified `firma` CLI.
//!
//! Resolves a single `firma.toml` from a fixed precedence list and
//! reports which directory won so callers can re-base unset resource
//! paths. Fail-closed: no silent fallback to an empty config.

mod profile;
mod resolver;
mod schema;

/// Canonical config file name shared by every binary.
pub const CONFIG_FILE_NAME: &str = "firma.toml";

pub use profile::AgentProfile;
pub use resolver::{ConfigResolveError, ConfigSource, ResolvedConfig, SystemDirs};
pub use schema::{FirmaConfig, load_section};
