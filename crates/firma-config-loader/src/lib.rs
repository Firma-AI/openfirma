//! Platform config-path discovery for the unified `firma` CLI.
//!
//! Resolves a single `firma.toml` from a fixed precedence list and
//! reports which directory won so callers can re-base unset resource
//! paths. Fail-closed: no silent fallback to an empty config.
//!
//! # Feature flags
//!
//! | name   | description                      | default |
//! |--------|----------------------------------|---------|
//! | `clap` | Enable command-line value enums. |         |

mod profile;
mod resolver;
mod schema;

/// Canonical config file name shared by every binary.
pub const CONFIG_FILE_NAME: &str = "firma.toml";
/// Canonical name for directory that contain `firma` configuration files.
pub const CONFIG_DIR_NAME: &str = ".firma";
/// Canonical name for the environment variable that can be used to
/// shortcircuit config discovery. See [`resolve_config`] for more details.
pub const CONFIG_ENV_NAME: &str = "FIRMA_CONFIG";

pub use profile::AgentProfile;
pub use resolver::{
    ConfigResolveError, ConfigSource, HomeConfigDirError, ResolvedConfig, home_config_dir,
    resolve_config,
};
pub use schema::{FirmaConfig, load_section};
