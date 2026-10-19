//! Where the connection directory is.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::StoreError;

/// Environment variable that overrides the connection directory.
const DIR_ENV: &str = "FIRMA_CONNECTION_DIR";

/// The directory that holds the connection.
///
/// It is `$FIRMA_CONNECTION_DIR` when set and not empty, otherwise `firma`
/// inside the per-user configuration directory: `$XDG_CONFIG_HOME` (when
/// absolute) or `~/.config` on Linux and other Unix systems,
/// `~/Library/Application Support` on macOS, `%APPDATA%` on Windows.
///
/// # Errors
///
/// Returns [`StoreError::RelativeDirectory`] for a relative
/// `FIRMA_CONNECTION_DIR`, and [`StoreError::NoConfigDirectory`] when no
/// directory is available.
pub fn default_dir() -> Result<PathBuf, StoreError> {
    if let Some(dir) = var(DIR_ENV).map(PathBuf::from) {
        return if dir.is_absolute() {
            Ok(dir)
        } else {
            Err(StoreError::RelativeDirectory { path: dir })
        };
    }
    dirs::config_dir()
        .map(|dir| dir.join("firma"))
        .ok_or(StoreError::NoConfigDirectory)
}

fn var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}
