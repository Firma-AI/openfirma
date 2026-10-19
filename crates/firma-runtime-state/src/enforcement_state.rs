//! The enforcement snapshot a running Sidecar publishes for status readers.
//!
//! The Sidecar is the only writer: it removes the file at startup and replaces
//! it after each accepted Authority snapshot. Readers treat the file as
//! observational; a missing or unparseable file means the version is unknown.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name of the per-run enforcement state, beside `metadata.toml`.
const RUN_FILE_NAME: &str = "enforcement.toml";

/// File name of the daemon Sidecar's enforcement state in the state directory.
const DAEMON_FILE_NAME: &str = "sidecar.enforcement.toml";

/// On-disk schema of the enforcement state file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementState {
    /// Authority bundle version the Sidecar enforces.
    pub version: String,
    /// TTL the bundle was accepted with.
    pub ttl_seconds: u32,
    /// RFC 3339 UTC time the bundle was swapped in.
    pub swapped_at: String,
    /// RFC 3339 UTC time after which the bundle is stale unless refreshed.
    pub expires_at: String,
}

/// Return the enforcement state path inside a per-run marker directory.
#[must_use]
pub fn run_path(marker_dir: &Path) -> PathBuf {
    marker_dir.join(RUN_FILE_NAME)
}

/// Return the daemon Sidecar's enforcement state path.
#[must_use]
pub fn daemon_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DAEMON_FILE_NAME)
}

/// Replace the enforcement state file atomically.
///
/// The content is written to a flushed owner-only temporary file in the same
/// directory and renamed over `path`, so readers observe the previous or the
/// complete new state.
///
/// # Errors
///
/// Returns serialization or filesystem errors.
pub fn write(path: &Path, state: &EnforcementState) -> crate::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(toml::to_string(state)?.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Read the enforcement state, or `None` when it is missing or unparseable.
#[must_use]
pub fn read(path: &Path) -> Option<EnforcementState> {
    toml::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Remove a previous process's enforcement state.
///
/// # Errors
///
/// Returns filesystem errors other than not-found.
pub fn remove(path: &Path) -> crate::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}
