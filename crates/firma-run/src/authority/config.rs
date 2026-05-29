//! User-level `firma.toml` reader.
//!
//! Path resolution is delegated to the shared `firma-config` crate so
//! every binary discovers the same `firma.toml`.

use std::fs;
use std::io;
use std::path::Path;

use crate::error::RunError;

pub use firma_sidecar::config::AuthorityConfig as SidecarAuthorityConfig;

/// Snapshot of routing-relevant sections from `firma.toml`.
#[derive(Debug, Clone, Default)]
pub struct AuthoritySection {
    /// `true` when `[authority]` is present — the file declares a
    /// co-located Mini Authority that `firma run` should autostart.
    pub local: bool,
    /// Client-side connect coordinates lifted from `[sidecar.authority]`.
    pub connect: Option<SidecarAuthorityConfig>,
}

/// Read the routing snapshot from `firma.toml`.
///
/// Returns `Ok(None)` when the file does not exist or carries neither
/// `[authority]` nor `[sidecar.authority]` connect coordinates.
///
/// # Errors
///
/// Returns an error on I/O failure (other than `NotFound`) or TOML
/// parse failure.
pub fn read_authority(path: &Path) -> Result<Option<AuthoritySection>, RunError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(RunError::Internal(format!(
                "read user config {}: {e}",
                path.display()
            )));
        }
    };

    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;

    let local = table.contains_key("authority");

    let connect = table
        .get("sidecar")
        .and_then(toml::Value::as_table)
        .and_then(|s| s.get("authority"))
        .and_then(toml::Value::as_table)
        .map(|a| {
            toml::Value::Table(a.clone())
                .try_into::<SidecarAuthorityConfig>()
                .map_err(|e| RunError::ConfigParse {
                    path: path.to_path_buf(),
                    reason: format!("[sidecar.authority]: {e}"),
                })
        })
        .transpose()?
        // Without a URL there is nothing to connect to; partial config
        // (e.g. only cert path set) is silently discarded to avoid a
        // confusing "no authority URL" error later in the startup path.
        .filter(|c| c.url.is_some());

    if !local && connect.is_none() {
        return Ok(None);
    }
    Ok(Some(AuthoritySection { local, connect }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_authority_returns_none_when_file_missing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nope/firma.toml");
        assert!(read_authority(&path).unwrap().is_none());
    }

    #[test]
    fn read_authority_returns_none_when_neither_section_present() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        fs::write(&path, "[other]\nkeep = true\n").unwrap();
        assert!(read_authority(&path).unwrap().is_none());
    }

    #[test]
    fn authority_section_marks_local() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        fs::write(&path, "[authority]\nlisten_addr = \"127.0.0.1:0\"\n").unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert!(section.local);
        assert!(section.connect.is_none());
    }

    #[test]
    fn sidecar_authority_url_is_lifted_into_connect() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        fs::write(&path, "[sidecar.authority]\nurl = \"https://x\"\n").unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert!(!section.local);
        assert_eq!(
            section.connect.as_ref().and_then(|c| c.url.as_deref()),
            Some("https://x")
        );
    }
}
