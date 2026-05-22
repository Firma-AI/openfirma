//! User-level `firma.toml` reader / writer.
//!
//! Path resolution is delegated to the shared `firma-config` crate so
//! every binary discovers and writes the same `firma.toml`.
//!
//! Only the `[authority]` table is touched by this module today.
//! Persistence is gated by the Y branch of the bootstrap prompt; CLI
//! overrides never rewrite the file.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::RunError;

/// Resolve the discovered `firma.toml` path (no explicit override),
/// or `None` when no candidate exists on this platform.
#[must_use]
pub fn default_user_config_path() -> Option<PathBuf> {
    firma_config::resolve_config("run", None, &firma_config::SystemDirs)
        .ok()
        .map(|r| r.config_file)
}

/// The canonical path to create when persisting `[authority]` and no
/// config file exists yet. Uses `.firma/firma.toml` under the current
/// working directory.
#[must_use]
pub fn canonical_write_path() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join(".firma").join(firma_config::CONFIG_FILE_NAME))
}

/// Client-side connect config (`[authority.connect]`).
///
/// Canonical place for URL, CA cert, and pub key — written by `firma config`,
/// read by `firma run` to synthesize the sidecar config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityConnectSection {
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Path to the PEM CA certificate that signed the authority's TLS cert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_path: Option<std::path::PathBuf>,
    /// Path to the authority's Ed25519 public key for PASETO token verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pub_key_path: Option<std::path::PathBuf>,
}

/// Persisted `[authority]` routing annotation written by `firma run`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySection {
    /// `"local"` or `"remote"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Client-side connect config from `[authority.connect]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<AuthorityConnectSection>,
}

/// Whole-file shape — only the sections we know live here today.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct UserConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<AuthoritySection>,
}

/// Read the `[authority]` section if the file exists and is parseable.
///
/// Returns `Ok(None)` when the file does not exist or the section is
/// absent. Parse errors propagate as [`RunError::ConfigParse`].
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
    let parsed: UserConfig = toml::from_str(&text).map_err(|e| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    Ok(parsed.authority)
}

/// Persist `[authority].type = "local"` (creating parent dirs as needed).
///
/// Atomic via tempfile + rename. Sets `0700` on the parent dir and
/// `0600` on the file on Unix. Preserves any other sections already in
/// the file if it exists.
///
/// # Errors
///
/// Returns an error on I/O failure or serialization failure.
pub fn persist_local(path: &Path) -> Result<(), RunError> {
    let mut existing: toml::Table = match fs::read_to_string(path) {
        Ok(text) => text
            .parse()
            .map_err(|e: toml::de::Error| RunError::ConfigParse {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => {
            return Err(RunError::Internal(format!(
                "read user config {}: {e}",
                path.display()
            )));
        }
    };
    // Merge into existing authority table rather than replacing it, so that
    // [authority.server] / [authority.connect] sub-tables written by
    // `firma config` are preserved.
    let authority = existing
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[authority] is not a table".into()))?;
    authority.insert("type".to_string(), toml::Value::String("local".to_string()));
    let serialized = toml::to_string_pretty(&existing).map_err(|e| {
        RunError::Internal(format!("serialize user config {}: {e}", path.display()))
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", parent.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(parent)
                .map_err(|e| RunError::Internal(format!("stat {}: {e}", parent.display())))?
                .permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)
                .map_err(|e| RunError::Internal(format!("chmod {}: {e}", parent.display())))?;
        }
    }

    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, serialized)
        .map_err(|e| RunError::Internal(format!("write {}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)
            .map_err(|e| RunError::Internal(format!("stat {}: {e}", tmp.display())))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp, perms)
            .map_err(|e| RunError::Internal(format!("chmod {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        RunError::Internal(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_user_config_path_uses_firma_config() {
        let _ = default_user_config_path();
    }

    #[test]
    fn read_authority_returns_none_when_file_missing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nope/firma.toml");
        assert_eq!(read_authority(&path).unwrap(), None);
    }

    #[test]
    fn persist_local_writes_authority_table() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma/firma.toml");
        persist_local(&path).unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert_eq!(section.r#type.as_deref(), Some("local"));
    }

    #[test]
    fn persist_local_preserves_other_sections() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        fs::write(&path, "[other]\nkeep = true\n").unwrap();
        persist_local(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("[other]"), "got: {text}");
        assert!(text.contains("keep = true"), "got: {text}");
        assert!(text.contains("[authority]"), "got: {text}");
    }

    #[cfg(unix)]
    #[test]
    fn persist_local_sets_unix_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma/firma.toml");
        persist_local(&path).unwrap();
        let parent_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn parse_remote_section() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        fs::write(
            &path,
            "[authority]\ntype = \"remote\"\n\n[authority.connect]\nurl = \"https://x\"\n",
        )
        .unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert_eq!(section.r#type.as_deref(), Some("remote"));
        assert_eq!(
            section.connect.as_ref().and_then(|c| c.url.as_deref()),
            Some("https://x")
        );
    }
}
