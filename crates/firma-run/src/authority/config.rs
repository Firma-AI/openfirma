//! User-level `firma.toml` reader / writer.
//!
//! Path resolution: `dirs::config_dir().join("firma/firma.toml")`. Linux
//! -> `$XDG_CONFIG_HOME/firma/firma.toml`; macOS -> `~/Library/Application
//! Support/firma/firma.toml`; Windows -> `%APPDATA%\firma\firma.toml`.
//!
//! Only the `[authority]` table is touched by this module today.
//! Persistence is gated by the Y branch of the bootstrap prompt; CLI
//! overrides never rewrite the file.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::RunError;

const FILE_NAME: &str = "firma.toml";
const SUBDIR: &str = "firma";

/// Resolve the default user config path, or `None` on platforms where
/// `dirs::config_dir()` returns `None`.
#[must_use]
pub fn default_user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(SUBDIR).join(FILE_NAME))
}

/// Persisted `[authority]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySection {
    /// `"local"` or `"remote"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Required when `type = "remote"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
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
    let mut authority_table = toml::Table::new();
    authority_table.insert("type".to_string(), toml::Value::String("local".to_string()));
    existing.insert("authority".to_string(), toml::Value::Table(authority_table));
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
        assert!(section.url.is_none());
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
            "[authority]\ntype = \"remote\"\nurl = \"https://x\"\n",
        )
        .unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert_eq!(section.r#type.as_deref(), Some("remote"));
        assert_eq!(section.url.as_deref(), Some("https://x"));
    }
}
