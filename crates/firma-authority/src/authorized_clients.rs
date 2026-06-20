//! Allow-list of authorized mTLS client identities.
//!
//! Loaded from a TOML file at Authority startup. Each entry names a CN or DNS
//! SAN that a Sidecar client certificate must present for the TLS handshake to
//! succeed. The set is read once at startup; restart the Authority to rotate
//! the allow-list.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

use crate::config::ConfigError;

/// In-memory set of authorized client identities (CN or DNS SAN strings).
///
/// Populated from the on-disk authorized clients TOML file at startup. Look-ups are O(1)
/// and require no locking — the set is immutable after construction.
#[derive(Debug, Clone)]
pub struct AuthorizedClientSet {
    identities: HashSet<String>,
}

impl AuthorizedClientSet {
    /// Load the allow-list from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::IoError`] if the file cannot be read, or
    /// [`ConfigError::ParseError`] if the TOML is malformed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        let file: AuthorizedClientsFile =
            toml::from_str(&contents).map_err(|e| ConfigError::ParseError {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        let mut identities = HashSet::new();

        for client in file.clients {
            if !client.identity.trim().is_empty() {
                identities.insert(client.identity);
            }
        }

        for entry in file.authorized {
            if let Some(cn) = entry.cn
                && !cn.trim().is_empty()
            {
                identities.insert(cn);
            }
            if let Some(san) = entry.san
                && !san.trim().is_empty()
            {
                identities.insert(san);
            }
        }

        Ok(Self { identities })
    }

    /// Return `true` if `identity` (a CN or DNS SAN) is in the allow-list.
    #[must_use]
    pub fn contains(&self, identity: &str) -> bool {
        self.identities.contains(identity)
    }

    /// Number of entries in the allow-list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// `true` when the allow-list is empty (no clients are authorized).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizedClientsFile {
    #[serde(default)]
    authorized: Vec<AuthorizedEntry>,
    #[serde(default)]
    clients: Vec<ClientEntry>,
}

#[derive(Deserialize)]
#[expect(
    dead_code,
    reason = "backward-compatible TOML schema accepts metadata fields that serde deserializes even when the loader ignores them"
)]
struct AuthorizedEntry {
    #[serde(default)]
    cn: Option<String>,
    #[serde(default)]
    san: Option<String>,
    #[serde(default)]
    issued_at: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct ClientEntry {
    identity: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn write_toml(toml: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        f
    }

    #[test]
    fn load_valid_allow_list() {
        let f = write_toml(
            r#"
[[clients]]
identity = "sidecar-production-1"

[[clients]]
identity = "sidecar-staging"
"#,
        );
        let set = AuthorizedClientSet::load(f.path()).unwrap();
        assert!(set.contains("sidecar-production-1"));
        assert!(set.contains("sidecar-staging"));
        assert!(!set.contains("unknown"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn load_v11_authorized_schema() {
        let f = write_toml(
            r#"
[[authorized]]
cn = "firma-sidecar-workstation-alice"
issued_at = "2026-06-01"
notes = "Alice's laptop"

[[authorized]]
san = "sidecar-prod-1.internal"
"#,
        );
        let set = AuthorizedClientSet::load(f.path()).unwrap();
        assert!(set.contains("firma-sidecar-workstation-alice"));
        assert!(set.contains("sidecar-prod-1.internal"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn empty_clients_list_is_valid() {
        let f = write_toml("");
        let set = AuthorizedClientSet::load(f.path()).unwrap();
        assert!(set.is_empty());
        assert!(!set.contains("anything"));
    }

    #[test]
    fn nonexistent_file_returns_io_error() {
        let result = AuthorizedClientSet::load(std::path::Path::new("/nonexistent/clients.toml"));
        assert!(matches!(result, Err(ConfigError::IoError { .. })));
    }

    #[test]
    fn malformed_toml_returns_parse_error() {
        let f = write_toml("NOT VALID TOML ::::");
        let result = AuthorizedClientSet::load(f.path());
        assert!(matches!(result, Err(ConfigError::ParseError { .. })));
    }
}
