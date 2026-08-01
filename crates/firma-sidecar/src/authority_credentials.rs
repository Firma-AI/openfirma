//! Sidecar credentials presented to Authority RPCs.

use std::fmt;
use std::path::{Path, PathBuf};

use firma_protobuf::v1::SidecarCredentials;
use serde::Deserialize;

/// Configured source for Sidecar pre-shared-key credentials.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SidecarCredentialsConfig {
    /// Workspace the Sidecar belongs to.
    pub workspace_id: String,
    /// Authority-assigned Sidecar identity.
    pub sidecar_id: String,
    /// Environment variable containing the pre-shared key.
    #[serde(default)]
    pub pre_shared_key_env: Option<String>,
    /// File containing the pre-shared key.
    #[serde(default)]
    pub pre_shared_key_path: Option<PathBuf>,
}

impl SidecarCredentialsConfig {
    /// Validate configured Sidecar credentials.
    ///
    /// # Errors
    ///
    /// Returns a field-level error when the identity or PSK source is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.workspace_id.trim().is_empty() {
            return Err("workspace_id must not be empty".to_string());
        }
        if self.sidecar_id.trim().is_empty() {
            return Err("sidecar_id must not be empty".to_string());
        }

        let has_env = self
            .pre_shared_key_env
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_path = self
            .pre_shared_key_path
            .as_deref()
            .is_some_and(|path| !path.as_os_str().is_empty());

        match (has_env, has_path) {
            (true, false) | (false, true) => Ok(()),
            (false, false) => {
                Err("exactly one of pre_shared_key_env or pre_shared_key_path must be set".into())
            }
            (true, true) => {
                Err("pre_shared_key_env and pre_shared_key_path are mutually exclusive".into())
            }
        }
    }

    /// Re-base a relative PSK file path against the config directory.
    pub fn rebase_defaults(&mut self, config_dir: &Path) {
        if let Some(path) = self.pre_shared_key_path.as_mut()
            && !path.as_os_str().is_empty()
            && path.is_relative()
        {
            *path = config_dir.join(&*path);
        }
    }

    /// Resolve the configured PSK source into in-memory credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails or the selected PSK source cannot
    /// be read.
    pub fn resolve(&self) -> Result<ResolvedSidecarCredentials, String> {
        self.validate()?;
        if let Some(env_name) = self
            .pre_shared_key_env
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let value = std::env::var(env_name)
                .map_err(|_| format!("pre-shared key env var {env_name} is not set"))?;
            let key = trim_trailing_newlines(value);
            if key.is_empty() {
                return Err(format!("pre-shared key env var {env_name} is empty"));
            }
            return Ok(ResolvedSidecarCredentials {
                workspace_id: self.workspace_id.clone(),
                sidecar_id: self.sidecar_id.clone(),
                pre_shared_key: RedactedPreSharedKey(key),
                source: SidecarCredentialSource::Env(env_name.to_string()),
            });
        }

        let path = self
            .pre_shared_key_path
            .as_deref()
            .ok_or_else(|| "pre_shared_key_path missing after validation".to_string())?;
        let value = std::fs::read_to_string(path)
            .map_err(|error| format!("read pre-shared key file {}: {error}", path.display()))?;
        let key = trim_trailing_newlines(value);
        if key.is_empty() {
            return Err(format!("pre-shared key file {} is empty", path.display()));
        }
        Ok(ResolvedSidecarCredentials {
            workspace_id: self.workspace_id.clone(),
            sidecar_id: self.sidecar_id.clone(),
            pre_shared_key: RedactedPreSharedKey(key),
            source: SidecarCredentialSource::File(path.to_path_buf()),
        })
    }
}

/// Resolved credential source, kept for startup logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarCredentialSource {
    /// PSK was read from an environment variable.
    Env(String),
    /// PSK was read from a file.
    File(PathBuf),
}

impl SidecarCredentialSource {
    /// Return the source kind for structured logs.
    #[must_use]
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Env(_) => "env",
            Self::File(_) => "file",
        }
    }
}

/// Resolved Sidecar credentials ready to attach to Authority requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSidecarCredentials {
    /// Workspace the Sidecar belongs to.
    pub(crate) workspace_id: String,
    /// Authority-assigned Sidecar identity.
    pub(crate) sidecar_id: String,
    /// Resolved pre-shared key.
    pub(crate) pre_shared_key: RedactedPreSharedKey,
    /// Source used to resolve the PSK.
    pub(crate) source: SidecarCredentialSource,
}

impl ResolvedSidecarCredentials {
    /// Convert to the generated protobuf message.
    #[must_use]
    pub fn to_proto(&self) -> SidecarCredentials {
        SidecarCredentials {
            workspace_id: self.workspace_id.clone(),
            sidecar_id: self.sidecar_id.clone(),
            pre_shared_key: self.pre_shared_key.expose_secret().to_string(),
        }
    }
}

/// Pre-shared key wrapper with redacted debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedPreSharedKey(String);

impl RedactedPreSharedKey {
    /// Wrap a plaintext pre-shared key.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Expose the plaintext secret for the final Authority request message.
    #[must_use]
    fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedPreSharedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedPreSharedKey(...)")
    }
}

fn trim_trailing_newlines(mut value: String) -> String {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_missing_psk_source() {
        let config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: None,
            pre_shared_key_path: None,
        };
        assert!(config.validate().unwrap_err().contains("exactly one"));
    }

    #[test]
    fn validate_rejects_both_psk_sources() {
        let config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: Some("FIRMA_PSK".to_string()),
            pre_shared_key_path: Some(PathBuf::from("psk")),
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("mutually exclusive")
        );
    }

    #[test]
    fn validate_rejects_empty_identity() {
        let config = SidecarCredentialsConfig {
            workspace_id: " ".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: Some("FIRMA_PSK".to_string()),
            pre_shared_key_path: None,
        };
        assert!(config.validate().unwrap_err().contains("workspace_id"));
    }

    #[test]
    fn file_resolution_trims_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("psk");
        std::fs::write(&path, "secret\n").unwrap();
        let config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: None,
            pre_shared_key_path: Some(path),
        };

        let resolved = config.resolve().unwrap();

        assert_eq!(resolved.pre_shared_key.expose_secret(), "secret");
        assert!(matches!(resolved.source, SidecarCredentialSource::File(_)));
    }

    #[test]
    fn file_resolution_rejects_missing_file() {
        let config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: None,
            pre_shared_key_path: Some(PathBuf::from("/no/such/firma/psk")),
        };

        assert!(
            config
                .resolve()
                .unwrap_err()
                .contains("read pre-shared key file")
        );
    }

    #[test]
    fn rebase_defaults_rebases_relative_path() {
        let mut config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: None,
            pre_shared_key_path: Some(PathBuf::from("secrets/psk")),
        };

        config.rebase_defaults(Path::new("/etc/firma"));

        assert_eq!(
            config.pre_shared_key_path.as_deref(),
            Some(Path::new("/etc/firma/secrets/psk"))
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let secret = RedactedPreSharedKey("secret-value".to_string());

        let rendered = format!("{secret:?}");

        assert!(rendered.contains("RedactedPreSharedKey"));
        assert!(!rendered.contains("secret-value"));
    }
}
