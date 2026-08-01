//! Audit emitter configuration.

use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;

/// Audit event output sink selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSink {
    /// Structured JSON lines written to stdout (default for containers).
    #[default]
    Stdout,
    /// Append-only file sink.
    File,
    /// Streaming gRPC sink to a downstream audit service.
    Grpc,
    /// Write-ahead log: buffers events locally when gRPC is
    /// unavailable and replays on reconnect.
    Wal,
}

impl fmt::Display for AuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => write!(f, "stdout"),
            Self::File => write!(f, "file"),
            Self::Grpc => write!(f, "grpc"),
            Self::Wal => write!(f, "wal"),
        }
    }
}

/// Audit emitter configuration.
///
/// Controls where enforcement events are written and how they are
/// signed.
///
/// | Sink   | Required fields                                    |
/// |--------|----------------------------------------------------|
/// | `stdout` | none                                             |
/// | `file`   | `file_path`                                      |
/// | `grpc`   | `grpc_url`                                       |
/// | `wal`    | `grpc_url`, `wal_path`                            |
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    /// Output sink. Default: `stdout`.
    #[serde(default)]
    pub(crate) sink: AuditSink,
    /// Path for the `file` sink. Ignored by other sinks.
    #[serde(default)]
    pub(crate) file_path: Option<PathBuf>,
    /// Downstream audit service URL for `grpc` and `wal` sinks.
    #[serde(default)]
    pub(crate) grpc_url: Option<String>,
    /// Local WAL directory for the `wal` sink.
    #[serde(default)]
    pub(crate) wal_path: Option<PathBuf>,
    /// Maximum WAL size in bytes. Default: 100 MiB.
    #[serde(default = "default_wal_max_bytes")]
    pub(crate) wal_max_bytes: u64,
    /// Path to the ECDSA private key used for event signing.
    /// Mutually exclusive with `signing_key_env`.
    #[serde(default)]
    pub(crate) signing_key_path: Option<PathBuf>,
    /// Environment variable containing the ECDSA private key (PEM).
    /// Mutually exclusive with `signing_key_path`.
    #[serde(default)]
    pub(crate) signing_key_env: Option<String>,
    /// Additional query parameter names to redact in audit logs.
    /// Case-insensitive. Extends the built-in deny-list:
    /// `api_key`, `apikey`, `key`, `token`, `access_token`,
    /// `refresh_token`, `auth`, `password`, `secret`, `signature`,
    /// `sig`, `sas`.
    #[serde(default)]
    pub(crate) redact_query_params: Vec<String>,
}

impl AuditConfig {
    /// Validate the audit configuration.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the first invalid
    /// field.
    pub(crate) fn validate(&self) -> Result<(), String> {
        match self.sink {
            AuditSink::File => match &self.file_path {
                Some(p) if p.as_os_str().is_empty() => {
                    return Err("file_path must not be empty when sink is file".into());
                }
                None => {
                    return Err("file_path is required when sink is file".into());
                }
                _ => {}
            },
            AuditSink::Grpc => {
                Self::validate_grpc_url(self.grpc_url.as_ref())?;
            }
            AuditSink::Wal => {
                Self::validate_grpc_url(self.grpc_url.as_ref())?;
                match &self.wal_path {
                    Some(p) if p.as_os_str().is_empty() => {
                        return Err("wal_path must not be empty when sink is wal".into());
                    }
                    None => {
                        return Err("wal_path is required when sink is wal".into());
                    }
                    _ => {}
                }
                if self.wal_max_bytes == 0 {
                    return Err("wal_max_bytes must be > 0".into());
                }
            }
            AuditSink::Stdout => {}
        }

        if self.signing_key_path.is_some() && self.signing_key_env.is_some() {
            return Err("signing_key_path and signing_key_env are mutually exclusive".into());
        }
        if let Some(ref p) = self.signing_key_path
            && p.as_os_str().is_empty()
        {
            return Err("signing_key_path must not be empty when set".into());
        }
        if let Some(ref v) = self.signing_key_env
            && v.trim().is_empty()
        {
            return Err("signing_key_env must not be empty when set".into());
        }

        Ok(())
    }

    fn validate_grpc_url(url: Option<&String>) -> Result<(), String> {
        match url {
            Some(u) if u.trim().is_empty() => {
                Err("grpc_url must not be empty when sink is grpc or wal".into())
            }
            None => Err("grpc_url is required when sink is grpc or wal".into()),
            _ => Ok(()),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sink: AuditSink::default(),
            file_path: None,
            grpc_url: None,
            wal_path: None,
            wal_max_bytes: default_wal_max_bytes(),
            signing_key_path: None,
            signing_key_env: None,
            redact_query_params: Vec::new(),
        }
    }
}

/// 100 MiB default WAL cap.
const fn default_wal_max_bytes() -> u64 {
    100 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_config_defaults_valid() {
        let config = AuditConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_audit_file_sink_requires_file_path() {
        let config = AuditConfig {
            sink: AuditSink::File,
            file_path: None,
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("file_path"),
            "error should mention file_path: {err}"
        );
    }

    #[test]
    fn test_audit_file_sink_rejects_empty_path() {
        let config = AuditConfig {
            sink: AuditSink::File,
            file_path: Some(PathBuf::new()),
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("file_path"),
            "error should mention file_path: {err}"
        );
    }

    #[test]
    fn test_audit_file_sink_valid() {
        let config = AuditConfig {
            sink: AuditSink::File,
            file_path: Some(PathBuf::from("/var/log/audit.jsonl")),
            ..AuditConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_audit_grpc_sink_requires_grpc_url() {
        let config = AuditConfig {
            sink: AuditSink::Grpc,
            grpc_url: None,
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("grpc_url"),
            "error should mention grpc_url: {err}"
        );
    }

    #[test]
    fn test_audit_grpc_sink_valid() {
        let config = AuditConfig {
            sink: AuditSink::Grpc,
            grpc_url: Some("https://audit.example.com".into()),
            ..AuditConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_audit_wal_sink_requires_grpc_url_and_wal_path() {
        let config = AuditConfig {
            sink: AuditSink::Wal,
            grpc_url: None,
            wal_path: None,
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("grpc_url"),
            "error should mention grpc_url: {err}"
        );

        let config = AuditConfig {
            sink: AuditSink::Wal,
            grpc_url: Some("https://audit.example.com".into()),
            wal_path: None,
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("wal_path"),
            "error should mention wal_path: {err}"
        );
    }

    #[test]
    fn test_audit_wal_sink_rejects_zero_max_bytes() {
        let config = AuditConfig {
            sink: AuditSink::Wal,
            grpc_url: Some("https://audit.example.com".into()),
            wal_path: Some(PathBuf::from("/var/lib/firma/wal")),
            wal_max_bytes: 0,
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("wal_max_bytes"),
            "error should mention wal_max_bytes: {err}"
        );
    }

    #[test]
    fn test_audit_wal_sink_valid() {
        let config = AuditConfig {
            sink: AuditSink::Wal,
            grpc_url: Some("https://audit.example.com".into()),
            wal_path: Some(PathBuf::from("/var/lib/firma/wal")),
            ..AuditConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_audit_signing_key_mutual_exclusion() {
        let config = AuditConfig {
            signing_key_path: Some(PathBuf::from("/etc/firma/audit.pem")),
            signing_key_env: Some("FIRMA_AUDIT_KEY".into()),
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("mutually exclusive"),
            "error should mention mutual exclusion: {err}"
        );
    }

    #[test]
    fn test_audit_signing_key_path_rejects_empty() {
        let config = AuditConfig {
            signing_key_path: Some(PathBuf::new()),
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("signing_key_path"),
            "error should mention signing_key_path: {err}"
        );
    }

    #[test]
    fn test_audit_signing_key_env_rejects_empty() {
        let config = AuditConfig {
            signing_key_env: Some("  ".into()),
            ..AuditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("signing_key_env"),
            "error should mention signing_key_env: {err}"
        );
    }
}
