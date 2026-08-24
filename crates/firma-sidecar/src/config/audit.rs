//! Audit emitter configuration.

use std::path::PathBuf;

use firma_config_schema::sidecar::audit::{
    AuditConfig as SchemaAuditConfig, AuditSink as SchemaAuditSink,
};

/// Validated audit emitter configuration.
///
/// | Sink   | Required fields          |
/// |--------|--------------------------|
/// | `stdout` | none                   |
/// | `file`   | `file_path`            |
/// | `grpc`   | `grpc_url`             |
/// | `wal`    | `grpc_url`, `wal_path` |
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Output sink. Default: `stdout`.
    pub(crate) sink: SchemaAuditSink,
    /// Path for the `file` sink.
    pub(crate) file_path: Option<PathBuf>,
    /// Downstream audit service URL for `grpc` and `wal` sinks.
    pub(crate) grpc_url: Option<String>,
    /// Local WAL directory for the `wal` sink.
    pub(crate) wal_path: Option<PathBuf>,
    /// Maximum WAL size in bytes.
    pub(crate) wal_max_bytes: u64,
    /// Path to the ECDSA private key used for event signing.
    pub(crate) signing_key_path: Option<PathBuf>,
    /// Environment variable containing the ECDSA private key (PEM).
    pub(crate) signing_key_env: Option<String>,
    /// Additional query parameter names to redact in audit logs.
    pub(crate) redact_query_params: Vec<String>,
}

/// Error validating an [`AuditConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditConfigError {
    /// `file` sink was selected without a `file_path`.
    #[error("audit.file_path is required when sink is file")]
    FileSinkRequiresPath,
    /// `file_path` was empty.
    #[error("audit.file_path must not be empty when sink is file")]
    EmptyFilePath,
    /// `grpc`/`wal` sink was selected without a `grpc_url`.
    #[error("audit.grpc_url is required when sink is grpc or wal")]
    GrpcUrlRequired,
    /// `grpc_url` was empty.
    #[error("audit.grpc_url must not be empty when sink is grpc or wal")]
    EmptyGrpcUrl,
    /// `wal` sink was selected without a `wal_path`.
    #[error("audit.wal_path is required when sink is wal")]
    WalPathRequired,
    /// `wal_path` was empty.
    #[error("audit.wal_path must not be empty when sink is wal")]
    EmptyWalPath,
    /// `wal_max_bytes` was zero.
    #[error("audit.wal_max_bytes must be > 0")]
    ZeroWalMaxBytes,
    /// Both signing-key sources were set.
    #[error("audit.signing_key_path and audit.signing_key_env are mutually exclusive")]
    SigningKeyMutuallyExclusive,
    /// `signing_key_path` was empty.
    #[error("audit.signing_key_path must not be empty when set")]
    EmptySigningKeyPath,
    /// `signing_key_env` was empty.
    #[error("audit.signing_key_env must not be empty when set")]
    EmptySigningKeyEnv,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sink: SchemaAuditSink::default(),
            file_path: None,
            grpc_url: None,
            wal_path: None,
            wal_max_bytes: 100 * 1024 * 1024,
            signing_key_path: None,
            signing_key_env: None,
            redact_query_params: Vec::new(),
        }
    }
}

impl TryFrom<SchemaAuditConfig> for AuditConfig {
    type Error = AuditConfigError;

    fn try_from(schema: SchemaAuditConfig) -> Result<Self, Self::Error> {
        match schema.sink {
            SchemaAuditSink::File => match &schema.file_path {
                Some(p) if p.as_os_str().is_empty() => {
                    return Err(AuditConfigError::EmptyFilePath);
                }
                None => return Err(AuditConfigError::FileSinkRequiresPath),
                _ => {}
            },
            SchemaAuditSink::Grpc => validate_grpc_url(schema.grpc_url.as_ref())?,
            SchemaAuditSink::Wal => {
                validate_grpc_url(schema.grpc_url.as_ref())?;
                match &schema.wal_path {
                    Some(p) if p.as_os_str().is_empty() => {
                        return Err(AuditConfigError::EmptyWalPath);
                    }
                    None => return Err(AuditConfigError::WalPathRequired),
                    _ => {}
                }
                if schema.wal_max_bytes == 0 {
                    return Err(AuditConfigError::ZeroWalMaxBytes);
                }
            }
            SchemaAuditSink::Stdout => {}
        }

        if schema.signing_key_path.is_some() && schema.signing_key_env.is_some() {
            return Err(AuditConfigError::SigningKeyMutuallyExclusive);
        }
        if let Some(ref p) = schema.signing_key_path
            && p.as_os_str().is_empty()
        {
            return Err(AuditConfigError::EmptySigningKeyPath);
        }
        if let Some(ref v) = schema.signing_key_env
            && v.trim().is_empty()
        {
            return Err(AuditConfigError::EmptySigningKeyEnv);
        }

        Ok(Self {
            sink: schema.sink,
            file_path: schema.file_path,
            grpc_url: schema.grpc_url,
            wal_path: schema.wal_path,
            wal_max_bytes: schema.wal_max_bytes,
            signing_key_path: schema.signing_key_path,
            signing_key_env: schema.signing_key_env,
            redact_query_params: schema.redact_query_params,
        })
    }
}

fn validate_grpc_url(url: Option<&String>) -> Result<(), AuditConfigError> {
    match url {
        Some(u) if u.trim().is_empty() => Err(AuditConfigError::EmptyGrpcUrl),
        None => Err(AuditConfigError::GrpcUrlRequired),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> SchemaAuditConfig {
        SchemaAuditConfig::default()
    }

    #[test]
    fn defaults_valid() {
        assert!(AuditConfig::try_from(schema()).is_ok());
    }

    #[test]
    fn file_sink_requires_file_path() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::File,
            file_path: None,
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::FileSinkRequiresPath)
        ));
    }

    #[test]
    fn file_sink_rejects_empty_path() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::File,
            file_path: Some(PathBuf::new()),
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::EmptyFilePath)
        ));
    }

    #[test]
    fn file_sink_valid() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::File,
            file_path: Some(PathBuf::from("/var/log/audit.jsonl")),
            ..schema()
        };
        assert!(AuditConfig::try_from(s).is_ok());
    }

    #[test]
    fn grpc_sink_requires_grpc_url() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Grpc,
            grpc_url: None,
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::GrpcUrlRequired)
        ));
    }

    #[test]
    fn wal_sink_requires_grpc_url_and_wal_path() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Wal,
            grpc_url: None,
            wal_path: None,
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::GrpcUrlRequired)
        ));

        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Wal,
            grpc_url: Some("https://audit.example.com".into()),
            wal_path: None,
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::WalPathRequired)
        ));
    }

    #[test]
    fn wal_sink_rejects_zero_max_bytes() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Wal,
            grpc_url: Some("https://audit.example.com".into()),
            wal_path: Some(PathBuf::from("/var/lib/firma/wal")),
            wal_max_bytes: 0,
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::ZeroWalMaxBytes)
        ));
    }

    #[test]
    fn signing_key_mutual_exclusion() {
        let s = SchemaAuditConfig {
            signing_key_path: Some(PathBuf::from("/etc/firma/audit.pem")),
            signing_key_env: Some("FIRMA_AUDIT_KEY".into()),
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::SigningKeyMutuallyExclusive)
        ));
    }

    #[test]
    fn signing_key_path_rejects_empty() {
        let s = SchemaAuditConfig {
            signing_key_path: Some(PathBuf::new()),
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::EmptySigningKeyPath)
        ));
    }

    #[test]
    fn signing_key_env_rejects_empty() {
        let s = SchemaAuditConfig {
            signing_key_env: Some("  ".into()),
            ..schema()
        };
        assert!(matches!(
            AuditConfig::try_from(s),
            Err(AuditConfigError::EmptySigningKeyEnv)
        ));
    }
}
