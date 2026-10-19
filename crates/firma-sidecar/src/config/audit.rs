//! Audit emitter configuration.

use std::path::PathBuf;

use firma_config_schema::sidecar::audit::{
    AuditConfig as SchemaAuditConfig, AuditSink as SchemaAuditSink,
};
use firma_config_utils::NonZeroDuration;
use hyper::Uri;

/// Validated audit emitter configuration.
///
/// | Sink     | Required fields           | Filled from the state directory |
/// |----------|---------------------------|---------------------------------|
/// | `stdout` | none                      | signing key                     |
/// | `file`   | none                      | signing key, `file_path`        |
/// | `grpc`   | `grpc_url`, `buffer_path` | signing key                     |
/// | `wal`    | `grpc_url`, `wal_path`    | signing key                     |
///
/// Every path here is already resolved: this type is only ever built by
/// [`SidecarConfig::resolve`](crate::config::SidecarConfig::resolve), which
/// fills in the state-directory defaults for whatever the config left unset.
/// `buffer_path` is the exception: the `grpc` sink is durable, so the operator
/// has to say where it buffers.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Output sink. Default: `stdout`.
    pub(crate) sink: SchemaAuditSink,
    /// Resolved path for the `file` sink; `None` for every other sink.
    pub(crate) file_path: Option<PathBuf>,
    /// Downstream audit service URL for the `grpc` sink.
    pub(crate) grpc_url: Option<String>,
    /// Local buffer file backing the `grpc` sink while the stream is down.
    pub(crate) buffer_path: Option<PathBuf>,
    /// Maximum size of the `grpc` sink's local buffer, in bytes.
    pub(crate) buffer_max_bytes: u64,
    /// How long the `grpc` sink waits for a replay acknowledgment.
    pub(crate) replay_ack_timeout: NonZeroDuration,
    /// Journal written before delivery; never shared with a buffered gRPC sink.
    pub(crate) wal_path: Option<PathBuf>,
    /// Maximum pending journal bytes, without oldest-event eviction.
    pub(crate) wal_max_bytes: u64,
    /// Bound on each `wal` sink delivery attempt.
    pub(crate) wal_request_timeout: NonZeroDuration,
    /// Resolved source of the ECDSA key events are signed with.
    pub(crate) signing_key: AuditSigningKey,
    /// Additional query parameter names to redact in audit logs.
    pub(crate) redact_query_params: Vec<String>,
}

/// Where the audit event-signing key comes from, after state-directory
/// resolution.
///
/// The variant is what tells a startup failure how to phrase its remedy:
/// "run `firma config`" is the right advice for a path nobody chose, and the
/// wrong advice for one the operator pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditSigningKey {
    /// `audit.signing_key_env`: the PEM is the value of this variable.
    Env(String),
    /// `audit.signing_key_path`: the operator pinned this file.
    Path(PathBuf),
    /// Neither was set, so the key is the one `firma config` generates in the
    /// state directory.
    StateDefault(PathBuf),
}

/// Error validating an [`AuditConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditConfigError {
    /// `file_path` was empty.
    #[error("audit.file_path must not be empty when sink is file")]
    EmptyFilePath,
    /// `grpc` sink was selected without a `grpc_url`.
    #[error("audit.grpc_url is required when sink is grpc")]
    GrpcUrlRequired,
    /// `grpc_url` was empty.
    #[error("audit.grpc_url must not be empty when sink is grpc")]
    EmptyGrpcUrl,
    /// `grpc_url` was not a valid URI.
    #[error("audit.grpc_url must be a valid URI: {0}")]
    InvalidGrpcUrl(String),
    /// `grpc_url` had no scheme.
    #[error("audit.grpc_url must include a scheme, e.g. http://host:port (got {0})")]
    GrpcUrlMissingScheme(String),
    /// `grpc_url` used a scheme the sink cannot dial.
    #[error("audit.grpc_url scheme must be http or https, got {0}")]
    GrpcUrlUnsupportedScheme(String),
    /// `grpc_url` had no host.
    #[error("audit.grpc_url must include a host (got {0})")]
    GrpcUrlMissingHost(String),
    /// `grpc` sink was selected without a `buffer_path`.
    ///
    /// Newly required: the `grpc` sink used to drop events whenever the
    /// stream was down, so it needed no local storage. It is now durable and
    /// needs somewhere to buffer, which makes this error the first thing a
    /// previously valid `grpc` config hits.
    #[error(
        "audit.buffer_path is required when sink is grpc: the grpc sink is now durable and buffers events to disk while the stream is down. Set buffer_path to a writable file path"
    )]
    BufferPathRequired,
    /// `buffer_path` was empty.
    #[error("audit.buffer_path must not be empty when sink is grpc")]
    EmptyBufferPath,
    /// `buffer_max_size` was zero.
    #[error("audit.buffer_max_size must be > 0")]
    ZeroBufferMaxBytes,
    /// `wal` was selected without a journal path.
    #[error("audit.wal_path is required when sink is wal")]
    WalPathRequired,
    /// `wal_path` was empty.
    #[error("audit.wal_path must not be empty when sink is wal")]
    EmptyWalPath,
    /// `wal_max_size` was zero.
    #[error("audit.wal_max_size must be > 0")]
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

impl AuditConfig {
    /// Validate `schema` and fill every unset path from `state`.
    ///
    /// An unset `file_path` or signing key is not a misconfiguration: both
    /// resolve to the artifacts `firma config` generates in the state
    /// directory, so a path-free config and a scaffolded one audit to the same
    /// files.
    ///
    /// # Errors
    ///
    /// Returns [`AuditConfigError`] when a field the selected sink requires is
    /// missing or empty.
    pub(crate) fn resolve(
        schema: SchemaAuditConfig,
        state: &firma_runtime_state::RuntimeLayout,
    ) -> Result<Self, AuditConfigError> {
        match schema.sink {
            SchemaAuditSink::File => {
                if let Some(p) = &schema.file_path
                    && p.as_os_str().is_empty()
                {
                    return Err(AuditConfigError::EmptyFilePath);
                }
            }
            SchemaAuditSink::Grpc => {
                validate_grpc_url(schema.grpc_url.as_ref())?;
                match &schema.buffer_path {
                    Some(p) if p.as_os_str().is_empty() => {
                        return Err(AuditConfigError::EmptyBufferPath);
                    }
                    None => return Err(AuditConfigError::BufferPathRequired),
                    _ => {}
                }
                if schema.buffer_max_size.as_u64() == 0 {
                    return Err(AuditConfigError::ZeroBufferMaxBytes);
                }
            }
            SchemaAuditSink::Stdout => {}
            SchemaAuditSink::Wal => {
                validate_grpc_url(schema.grpc_url.as_ref())?;
                match &schema.wal_path {
                    Some(path) if path.as_os_str().is_empty() => {
                        return Err(AuditConfigError::EmptyWalPath);
                    }
                    None => return Err(AuditConfigError::WalPathRequired),
                    _ => {}
                }
                if schema.wal_max_size.as_u64() == 0 {
                    return Err(AuditConfigError::ZeroWalMaxBytes);
                }
            }
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

        let signing_key = match (schema.signing_key_env, schema.signing_key_path) {
            (Some(variable), _) => AuditSigningKey::Env(variable),
            (None, Some(path)) => AuditSigningKey::Path(path),
            (None, None) => AuditSigningKey::StateDefault(state.audit_key()),
        };
        let file_path = match schema.sink {
            SchemaAuditSink::File => Some(schema.file_path.unwrap_or_else(|| state.audit_log())),
            SchemaAuditSink::Grpc | SchemaAuditSink::Wal | SchemaAuditSink::Stdout => None,
        };

        Ok(Self {
            sink: schema.sink,
            file_path,
            grpc_url: schema.grpc_url,
            buffer_path: schema.buffer_path,
            buffer_max_bytes: schema.buffer_max_size.as_u64(),
            replay_ack_timeout: schema.replay_ack_timeout,
            wal_path: schema.wal_path,
            wal_max_bytes: schema.wal_max_size.as_u64(),
            wal_request_timeout: schema.wal_request_timeout,
            signing_key,
            redact_query_params: schema.redact_query_params,
        })
    }
}

/// Validates `grpc_url` as an outbound gRPC origin.
///
/// The sink no longer dials at startup — an unreachable endpoint buffers and
/// retries — so a malformed URL has no other moment to be caught. Left to the
/// run loop it looks exactly like an outage: events pile up until compaction
/// starts dropping real ones. The rules match [`AuthorityEndpoint`], the other
/// outbound gRPC origin in this crate.
///
/// [`AuthorityEndpoint`]: crate::config::AuthorityEndpoint
fn validate_grpc_url(url: Option<&String>) -> Result<(), AuditConfigError> {
    let url = match url {
        Some(u) if u.trim().is_empty() => return Err(AuditConfigError::EmptyGrpcUrl),
        Some(u) => u,
        None => return Err(AuditConfigError::GrpcUrlRequired),
    };

    let uri = url
        .parse::<Uri>()
        .map_err(|error| AuditConfigError::InvalidGrpcUrl(error.to_string()))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| AuditConfigError::GrpcUrlMissingScheme(url.clone()))?;
    if !matches!(scheme, "http" | "https") {
        return Err(AuditConfigError::GrpcUrlUnsupportedScheme(
            scheme.to_string(),
        ));
    }
    if uri.host().is_none_or(str::is_empty) {
        return Err(AuditConfigError::GrpcUrlMissingHost(url.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> SchemaAuditConfig {
        SchemaAuditConfig::default()
    }

    /// A fixed state root: these cases are about validation, so the resolved
    /// defaults only need to be predictable.
    fn state() -> firma_runtime_state::RuntimeLayout {
        firma_runtime_state::RuntimeLayout::from_root("/state")
    }

    #[test]
    fn defaults_valid() {
        assert!(AuditConfig::resolve(schema(), &state()).is_ok());
    }

    /// The path is filled in at startup, so omitting it is the portable shape
    /// rather than an error.
    #[test]
    fn file_sink_accepts_an_unset_file_path() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::File,
            file_path: None,
            ..schema()
        };
        assert!(AuditConfig::resolve(s, &state()).is_ok());
    }

    #[test]
    fn file_sink_rejects_empty_path() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::File,
            file_path: Some(PathBuf::new()),
            ..schema()
        };
        assert!(matches!(
            AuditConfig::resolve(s, &state()),
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
        assert!(AuditConfig::resolve(s, &state()).is_ok());
    }

    #[test]
    fn grpc_sink_requires_grpc_url_and_buffer_path() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Grpc,
            grpc_url: None,
            buffer_path: None,
            ..schema()
        };
        assert!(matches!(
            AuditConfig::resolve(s, &state()),
            Err(AuditConfigError::GrpcUrlRequired)
        ));

        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Grpc,
            grpc_url: Some("https://audit.example.com".into()),
            buffer_path: None,
            ..schema()
        };
        let error =
            AuditConfig::resolve(s, &state()).expect_err("buffer_path is required for grpc");
        assert!(matches!(error, AuditConfigError::BufferPathRequired));
        // `buffer_path` is newly required, so the message has to explain the
        // change to operators whose previously valid grpc config now fails.
        assert_eq!(
            error.to_string(),
            "audit.buffer_path is required when sink is grpc: the grpc sink is now durable \
             and buffers events to disk while the stream is down. Set buffer_path to a \
             writable file path"
        );
    }

    /// The sink buffers and retries instead of dialing at startup, so a
    /// malformed URL is indistinguishable from an outage once it is running.
    #[test]
    fn grpc_sink_rejects_urls_it_could_never_dial() {
        let grpc = |url: &str| SchemaAuditConfig {
            sink: SchemaAuditSink::Grpc,
            grpc_url: Some(url.into()),
            buffer_path: Some(PathBuf::from("/var/lib/firma/audit-buffer.jsonl")),
            ..schema()
        };

        assert!(matches!(
            AuditConfig::resolve(grpc("audit.example.com:50051"), &state()),
            Err(AuditConfigError::GrpcUrlMissingScheme(_))
        ));
        assert!(matches!(
            AuditConfig::resolve(grpc("ftp://audit.example.com"), &state()),
            Err(AuditConfigError::GrpcUrlUnsupportedScheme(scheme)) if scheme == "ftp"
        ));
        // A Unix socket path is not a URI hyper can route at all.
        assert!(matches!(
            AuditConfig::resolve(grpc("unix:///var/run/audit.sock"), &state()),
            Err(AuditConfigError::InvalidGrpcUrl(_))
        ));
        assert!(matches!(
            AuditConfig::resolve(grpc("http://:0"), &state()),
            Err(AuditConfigError::GrpcUrlMissingHost(_))
        ));
        assert!(AuditConfig::resolve(grpc("http://audit.example.com:50051"), &state()).is_ok());
        assert!(AuditConfig::resolve(grpc("https://audit.example.com"), &state()).is_ok());
    }

    #[test]
    fn grpc_sink_rejects_zero_buffer_max_size() {
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Grpc,
            grpc_url: Some("https://audit.example.com".into()),
            buffer_path: Some(PathBuf::from("/var/lib/firma/audit-buffer.jsonl")),
            buffer_max_size: bytesize::ByteSize::b(0),
            ..schema()
        };
        assert!(matches!(
            AuditConfig::resolve(s, &state()),
            Err(AuditConfigError::ZeroBufferMaxBytes)
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
            AuditConfig::resolve(s, &state()),
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
            AuditConfig::resolve(s, &state()),
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
            AuditConfig::resolve(s, &state()),
            Err(AuditConfigError::EmptySigningKeyEnv)
        ));
    }

    #[test]
    fn grpc_sink_rejects_malformed_grpc_url() {
        // Startup never dials the collector (the first connect runs on the
        // run loop so early events buffer instead of blocking), so a typo'd
        // URL would otherwise surface only as endless buffering while the
        // local buffer fills and compacts real events away. Reject it here.
        let s = SchemaAuditConfig {
            sink: SchemaAuditSink::Grpc,
            grpc_url: Some("ht!tp://[not a url".into()),
            buffer_path: Some(PathBuf::from("/var/lib/firma/audit-buffer.jsonl")),
            ..schema()
        };
        assert!(
            AuditConfig::resolve(s, &state()).is_err(),
            "a grpc_url no gRPC client could dial must fail validation"
        );
    }
}
