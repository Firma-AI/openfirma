//! Schema for `[sidecar.audit]`.
//!
//! Representation only. `firma-sidecar` validates the sink-specific required
//! fields and the signing-key source.

use std::fmt;
use std::path::PathBuf;

use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

/// Audit event output sink selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSink {
    /// Structured JSON lines written to stdout (default for containers).
    #[default]
    Stdout,
    /// Append-only file sink.
    File,
    /// Streaming gRPC sink to a downstream audit service.
    Grpc,
    /// Write-ahead log: buffers events locally when gRPC is unavailable and
    /// replays on reconnect.
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
/// | Sink   | Required fields          |
/// |--------|--------------------------|
/// | `stdout` | none                   |
/// | `file`   | `file_path`            |
/// | `grpc`   | `grpc_url`             |
/// | `wal`    | `grpc_url`, `wal_path` |
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Output sink. Default: `stdout`.
    #[serde(default)]
    pub sink: AuditSink,
    /// Path for the `file` sink. Ignored by other sinks.
    #[serde(default)]
    pub file_path: Option<PathBuf>,
    /// Downstream audit service URL for `grpc` and `wal` sinks.
    #[serde(default)]
    pub grpc_url: Option<String>,
    /// Local WAL directory for the `wal` sink.
    #[serde(default)]
    pub wal_path: Option<PathBuf>,
    /// Maximum WAL size. Default: 100 MiB.
    #[serde(
        deserialize_with = "crate::utils::byte_size::deserialize",
        default = "default_wal_max_size"
    )]
    pub wal_max_size: ByteSize,
    /// Path to the ECDSA private key used for event signing. Mutually
    /// exclusive with `signing_key_env`.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,
    /// Environment variable containing the ECDSA private key (PEM). Mutually
    /// exclusive with `signing_key_path`.
    #[serde(default)]
    pub signing_key_env: Option<String>,
    /// Additional query parameter names to redact in audit logs.
    #[serde(default)]
    pub redact_query_params: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sink: AuditSink::default(),
            file_path: None,
            grpc_url: None,
            wal_path: None,
            wal_max_size: default_wal_max_size(),
            signing_key_path: None,
            signing_key_env: None,
            redact_query_params: Vec::new(),
        }
    }
}

/// 100 MiB default WAL cap.
const fn default_wal_max_size() -> ByteSize {
    ByteSize::mib(100)
}
