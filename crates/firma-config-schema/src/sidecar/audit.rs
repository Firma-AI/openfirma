//! Schema for `[sidecar.audit]`.
//!
//! Representation only. `firma-sidecar` validates the sink-specific required
//! fields and the signing-key source.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use bytesize::ByteSize;
use firma_config_utils::NonZeroDuration;
use serde::{Deserialize, Serialize};

const DEFAULT_REPLAY_ACK_TIMEOUT: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(30));
const DEFAULT_WAL_REQUEST_TIMEOUT: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(5));

/// Audit event output sink selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSink {
    /// Structured JSON lines written to stdout (default for containers).
    #[default]
    Stdout,
    /// Append-only file sink.
    File,
    /// Durable streaming gRPC sink to a downstream audit service. Buffers
    /// events to a local file while the stream is unavailable and replays
    /// them on reconnect.
    Grpc,
    /// Journal before delivery; reclaim only after a committed receipt or
    /// durable rejection archival. Capacity exhaustion never evicts records.
    Wal,
}

impl AuditSink {
    /// Every sink, so callers can enumerate the accepted values.
    ///
    /// The array length makes adding a variant a compile error here, which
    /// is the reminder to extend [`AuditSink::deserialize`] — a hand-written
    /// impl the compiler cannot otherwise keep in step with the derived
    /// [`Serialize`].
    pub const ALL: [Self; 4] = [Self::Stdout, Self::File, Self::Grpc, Self::Wal];

    /// The wire token for this sink, matching the `snake_case` rename used
    /// by [`Serialize`].
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::File => "file",
            Self::Grpc => "grpc",
            Self::Wal => "wal",
        }
    }
}

impl fmt::Display for AuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lists supported sink tokens explicitly when a configuration is invalid.
impl<'de> Deserialize<'de> for AuditSink {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if let Some(sink) = Self::ALL.into_iter().find(|s| s.as_str() == value) {
            return Ok(sink);
        }
        let accepted = Self::ALL.map(|s| format!("`{s}`")).join(", ");
        Err(serde::de::Error::custom(format!(
            "unknown audit.sink `{value}`: expected one of {accepted}"
        )))
    }
}

/// Audit emitter configuration.
///
/// | Sink     | Required fields            |
/// |----------|----------------------------|
/// | `stdout` | none                       |
/// | `file`   | `file_path`                |
/// | `grpc`   | `grpc_url`, `buffer_path`  |
/// | `wal`    | `grpc_url`, `wal_path`     |
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Output sink. Default: `stdout`.
    #[serde(default)]
    pub sink: AuditSink,
    /// Path for the `file` sink. Ignored by other sinks.
    #[serde(default)]
    pub file_path: Option<PathBuf>,
    /// Downstream audit service URL for the `grpc` sink.
    #[serde(default)]
    pub grpc_url: Option<String>,
    /// Local buffer file backing the `grpc` sink while the stream is
    /// unavailable.
    #[serde(default)]
    pub buffer_path: Option<PathBuf>,
    /// Maximum size of the `grpc` sink's local buffer. Default: 100 MiB.
    #[serde(with = "crate::utils::byte_size", default = "default_buffer_max_size")]
    pub buffer_max_size: ByteSize,
    /// How long the `grpc` sink waits for the audit service to acknowledge a
    /// buffer replay. Default: 30 s.
    #[serde(default = "default_replay_ack_timeout")]
    pub replay_ack_timeout: NonZeroDuration,
    /// Local WAL file; sibling files retain destination scope and rejections.
    #[serde(default)]
    pub wal_path: Option<PathBuf>,
    /// Maximum pending WAL size. Exhaustion stops the sink without eviction.
    /// Rejection archives require separate operator management.
    #[serde(with = "crate::utils::byte_size", default = "default_buffer_max_size")]
    pub wal_max_size: ByteSize,
    /// Bound on each `wal` sink delivery attempt: connecting, sending, and
    /// waiting for the audit service to commit. Default: 5 s.
    #[serde(default = "default_wal_request_timeout")]
    pub wal_request_timeout: NonZeroDuration,
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
            buffer_path: None,
            buffer_max_size: default_buffer_max_size(),
            replay_ack_timeout: default_replay_ack_timeout(),
            wal_path: None,
            wal_max_size: default_buffer_max_size(),
            wal_request_timeout: default_wal_request_timeout(),
            signing_key_path: None,
            signing_key_env: None,
            redact_query_params: Vec::new(),
        }
    }
}

/// 100 MiB default cap on the `grpc` sink's local buffer.
const fn default_buffer_max_size() -> ByteSize {
    ByteSize::mib(100)
}

const fn default_replay_ack_timeout() -> NonZeroDuration {
    DEFAULT_REPLAY_ACK_TIMEOUT
}

const fn default_wal_request_timeout() -> NonZeroDuration {
    DEFAULT_WAL_REQUEST_TIMEOUT
}
