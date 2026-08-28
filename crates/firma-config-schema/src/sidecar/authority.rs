//! Schema for `[sidecar.authority]` and its `[sidecar.authority.credentials]`.
//!
//! Representation only. `firma-sidecar` validates these values, parses the
//! `url` into an endpoint, and resolves the pre-shared-key source.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Sidecar pre-shared-key credentials presented to Authority RPCs.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SidecarCredentials {
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

/// Tuning for background Authority stream clients.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    /// Authority-registered `TypeID` for the agent represented by this Sidecar.
    /// Accepted for configuration compatibility; parsed by `firma-sidecar`.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`). When set, the
    /// sidecar streams policy bundles and revocations from the Authority.
    #[serde(default)]
    pub url: Option<String>,
    /// Optional physical TCP destination for the Authority connection.
    #[serde(default)]
    pub connect_addr: Option<SocketAddr>,
    /// Connection timeout in seconds.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// Minimum reconnect backoff in milliseconds.
    #[serde(default = "default_min_backoff_ms")]
    pub reconnect_min_backoff_ms: u64,
    /// Maximum reconnect backoff in seconds.
    #[serde(default = "default_max_backoff_secs")]
    pub reconnect_max_backoff_secs: u64,
    /// Grace period before the revocation stream is considered ready.
    #[serde(default = "default_readiness_grace_ms")]
    pub revocation_readiness_grace_ms: u64,
    /// Flip revocation readiness back to false on disconnect.
    #[serde(default)]
    pub revocation_fail_closed_on_disconnect: bool,
    /// Path to the Authority's PASETO v4 Ed25519 public key.
    #[serde(default)]
    pub public_key_path: Option<PathBuf>,
    /// Path to the PEM-encoded CA certificate used to verify the Authority's
    /// TLS certificate.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Allow an insecure plain `http://` authority URL to a non-loopback host.
    #[serde(default)]
    pub allow_insecure_remote_authority: bool,
    /// Path to the PEM-encoded mTLS client certificate presented to the
    /// Authority. Must be set together with `tls_client_key_path` or not at all.
    #[serde(default)]
    pub tls_client_cert_path: Option<PathBuf>,
    /// Path to the PEM-encoded mTLS client private key. Must be set together
    /// with `tls_client_cert_path` or not at all.
    #[serde(default)]
    pub tls_client_key_path: Option<PathBuf>,
    /// Credentials presented on each outbound Authority RPC.
    #[serde(default)]
    pub credentials: Option<SidecarCredentials>,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            agent_id: None,
            url: None,
            connect_addr: None,
            connect_timeout_secs: default_connect_timeout_secs(),
            reconnect_min_backoff_ms: default_min_backoff_ms(),
            reconnect_max_backoff_secs: default_max_backoff_secs(),
            revocation_readiness_grace_ms: default_readiness_grace_ms(),
            revocation_fail_closed_on_disconnect: false,
            public_key_path: None,
            ca_cert_path: None,
            allow_insecure_remote_authority: false,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            credentials: None,
        }
    }
}

const fn default_connect_timeout_secs() -> u64 {
    10
}

const fn default_min_backoff_ms() -> u64 {
    250
}

const fn default_max_backoff_secs() -> u64 {
    30
}

const fn default_readiness_grace_ms() -> u64 {
    500
}
