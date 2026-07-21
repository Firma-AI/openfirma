//! Authority stream client configuration.

use std::path::PathBuf;

use firma_core::AgentId;
use serde::Deserialize;

use crate::authority_credentials::SidecarCredentialsConfig;

/// Tuning for background Authority stream clients.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorityConfig {
    /// Authority-registered `TypeID` for the agent represented by this Sidecar.
    #[serde(default)]
    pub agent_id: Option<AgentId>,
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`). When set, the
    /// sidecar streams policy bundles and revocations from the Authority.
    #[serde(default)]
    pub url: Option<String>,
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
    /// Path to the Authority's PASETO v4 Ed25519 public key (32 raw
    /// bytes, as written by `firma-authority generate-key`). Required
    /// when `[capability_seed].paths` is non-empty so the sidecar can
    /// verify the seed signatures.
    #[serde(default)]
    pub public_key_path: Option<PathBuf>,
    /// Path to the PEM-encoded CA certificate used to verify the Authority's
    /// TLS certificate.
    ///
    /// Requirement is context-dependent and enforced in `SidecarConfig::validate`:
    /// required for `https://` authority URLs, optional for loopback `http://`.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Allow an insecure plain `http://` authority URL to a non-loopback
    /// host. Defaults to `false` (secure-by-default).
    #[serde(default)]
    pub allow_insecure_remote_authority: bool,
    /// Path to the PEM-encoded mTLS client certificate presented to the
    /// Authority during the TLS handshake. Required when the Authority is
    /// configured with `mtls_client_ca_cert_path`. Must be set together
    /// with `tls_client_key_path` or not at all.
    #[serde(default)]
    pub tls_client_cert_path: Option<PathBuf>,
    /// Path to the PEM-encoded mTLS client private key. Must be set
    /// together with `tls_client_cert_path` or not at all.
    #[serde(default)]
    pub tls_client_key_path: Option<PathBuf>,
    /// Credentials presented on each outbound Authority RPC.
    #[serde(default)]
    pub credentials: Option<SidecarCredentialsConfig>,
}

impl AuthorityConfig {
    /// Validate authority client tuning.
    ///
    /// # Errors
    ///
    /// Returns a human-readable field error for invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref url) = self.url
            && url.trim().is_empty()
        {
            return Err("url must not be empty when set".into());
        }
        if self.connect_timeout_secs == 0 {
            return Err("connect_timeout_secs must be > 0".to_string());
        }
        if self.reconnect_min_backoff_ms == 0 {
            return Err("reconnect_min_backoff_ms must be > 0".to_string());
        }
        if self.reconnect_max_backoff_secs == 0 {
            return Err("reconnect_max_backoff_secs must be > 0".to_string());
        }
        let max_backoff_ms = self.reconnect_max_backoff_secs.saturating_mul(1000);
        if max_backoff_ms < self.reconnect_min_backoff_ms {
            return Err(
                "reconnect_max_backoff_secs must be >= reconnect_min_backoff_ms".to_string(),
            );
        }
        if let Some(ref p) = self.public_key_path
            && p.as_os_str().is_empty()
        {
            return Err("public_key_path must not be empty when set".to_string());
        }
        if let Some(ref p) = self.ca_cert_path
            && p.as_os_str().is_empty()
        {
            return Err("ca_cert_path must not be empty when set".to_string());
        }
        if self.tls_client_cert_path.is_some() != self.tls_client_key_path.is_some() {
            return Err(
                "tls_client_cert_path and tls_client_key_path must both be set or both be unset"
                    .to_string(),
            );
        }
        if let Some(ref p) = self.tls_client_cert_path
            && p.as_os_str().is_empty()
        {
            return Err("tls_client_cert_path must not be empty when set".to_string());
        }
        if let Some(ref p) = self.tls_client_key_path
            && p.as_os_str().is_empty()
        {
            return Err("tls_client_key_path must not be empty when set".to_string());
        }
        if let Some(ref credentials) = self.credentials {
            credentials
                .validate()
                .map_err(|error| format!("credentials: {error}"))?;
        }
        Ok(())
    }
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            agent_id: None,
            url: None,
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
