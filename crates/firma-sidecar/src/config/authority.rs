//! Authority stream client configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use firma_identifiers::AgentId;
use hyper::Uri;
use serde::Deserialize;

use super::AuthorityTarget;
use crate::authority_credentials::SidecarCredentialsConfig;

/// A validated Authority destination.
///
/// The URI is the logical HTTP and TLS origin. The optional socket address is
/// only the physical TCP route and does not change HTTP authority or TLS
/// server-name verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityEndpoint {
    origin: Uri,
    connect_addr: Option<SocketAddr>,
}

impl AuthorityEndpoint {
    /// Validate and construct an Authority endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityEndpointError`] when the logical origin or physical
    /// route is not suitable for an outbound Authority connection.
    pub fn new(
        url: &str,
        connect_addr: Option<SocketAddr>,
    ) -> Result<Self, AuthorityEndpointError> {
        if url.trim().is_empty() {
            return Err(AuthorityEndpointError::EmptyUrl);
        }
        let origin = url
            .parse::<Uri>()
            .map_err(|error| AuthorityEndpointError::InvalidUrl(error.to_string()))?;
        let scheme = origin
            .scheme_str()
            .ok_or(AuthorityEndpointError::MissingScheme)?;
        if !matches!(scheme, "http" | "https") {
            return Err(AuthorityEndpointError::UnsupportedScheme(
                scheme.to_string(),
            ));
        }
        if origin.host().is_none_or(str::is_empty) {
            return Err(AuthorityEndpointError::MissingHost);
        }
        if let Some(address) = connect_addr {
            if address.port() == 0 {
                return Err(AuthorityEndpointError::ZeroPhysicalPort);
            }
            if address.ip().is_unspecified() {
                return Err(AuthorityEndpointError::UnspecifiedPhysicalIp);
            }
        }
        Ok(Self {
            origin,
            connect_addr,
        })
    }

    /// Return the logical HTTP and TLS origin.
    #[must_use]
    pub(crate) const fn origin(&self) -> &Uri {
        &self.origin
    }

    /// Return the optional physical TCP route.
    #[must_use]
    pub(crate) const fn connect_addr(&self) -> Option<SocketAddr> {
        self.connect_addr
    }

    /// Return whether the logical origin uses HTTPS.
    #[must_use]
    pub(crate) fn is_https(&self) -> bool {
        self.origin.scheme_str() == Some("https")
    }
}

/// Error constructing an [`AuthorityEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityEndpointError {
    /// The configured URL is empty.
    #[error("url must not be empty when set")]
    EmptyUrl,
    /// The configured URL is not a valid URI.
    #[error("url must be a valid URI: {0}")]
    InvalidUrl(String),
    /// A physical route was configured without a logical origin.
    #[error("connect_addr requires url to be set")]
    ConnectAddrWithoutUrl,
    /// The configured URL has no scheme.
    #[error("url must include a scheme")]
    MissingScheme,
    /// The configured URL has no host.
    #[error("url must include a host")]
    MissingHost,
    /// The configured URL does not use HTTP or HTTPS.
    #[error("url scheme must be http or https, got {0}")]
    UnsupportedScheme(String),
    /// The physical route uses port zero.
    #[error("connect_addr port must be > 0")]
    ZeroPhysicalPort,
    /// The physical route uses an unspecified IP address.
    #[error("connect_addr IP must not be unspecified")]
    UnspecifiedPhysicalIp,
}

/// Tuning for background Authority stream clients.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorityConfig {
    /// Authority-registered `TypeID` for the agent represented by this Sidecar.
    #[serde(default)]
    #[expect(dead_code, reason = "accepted for configuration compatibility")]
    pub(crate) agent_id: Option<AgentId>,
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`). When set, the
    /// sidecar streams policy bundles and revocations from the Authority.
    #[serde(default)]
    pub url: Option<String>,
    /// Optional physical TCP destination for the Authority connection.
    ///
    /// `url` remains the logical HTTP and TLS origin. This override is useful
    /// when a composition layer discovers the Authority's endpoint at runtime.
    #[serde(default)]
    pub connect_addr: Option<SocketAddr>,
    /// Connection timeout in seconds.
    #[serde(default = "default_connect_timeout_secs")]
    pub(crate) connect_timeout_secs: u64,
    /// Minimum reconnect backoff in milliseconds.
    #[serde(default = "default_min_backoff_ms")]
    pub(crate) reconnect_min_backoff_ms: u64,
    /// Maximum reconnect backoff in seconds.
    #[serde(default = "default_max_backoff_secs")]
    pub(crate) reconnect_max_backoff_secs: u64,
    /// Grace period before the revocation stream is considered ready.
    #[serde(default = "default_readiness_grace_ms")]
    pub(crate) revocation_readiness_grace_ms: u64,
    /// Flip revocation readiness back to false on disconnect.
    #[serde(default)]
    pub(crate) revocation_fail_closed_on_disconnect: bool,
    /// Path to the Authority's PASETO v4 Ed25519 public key (32 raw
    /// bytes, as written by `firma-authority generate-key`). Required
    /// when `[capability_seed].paths` is non-empty so the sidecar can
    /// verify the seed signatures.
    #[serde(default)]
    pub(crate) public_key_path: Option<PathBuf>,
    /// Path to the PEM-encoded CA certificate used to verify the Authority's
    /// TLS certificate.
    ///
    /// Requirement is context-dependent and enforced in `SidecarConfig::validate`:
    /// required for `https://` authority URLs, optional for loopback `http://`.
    #[serde(default)]
    pub(crate) ca_cert_path: Option<PathBuf>,
    /// Allow an insecure plain `http://` authority URL to a non-loopback
    /// host. Defaults to `false` (secure-by-default).
    #[serde(default)]
    pub(crate) allow_insecure_remote_authority: bool,
    /// Path to the PEM-encoded mTLS client certificate presented to the
    /// Authority during the TLS handshake. Required when the Authority is
    /// configured with `mtls_client_ca_cert_path`. Must be set together
    /// with `tls_client_key_path` or not at all.
    #[serde(default)]
    pub(crate) tls_client_cert_path: Option<PathBuf>,
    /// Path to the PEM-encoded mTLS client private key. Must be set
    /// together with `tls_client_cert_path` or not at all.
    #[serde(default)]
    pub(crate) tls_client_key_path: Option<PathBuf>,
    /// Credentials presented on each outbound Authority RPC.
    #[serde(default)]
    pub(crate) credentials: Option<SidecarCredentialsConfig>,
}

impl AuthorityConfig {
    pub(crate) fn target(&self) -> Result<AuthorityTarget, AuthorityEndpointError> {
        match self.url.as_deref() {
            Some(url) => {
                AuthorityEndpoint::new(url, self.connect_addr).map(AuthorityTarget::Enabled)
            }
            None if self.connect_addr.is_some() => {
                Err(AuthorityEndpointError::ConnectAddrWithoutUrl)
            }
            None => Ok(AuthorityTarget::Disabled),
        }
    }

    /// Validate authority client tuning.
    ///
    /// # Errors
    ///
    /// Returns a human-readable field error for invalid values.
    pub(crate) fn validate(&self) -> Result<(), String> {
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
