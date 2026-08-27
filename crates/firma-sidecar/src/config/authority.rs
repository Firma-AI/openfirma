//! Authority stream client configuration.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use firma_config_schema::sidecar::authority::AuthorityConfig as SchemaAuthorityConfig;
use firma_identifiers::{AgentId, AgentIdParseError};
use hyper::Uri;

use super::AuthorityTarget;
use crate::authority_credentials::{SidecarCredentialsConfig, SidecarCredentialsConfigError};

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

/// Validated tuning for background Authority stream clients.
#[derive(Debug, Clone)]
pub struct AuthorityConfig {
    /// Authority-registered `TypeID` for the agent represented by this Sidecar.
    #[expect(dead_code, reason = "accepted for configuration compatibility")]
    pub(crate) agent_id: Option<AgentId>,
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`).
    pub url: Option<String>,
    /// Optional physical TCP destination for the Authority connection.
    pub connect_addr: Option<SocketAddr>,
    /// Connection timeout.
    pub(crate) connect_timeout: Duration,
    /// Minimum reconnect backoff in milliseconds.
    pub(crate) reconnect_min_backoff_ms: u64,
    /// Maximum reconnect backoff in seconds.
    pub(crate) reconnect_max_backoff_secs: u64,
    /// Grace period before the revocation stream is considered ready.
    pub(crate) revocation_readiness_grace_ms: u64,
    /// Flip revocation readiness back to false on disconnect.
    pub(crate) revocation_fail_closed_on_disconnect: bool,
    /// Path to the Authority's PASETO v4 Ed25519 public key.
    pub(crate) public_key_path: Option<PathBuf>,
    /// Path to the PEM-encoded CA certificate used to verify the Authority's
    /// TLS certificate. Requirement is context-dependent and enforced in
    /// `SidecarConfig`: required for `https://` authority URLs, optional for
    /// loopback `http://`.
    pub(crate) ca_cert_path: Option<PathBuf>,
    /// Allow an insecure plain `http://` authority URL to a non-loopback host.
    pub(crate) allow_insecure_remote_authority: bool,
    /// Path to the PEM-encoded mTLS client certificate presented to the
    /// Authority. Must be set together with `tls_client_key_path` or not at all.
    pub(crate) tls_client_cert_path: Option<PathBuf>,
    /// Path to the PEM-encoded mTLS client private key. Must be set together
    /// with `tls_client_cert_path` or not at all.
    pub(crate) tls_client_key_path: Option<PathBuf>,
    /// Credentials presented on each outbound Authority RPC.
    pub(crate) credentials: Option<SidecarCredentialsConfig>,
}

/// Error validating an [`AuthorityConfig`].
#[derive(Debug, thiserror::Error)]
pub enum AuthorityConfigError {
    /// `agent_id` was not a valid `TypeID`.
    #[error("authority.agent_id: {0}")]
    AgentId(#[from] AgentIdParseError),
    /// `connect_timeout` was zero.
    #[error("authority.connect_timeout must be > 0")]
    ZeroConnectTimeout,
    /// `reconnect_min_backoff_ms` was zero.
    #[error("authority.reconnect_min_backoff_ms must be > 0")]
    ZeroMinBackoff,
    /// `reconnect_max_backoff_secs` was zero.
    #[error("authority.reconnect_max_backoff_secs must be > 0")]
    ZeroMaxBackoff,
    /// The maximum reconnect backoff was below the minimum.
    #[error("authority.reconnect_max_backoff_secs must be >= reconnect_min_backoff_ms")]
    MaxBackoffLessThanMin,
    /// `public_key_path` was set but empty.
    #[error("authority.public_key_path must not be empty when set")]
    EmptyPublicKeyPath,
    /// `ca_cert_path` was set but empty.
    #[error("authority.ca_cert_path must not be empty when set")]
    EmptyCaCertPath,
    /// Exactly one of the mTLS client cert/key pair was set.
    #[error(
        "authority.tls_client_cert_path and authority.tls_client_key_path must both be set or both be unset"
    )]
    TlsClientPairMismatch,
    /// `tls_client_cert_path` was set but empty.
    #[error("authority.tls_client_cert_path must not be empty when set")]
    EmptyTlsClientCertPath,
    /// `tls_client_key_path` was set but empty.
    #[error("authority.tls_client_key_path must not be empty when set")]
    EmptyTlsClientKeyPath,
    /// The nested credentials were invalid.
    #[error("authority.credentials: {0}")]
    Credentials(#[from] SidecarCredentialsConfigError),
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
}

fn require_non_empty_path(
    path: Option<PathBuf>,
    empty: AuthorityConfigError,
) -> Result<Option<PathBuf>, AuthorityConfigError> {
    if let Some(ref p) = path
        && p.as_os_str().is_empty()
    {
        return Err(empty);
    }
    Ok(path)
}

impl TryFrom<SchemaAuthorityConfig> for AuthorityConfig {
    type Error = AuthorityConfigError;

    fn try_from(s: SchemaAuthorityConfig) -> Result<Self, Self::Error> {
        let agent_id = s.agent_id.map(|id| id.parse::<AgentId>()).transpose()?;
        if s.connect_timeout.is_zero() {
            return Err(AuthorityConfigError::ZeroConnectTimeout);
        }
        if s.reconnect_min_backoff_ms == 0 {
            return Err(AuthorityConfigError::ZeroMinBackoff);
        }
        if s.reconnect_max_backoff_secs == 0 {
            return Err(AuthorityConfigError::ZeroMaxBackoff);
        }
        if s.reconnect_max_backoff_secs.saturating_mul(1000) < s.reconnect_min_backoff_ms {
            return Err(AuthorityConfigError::MaxBackoffLessThanMin);
        }
        let public_key_path =
            require_non_empty_path(s.public_key_path, AuthorityConfigError::EmptyPublicKeyPath)?;
        let ca_cert_path =
            require_non_empty_path(s.ca_cert_path, AuthorityConfigError::EmptyCaCertPath)?;
        if s.tls_client_cert_path.is_some() != s.tls_client_key_path.is_some() {
            return Err(AuthorityConfigError::TlsClientPairMismatch);
        }
        let tls_client_cert_path = require_non_empty_path(
            s.tls_client_cert_path,
            AuthorityConfigError::EmptyTlsClientCertPath,
        )?;
        let tls_client_key_path = require_non_empty_path(
            s.tls_client_key_path,
            AuthorityConfigError::EmptyTlsClientKeyPath,
        )?;
        let credentials = s
            .credentials
            .map(SidecarCredentialsConfig::try_from)
            .transpose()?;
        Ok(Self {
            agent_id,
            url: s.url,
            connect_addr: s.connect_addr,
            connect_timeout: s.connect_timeout,
            reconnect_min_backoff_ms: s.reconnect_min_backoff_ms,
            reconnect_max_backoff_secs: s.reconnect_max_backoff_secs,
            revocation_readiness_grace_ms: s.revocation_readiness_grace_ms,
            revocation_fail_closed_on_disconnect: s.revocation_fail_closed_on_disconnect,
            public_key_path,
            ca_cert_path,
            allow_insecure_remote_authority: s.allow_insecure_remote_authority,
            tls_client_cert_path,
            tls_client_key_path,
            credentials,
        })
    }
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            agent_id: None,
            url: None,
            connect_addr: None,
            connect_timeout: Duration::from_secs(10),
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

const fn default_min_backoff_ms() -> u64 {
    250
}

const fn default_max_backoff_secs() -> u64 {
    30
}

const fn default_readiness_grace_ms() -> u64 {
    500
}
