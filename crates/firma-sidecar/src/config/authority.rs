//! Authority stream client configuration.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use firma_config_schema::sidecar::authority::AuthorityConfig as SchemaAuthorityConfig;
use firma_config_utils::NonZeroDuration;
use firma_config_utils::http::host_is_this_machine;
use firma_identifiers::{AgentId, AgentIdParseError};
use hyper::Uri;

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

    /// Return whether the physical route stays on this host: the `connect_addr`
    /// when one is set, otherwise the logical host. A tunnel to a remote host
    /// counts, so this answers whether plaintext leaves the host, not whose
    /// certificate is presented.
    #[must_use]
    pub(crate) fn route_is_loopback(&self) -> bool {
        self.connect_addr.map_or_else(
            || self.logical_host_is_loopback(),
            |connect_addr| ip_is_loopback(connect_addr.ip()),
        )
    }

    /// Return whether the Authority runs on this host, where its certificate
    /// would come from the local CA: the logical host names this machine and
    /// the physical route, when one is set, is loopback. A tunnel to a remote
    /// Authority presents that Authority's certificate, not a local one.
    pub(crate) fn is_on_this_host(&self) -> bool {
        self.origin.host().is_some_and(host_is_this_machine)
            && self
                .connect_addr
                .is_none_or(|connect_addr| ip_is_loopback(connect_addr.ip()))
    }

    /// Return whether `uri` names the same origin as the Authority: scheme,
    /// host (case and a trailing dot aside) and effective port.
    #[must_use]
    pub fn has_origin_of(&self, uri: &Uri) -> bool {
        canonical_origin(&self.origin).is_some_and(|origin| canonical_origin(uri) == Some(origin))
    }

    /// The strict loopback rule that decides where plain HTTP is allowed:
    /// `localhost` or a loopback IP literal, with no trailing dot.
    fn logical_host_is_loopback(&self) -> bool {
        let host = self.origin.host().unwrap_or_default();
        let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || unbracketed.parse::<IpAddr>().is_ok_and(ip_is_loopback)
    }
}

/// The scheme, host and effective port of an `http` or `https` URI: an IP
/// literal in canonical form, a name lowercased without a trailing dot.
fn canonical_origin(uri: &Uri) -> Option<(&str, String, u16)> {
    let scheme = uri.scheme_str()?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let host = uri.host()?;
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    let host = unbracketed.parse::<IpAddr>().map_or_else(
        |_| host.trim_end_matches('.').to_ascii_lowercase(),
        |ip| ip.to_canonical().to_string(),
    );
    Some((scheme, host, uri.port_u16().unwrap_or(default_port)))
}

/// Loopback, including an IPv4 loopback address written as IPv4-mapped IPv6.
fn ip_is_loopback(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// The default CA for an Authority at `url` that names none.
///
/// It is the state directory's Authority CA, only when that Authority runs on
/// this host and the file exists. An unset URL names no remote Authority; an
/// unusable one is not treated as local.
///
/// An `https` Authority on another host leaves the file unused and is logged,
/// since a deployment that issued that Authority's certificate from this CA
/// now has to name it in `ca_cert_paths`.
#[must_use]
pub fn default_authority_ca(
    url: Option<&str>,
    connect_addr: Option<SocketAddr>,
    state: &firma_runtime_state::RuntimeLayout,
) -> Option<PathBuf> {
    let candidate = state.authority_tls_ca_certificate();
    if !firma_runtime_state::is_material_present(&candidate) {
        return None;
    }
    let Some(url) = url else {
        return Some(candidate);
    };
    let endpoint = AuthorityEndpoint::new(url, connect_addr).ok()?;
    if endpoint.is_on_this_host() {
        return Some(candidate);
    }
    if endpoint.is_https() {
        tracing::warn!(
            url,
            path = %candidate.display(),
            "the state directory's Authority CA is not used for an Authority on another host; \
             list it in authority.ca_cert_paths if that Authority's certificate was issued from it"
        );
    }
    None
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

/// What the Authority's TLS certificate is verified against.
///
/// Exactly one source: a configured CA list is never combined with the
/// platform's roots, so a private CA pins the Authority. Resolved once from
/// `[sidecar.authority]` and shared by the Sidecar's Authority channel, its
/// Authority-origin audit client and `firma run`'s capability mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityTrust {
    /// Only these CA certificates, in `ca_cert_paths` order; never empty.
    CustomCas(Vec<PathBuf>),
    /// The platform's trusted roots (`SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// override them).
    PlatformStore,
}

/// Whether the platform's trusted roots may verify the Authority when no CA
/// is named: `authority.disable_platform_roots`, read once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PlatformRoots {
    /// The platform's roots verify the Authority when no CA is named.
    #[default]
    Allowed,
    /// The platform's roots never verify the Authority.
    Disabled,
}

impl PlatformRoots {
    /// Read `authority.disable_platform_roots`.
    #[must_use]
    pub const fn from_disable_flag(disable_platform_roots: bool) -> Self {
        if disable_platform_roots {
            Self::Disabled
        } else {
            Self::Allowed
        }
    }
}

impl AuthorityTrust {
    /// Resolve the trust source from the configured CAs and the platform-root
    /// switch: any CA named wins over the switch.
    ///
    /// Call it before re-basing the paths: a blank entry re-based onto the
    /// config directory would name that directory and look valid.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityTrustError`] when an entry is blank, or when the
    /// platform's roots are disabled and no CA is named, a configuration that
    /// could verify nothing.
    pub fn resolve(
        ca_cert_paths: Vec<PathBuf>,
        platform_roots: PlatformRoots,
    ) -> Result<Self, AuthorityTrustError> {
        if ca_cert_paths.iter().any(|path| path.as_os_str().is_empty()) {
            return Err(AuthorityTrustError::EmptyCaCertPath);
        }
        match (ca_cert_paths.is_empty(), platform_roots) {
            (false, _) => Ok(Self::CustomCas(ca_cert_paths)),
            (true, PlatformRoots::Allowed) => Ok(Self::PlatformStore),
            (true, PlatformRoots::Disabled) => Err(AuthorityTrustError::NoTrustAnchors),
        }
    }

    /// The configured CA certificate paths; empty for the platform store.
    #[must_use]
    pub fn ca_cert_paths(&self) -> &[PathBuf] {
        match self {
            Self::CustomCas(paths) => paths,
            Self::PlatformStore => &[],
        }
    }

    /// The same trust with every CA path passed through `rebase`, for a
    /// caller that resolves relative paths after [`Self::resolve`].
    #[must_use]
    pub fn rebased(self, rebase: impl FnMut(&Path) -> PathBuf) -> Self {
        match self {
            Self::CustomCas(paths) => {
                Self::CustomCas(paths.iter().map(PathBuf::as_path).map(rebase).collect())
            }
            Self::PlatformStore => Self::PlatformStore,
        }
    }

    /// The configured CA certificate paths, for re-basing; none for the
    /// platform store.
    pub(crate) fn ca_cert_paths_mut(&mut self) -> impl Iterator<Item = &mut PathBuf> {
        match self {
            Self::CustomCas(paths) => paths.iter_mut(),
            Self::PlatformStore => [].iter_mut(),
        }
    }
}

/// `[sidecar.authority]` names no usable trust source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityTrustError {
    /// An entry of `ca_cert_paths` was blank.
    #[error("authority.ca_cert_paths entries must not be empty")]
    EmptyCaCertPath,
    /// The platform's roots were disabled with no CA named.
    #[error("authority.disable_platform_roots = true requires authority.ca_cert_paths")]
    NoTrustAnchors,
}

/// Validated tuning for background Authority stream clients.
#[derive(Debug, Clone)]
pub struct AuthorityConfig {
    /// Authority-registered `TypeID` for the agent represented by this Sidecar.
    #[expect(
        dead_code,
        reason = "validated here and consumed by firma-run before sidecar startup"
    )]
    pub(crate) agent_id: Option<AgentId>,
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`).
    pub url: String,
    /// Optional physical TCP destination for the Authority connection.
    pub connect_addr: Option<SocketAddr>,
    /// Connection timeout.
    pub(crate) connect_timeout: NonZeroDuration,
    /// Minimum reconnect backoff.
    pub(crate) reconnect_min_backoff: NonZeroDuration,
    /// Maximum reconnect backoff.
    pub(crate) reconnect_max_backoff: NonZeroDuration,
    /// How long a connection may deliver no revocation set before the Sidecar
    /// warns. Readiness is granted only by an applied set, never by this
    /// elapsing, so a Sidecar that has never applied one stays not-ready.
    pub(crate) revocation_readiness_grace: Duration,
    /// Flip revocation readiness back to false on disconnect.
    pub(crate) revocation_fail_closed_on_disconnect: bool,
    /// Path to the Authority's PASETO v4 Ed25519 public key.
    pub(crate) public_key_path: Option<PathBuf>,
    /// What the Authority's TLS certificate is verified against.
    pub(crate) trust: AuthorityTrust,
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

impl AuthorityConfig {
    /// Whether this Sidecar serves one run, authenticated by its
    /// runtime credential.
    #[must_use]
    pub fn uses_runtime_credential(&self) -> bool {
        self.credentials
            .as_ref()
            .is_some_and(SidecarCredentialsConfig::uses_runtime_credential)
    }
}

/// Error validating an [`AuthorityConfig`].
#[derive(Debug, thiserror::Error)]
pub enum AuthorityConfigError {
    /// No Authority endpoint was selected.
    #[error("sidecar.authority.url is required")]
    MissingUrl,
    /// `agent_id` was not a valid `TypeID`.
    #[error("authority.agent_id: {0}")]
    AgentId(#[from] AgentIdParseError),
    /// The maximum reconnect backoff was below the minimum.
    #[error("authority.reconnect_max_backoff must be >= reconnect_min_backoff")]
    MaxBackoffLessThanMin,
    /// `public_key_path` was set but empty.
    #[error("authority.public_key_path must not be empty when set")]
    EmptyPublicKeyPath,
    /// The trust source is unusable.
    #[error(transparent)]
    Trust(#[from] AuthorityTrustError),
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
    pub(crate) fn target(&self) -> Result<AuthorityEndpoint, AuthorityEndpointError> {
        AuthorityEndpoint::new(&self.url, self.connect_addr)
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
        let url = s
            .url
            .filter(|url| !url.trim().is_empty())
            .ok_or(AuthorityConfigError::MissingUrl)?;
        let agent_id = s.agent_id.map(|id| id.parse::<AgentId>()).transpose()?;
        let reconnect_min_backoff = s.reconnect_min_backoff;
        let reconnect_max_backoff = s.reconnect_max_backoff;
        if reconnect_max_backoff < reconnect_min_backoff {
            return Err(AuthorityConfigError::MaxBackoffLessThanMin);
        }
        let public_key_path =
            require_non_empty_path(s.public_key_path, AuthorityConfigError::EmptyPublicKeyPath)?;
        let trust = AuthorityTrust::resolve(
            s.ca_cert_paths,
            PlatformRoots::from_disable_flag(s.disable_platform_roots),
        )?;
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
            url,
            connect_addr: s.connect_addr,
            connect_timeout: s.connect_timeout,
            reconnect_min_backoff,
            reconnect_max_backoff,
            revocation_readiness_grace: s.revocation_readiness_grace,
            revocation_fail_closed_on_disconnect: s.revocation_fail_closed_on_disconnect,
            public_key_path,
            trust,
            allow_insecure_remote_authority: s.allow_insecure_remote_authority,
            tls_client_cert_path,
            tls_client_key_path,
            credentials,
        })
    }
}
