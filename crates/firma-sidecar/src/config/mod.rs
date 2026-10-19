//! Sidecar configuration types.
//!
//! All configuration for the sidecar binary is defined here. The
//! behavior-free shape lives in [`firma_config_schema::sidecar`]; the
//! validated types here are built from it via `TryFrom`, so an invalid
//! configuration can never be constructed.
//!
//! The top-level [`SidecarConfig`] groups the enforcement-specific
//! [`EnforcementConfig`] after the behavior-free schema has deserialized its
//! `[sidecar.constraint_enforcement]` table. Mapping sources belong to the
//! Authority, not Sidecar configuration.
//!
//! Validation runs eagerly when the schema is converted at startup, so
//! misconfigurations surface before the first request arrives.

mod audit;
mod authority;
mod capability_seed;
mod connector;
mod enforcement;
mod revocation;

pub use self::audit::{AuditConfig, AuditConfigError, AuditSigningKey};
pub use self::authority::{
    AuthorityConfig, AuthorityConfigError, AuthorityEndpoint, AuthorityEndpointError,
};
pub use self::capability_seed::{CapabilitySeedConfig, CapabilitySeedConfigError, SeedFile};
pub use self::connector::{ConnectorConfig, ConnectorConfigError};
pub use self::enforcement::{
    EnforcementConfig, EnforcementConfigError, MappingRuleConfig, MappingRulesFile,
};
pub use self::revocation::{RevocationConfig, RevocationConfigError};
pub use crate::authority_credentials::SidecarCredentialsConfig;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use firma_config_schema::gateway::GatewayConfig;
use firma_config_schema::sidecar::infra as schema_infra;
use firma_config_schema::sidecar::interceptor as schema_ic;
use firma_config_schema::sidecar::local_exec as schema_le;
use firma_config_utils::NonZeroDuration;
use firma_core::SecretMatcher;
use firma_http::HeaderName;
use firma_secret_provider::spec::http::HttpIntegrationSpec;
// One-to-one config enums live in `firma_config_schema` and are imported for
// in-crate use only; they are never re-exported, so `firma_config_schema`
// stays the single owner and every consumer imports them from there directly.
use firma_config_schema::sidecar::infra::{CredentialMode, CredentialTransform};
use firma_config_schema::sidecar::interceptor::InterceptorMode;

// ---------------------------------------------------------------------------
// Top-level sidecar configuration
// ---------------------------------------------------------------------------

/// Top-level sidecar configuration deserialized from TOML.
///
/// Contains both infrastructure settings (interceptor, policy, CA,
/// credentials) and enforcement-engine settings (
/// capability validation, constraint enforcement) via
/// [`EnforcementConfig`].
///
/// Built only by [`SidecarConfig::resolve`]: there is deliberately no
/// [`Default`] and no `TryFrom`, because a config whose state-directory
/// defaults have not been filled in is not one any component can run on.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Interceptor settings (mode, listen address or socket path, drain timeout).
    pub interceptor: InterceptorConfig,
    /// Policy directory.
    policy: PolicyConfig,
    /// Certificate authority directory.
    pub(crate) ca: CaConfig,
    /// Per-target credential injection entries, keyed by an arbitrary label.
    pub(crate) credentials: HashMap<String, CredentialConfig>,
    /// Outbound connector settings (default timeout + per-host overrides).
    pub connector: ConnectorConfig,
    /// Background Authority stream client tuning.
    pub authority: AuthorityConfig,
    /// Enforcement engine settings (capability validation, constraint
    /// enforcement).
    pub(crate) enforcement: EnforcementConfig,
    /// Revocation cache settings (bloom filter + LRU sizing).
    pub(crate) revocation: RevocationConfig,
    /// Static capability provisioning seed files.
    pub capability_seed: CapabilitySeedConfig,
    /// Audit event emitter settings.
    pub audit: AuditConfig,
    /// Local-exec governance endpoint configuration. When absent, the
    /// local-exec endpoint is not started.
    pub(crate) local_exec: Option<LocalExecConfig>,
    /// HTTP secret-provider registry for MITM interception.
    pub http_secret_providers: Vec<HttpIntegrationSpec<SecretMatcher>>,
    /// Tunable timeouts and limits for the secret-gateway client.
    pub secret_gateway: GatewayConfig,
}

/// Error building or loading a validated [`SidecarConfig`].
#[derive(Debug, thiserror::Error)]
pub enum SidecarConfigError {
    /// The config file could not be read.
    #[error("failed to read config file {path}: {source}")]
    Read {
        /// The config file path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file could not be parsed as TOML.
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        /// The config file path.
        path: PathBuf,
        /// The underlying TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// The `[sidecar.interceptor]` section was invalid.
    #[error("interceptor: {0}")]
    Interceptor(#[from] InterceptorConfigError),
    /// The `[sidecar.policy]` section was invalid.
    #[error("{0}")]
    Policy(#[from] PolicyConfigError),
    /// The `[sidecar.ca]` section was invalid.
    #[error("{0}")]
    Ca(#[from] CaConfigError),
    /// A `[sidecar.credentials.*]` entry was invalid.
    #[error("credentials.{label}: {source}")]
    Credential {
        /// The credential label.
        label: String,
        /// The credential validation failure.
        #[source]
        source: CredentialConfigError,
    },
    /// The `[sidecar.connector]` section was invalid.
    #[error("connector: {0}")]
    Connector(#[from] ConnectorConfigError),
    /// The `[sidecar.authority]` section was invalid.
    #[error("authority: {0}")]
    Authority(#[from] AuthorityConfigError),
    /// An enforcement section was invalid.
    #[error("{0}")]
    Enforcement(#[from] EnforcementConfigError),
    /// The `[sidecar.revocation]` section was invalid.
    #[error("revocation: {0}")]
    Revocation(#[from] RevocationConfigError),
    /// The `[sidecar.capability_seed]` section was invalid.
    #[error("{0}")]
    CapabilitySeed(#[from] CapabilitySeedConfigError),
    /// The `[sidecar.audit]` section was invalid.
    #[error("audit: {0}")]
    Audit(#[from] AuditConfigError),
    /// The `[sidecar.local_exec]` section was invalid.
    #[error("local_exec: {0}")]
    LocalExec(#[from] LocalExecConfigError),
    /// An `[[sidecar.http_secret_providers]]` entry was invalid.
    #[error("http_secret_providers: {0}")]
    HttpSecretProvider(#[from] firma_secret_provider::spec::http::HttpSecretProviderConfigError),
    /// The Authority endpoint (`url` / `connect_addr`) was invalid.
    #[error("authority: {0}")]
    AuthorityEndpoint(#[from] AuthorityEndpointError),
    /// A validated Authority endpoint unexpectedly had no host.
    #[error("authority: validated endpoint unexpectedly has no host")]
    AuthorityEndpointMissingHost,
    /// `sidecar.capability_seed.paths` was non-empty without an Authority public key.
    #[error("authority.public_key_path must be set when capability_seed.paths is non-empty")]
    MissingPublicKeyForSeeds,
    /// An `https://` Authority URL was configured without a CA certificate,
    /// and none was found at the state-directory default either.
    #[error(
        "authority.ca_cert_path must be set when authority.url uses https://; no CA certificate was readable at the state-directory default {}",
        state_default.display()
    )]
    MissingCaCertForHttps {
        /// Path the adopted default would have come from.
        state_default: PathBuf,
    },
    /// An insecure `http://` Authority URL targeted a non-loopback host.
    #[error(
        "authority.url uses insecure http:// for a non-loopback host; either switch to https:// or set authority.allow_insecure_remote_authority = true"
    )]
    InsecureNonLoopbackAuthority,
}

impl SidecarConfig {
    /// Path of the Authority public key used to verify capability tokens, when
    /// one is configured or was adopted.
    #[must_use]
    pub fn authority_public_key_path(&self) -> Option<&std::path::Path> {
        self.authority.public_key_path.as_deref()
    }

    /// Directory the HTTPS MITM CA material is minted into.
    #[must_use]
    pub fn ca_dir(&self) -> &std::path::Path {
        &self.ca.dir
    }

    /// Path the `file` audit sink appends to; `None` for every other sink.
    #[must_use]
    pub fn audit_file_path(&self) -> Option<&std::path::Path> {
        self.audit.file_path.as_deref()
    }

    /// Path of the CA certificate the Authority's TLS identity is verified
    /// against, when one is configured or was adopted.
    #[must_use]
    pub fn authority_ca_cert_path(&self) -> Option<&std::path::Path> {
        self.authority.ca_cert_path.as_deref()
    }

    /// Load and validate a sidecar configuration from a TOML file, resolving
    /// unset artifact paths against `state`.
    ///
    /// # Errors
    ///
    /// Returns [`SidecarConfigError`] if the file cannot be read, the TOML is
    /// invalid, or any section fails validation.
    pub fn load_from_path(
        path: &std::path::Path,
        state: &firma_runtime_state::RuntimeLayout,
    ) -> Result<Self, SidecarConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| SidecarConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let schema: firma_config_schema::sidecar::SidecarConfig =
            toml::from_str(&text).map_err(|source| SidecarConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        Self::resolve(schema, state)
    }

    /// Cross-section validations that span more than one config section.
    fn validate_cross_fields(
        &self,
        state: &firma_runtime_state::RuntimeLayout,
    ) -> Result<(), SidecarConfigError> {
        if !self.capability_seed.paths.is_empty() && self.authority.public_key_path.is_none() {
            return Err(SidecarConfigError::MissingPublicKeyForSeeds);
        }
        {
            let endpoint = self.authority.target()?;
            let host = endpoint
                .origin()
                .host()
                .ok_or(SidecarConfigError::AuthorityEndpointMissingHost)?;
            if endpoint.is_https() {
                if self.authority.ca_cert_path.is_none() {
                    return Err(SidecarConfigError::MissingCaCertForHttps {
                        state_default: state.authority_tls_ca_certificate(),
                    });
                }
            } else {
                let is_loopback = endpoint.connect_addr().map_or_else(
                    || {
                        let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
                        host.eq_ignore_ascii_case("localhost")
                            || host_unbracketed
                                .parse::<IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                    },
                    |connect_addr| connect_addr.ip().is_loopback(),
                );
                if !is_loopback && !self.authority.allow_insecure_remote_authority {
                    return Err(SidecarConfigError::InsecureNonLoopbackAuthority);
                }
            }
        }
        Ok(())
    }

    /// Re-base every relative resource path against `config_dir`;
    /// absolute paths are left untouched. No default-name sentinel
    /// check — relative always means "relative to the config file's
    /// directory" for consistency.
    ///
    /// `sidecar.ca.dir` is intentionally excluded — it is state-managed (its
    /// location is owned by the state dir / env override, not the
    /// config file).
    pub fn rebase_defaults(&mut self, config_dir: &std::path::Path) {
        // Empty is left for the validator to reject (not a path to re-base).
        let rebase = |p: &mut PathBuf| {
            if !p.as_os_str().is_empty() && p.is_relative() {
                *p = config_dir.join(&*p);
            }
        };
        rebase(&mut self.policy.dir);
        if let Some(p) = self.authority.public_key_path.as_mut() {
            rebase(p);
        }
        if let Some(p) = self.authority.ca_cert_path.as_mut() {
            rebase(p);
        }
        if let Some(p) = self.authority.tls_client_cert_path.as_mut() {
            rebase(p);
        }
        if let Some(p) = self.authority.tls_client_key_path.as_mut() {
            rebase(p);
        }
        if let Some(credentials) = self.authority.credentials.as_mut() {
            credentials.rebase_defaults(config_dir);
        }
        for credential in self.credentials.values_mut() {
            if let Some(p) = credential.secret_path.as_mut() {
                rebase(p);
            }
        }
        // A key adopted from the state directory is already absolute; only an
        // operator-supplied path can be relative to the config file.
        if let AuditSigningKey::Path(p) = &mut self.audit.signing_key {
            rebase(p);
        }
        if let Some(p) = self.audit.file_path.as_mut() {
            rebase(p);
        }
        if let Some(p) = self.audit.buffer_path.as_mut() {
            rebase(p);
        }
        if let Some(p) = self.audit.wal_path.as_mut() {
            rebase(p);
        }
        for p in &mut self.capability_seed.paths {
            rebase(p);
        }
    }
}

/// Fill in the Authority trust anchors from `state` when the config names none
/// and the material is actually there.
///
/// `firma config` writes `authority.pub` and `tls/authority-ca.crt` into the
/// state directory and pins both paths in `firma.toml`. Adopting them as the
/// default keeps a deployment that pins neither verifying capability tokens and
/// the Authority's TLS identity without naming a host path.
///
/// The existence check is what keeps the other direction safe: a deployment that
/// never generated this material keeps its reject-all token verifier and its
/// rejection of an `https://` Authority, instead of failing on a file nobody
/// wrote.
///
/// What counts as present is
/// [`firma_runtime_state::is_material_present`]: every consumer of a
/// state-directory default has to answer that question the same way, including
/// `firma run`, which resolves these positions before spawning this process.
fn adopt_authority_trust_anchors(
    schema: &mut firma_config_schema::sidecar::SidecarConfig,
    state: &firma_runtime_state::RuntimeLayout,
) {
    if schema.authority.public_key_path.is_none() {
        let candidate = state.authority_public_key();
        if firma_runtime_state::is_material_present(&candidate) {
            schema.authority.public_key_path = Some(candidate);
        }
    }
    if schema.authority.ca_cert_path.is_none() {
        let candidate = state.authority_tls_ca_certificate();
        if firma_runtime_state::is_material_present(&candidate) {
            schema.authority.ca_cert_path = Some(candidate);
        }
    }
}

impl SidecarConfig {
    /// Validate `schema` against `state`, the state directory this process and
    /// its children resolve their artifacts from.
    ///
    /// This is the only way to build a [`SidecarConfig`]. Resolution and
    /// validation are one step because they are not independent: the validator
    /// rejects an `https://` Authority with no CA certificate, so an anchor
    /// adopted from the state directory has to be in place before the check
    /// runs. Splitting them is what let `firma doctor` reject configurations
    /// the Sidecar accepts.
    ///
    /// What `state` supplies, for each field the config leaves unset:
    ///
    /// | Field | Default |
    /// |-------|---------|
    /// | `authority.public_key_path` | `authority.pub`, if present |
    /// | `authority.ca_cert_path` | `tls/authority-ca.crt`, if present |
    /// | `ca.dir` | `generated-firma-ca` |
    /// | `audit.file_path` | `audit.jsonl` |
    /// | `audit.signing_key_path` | `audit.key` |
    ///
    /// Each is the path `firma config` generates, so a config that names
    /// nothing and a scaffolded one drive the same files.
    ///
    /// # Errors
    ///
    /// Returns [`SidecarConfigError`] when any section fails validation.
    pub fn resolve(
        mut schema: firma_config_schema::sidecar::SidecarConfig,
        state: &firma_runtime_state::RuntimeLayout,
    ) -> Result<Self, SidecarConfigError> {
        adopt_authority_trust_anchors(&mut schema, state);
        Self::from_schema(schema, state)
    }

    fn from_schema(
        s: firma_config_schema::sidecar::SidecarConfig,
        state: &firma_runtime_state::RuntimeLayout,
    ) -> Result<Self, SidecarConfigError> {
        let mut credentials = HashMap::with_capacity(s.credentials.len());
        for (label, cred) in s.credentials {
            let validated = CredentialConfig::try_from(cred).map_err(|source| {
                SidecarConfigError::Credential {
                    label: label.clone(),
                    source,
                }
            })?;
            credentials.insert(label, validated);
        }
        let http_secret_providers = s
            .http_secret_providers
            .into_iter()
            .map(HttpIntegrationSpec::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let enforcement = firma_config_schema::sidecar::EnforcementConfig {
            constraint_enforcement: s.constraint_enforcement,
        }
        .try_into()?;
        let config = Self {
            interceptor: s.interceptor.try_into()?,
            policy: s.policy.try_into()?,
            ca: CaConfig::resolve(s.ca, state)?,
            credentials,
            connector: s.connector.try_into()?,
            authority: s.authority.try_into()?,
            enforcement,
            revocation: s.revocation.try_into()?,
            capability_seed: s.capability_seed.try_into()?,
            audit: AuditConfig::resolve(s.audit, state)?,
            local_exec: s.local_exec.map(LocalExecConfig::try_from).transpose()?,
            http_secret_providers,
            secret_gateway: s.secret_gateway,
        };
        config.validate_cross_fields(state)?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Infrastructure sections
// ---------------------------------------------------------------------------

/// Interception mode selector.
///
/// Interceptor settings.
///
/// Selects the interception mode and supplies mode-specific
/// parameters:
///
/// | Mode | Required fields |
/// |------|-----------------|
/// | `http_proxy` | `listen_addr` |
/// | `grpc` | `listen_addr` |
/// | `unix_socket` | `socket_path` (defaults to the lifecycle runtime layout) |
///
/// `drain_timeout` is shared across all modes.
#[derive(Debug, Clone)]
pub struct InterceptorConfig {
    /// Interception mode. Default: `http_proxy`.
    pub mode: InterceptorMode,
    /// Socket address used by `http_proxy` and `grpc` modes.
    pub listen_addr: SocketAddr,
    /// Path to the Unix domain socket file, used by `unix_socket`
    /// mode.
    pub socket_path: Option<PathBuf>,
    /// Time to wait for in-flight requests to drain on shutdown.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "not yet consumed by interceptor shutdown")
    )]
    drain_timeout: NonZeroDuration,
    /// Maximum request body size accepted by proxy interceptors.
    pub(crate) max_request_body_bytes: NonZeroUsize,
    /// Maximum size a single request or response body may expand to when
    /// decompressed for secret placeholder rehydration or masking. Bounds
    /// the memory a decompression bomb (e.g. a small `gzip`/`br`/`zstd`
    /// payload that expands enormously) can force the Sidecar to allocate.
    max_decompressed_body_bytes: NonZeroUsize,
    /// CONNECT/MITM relay timeout controls.
    pub(crate) connect_relay: ConnectRelayConfig,
    /// HTTPS MITM settings used by the HTTP proxy interceptor.
    pub https_mitm: HttpsMitmConfig,
    /// Global ceiling for the total bytes of request bodies buffered
    /// concurrently across all in-flight proxy connections.  When the
    /// budget is full, new requests receive an immediate 403 denial
    /// with an audit trail rather than silently unbounded buffering
    /// that could OOM-kill the enforcer.
    pub(crate) total_body_budget_bytes: NonZeroUsize,
}

/// Error validating an [`InterceptorConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InterceptorConfigError {
    /// `max_request_body_size` was zero.
    #[error("interceptor.max_request_body_size must be > 0")]
    ZeroMaxRequestBody,
    /// `max_request_body_size` was too large for this platform's `usize`.
    #[error("interceptor.max_request_body_size is too large for this platform")]
    MaxRequestBodyTooLarge,
    /// `max_decompressed_body_size` was zero.
    #[error("interceptor.max_decompressed_body_size must be > 0")]
    ZeroMaxDecompressedBody,
    /// `max_decompressed_body_size` was too large for this platform's `usize`.
    #[error("interceptor.max_decompressed_body_size is too large for this platform")]
    MaxDecompressedBodyTooLarge,
    /// `total_body_budget` was zero.
    #[error("interceptor.total_body_budget must be > 0")]
    ZeroTotalBodyBudget,
    /// `total_body_budget` was too large for this platform's `usize`.
    #[error("interceptor.total_body_budget is too large for this platform")]
    TotalBodyBudgetTooLarge,
    /// The total body budget was below the per-request maximum.
    #[error("interceptor.total_body_budget must be >= interceptor.max_request_body_size")]
    TotalBodyBudgetBelowRequest,
    /// The HTTPS MITM settings were invalid.
    #[error(transparent)]
    HttpsMitm(#[from] HttpsMitmConfigError),
    /// `unix_socket` mode was selected but `socket_path` was empty.
    #[cfg(unix)]
    #[error("interceptor.socket_path must not be empty when mode is unix_socket")]
    SocketPathEmpty,
}

impl TryFrom<schema_ic::InterceptorConfig> for InterceptorConfig {
    type Error = InterceptorConfigError;

    fn try_from(s: schema_ic::InterceptorConfig) -> Result<Self, Self::Error> {
        let max_request_body_bytes = usize::try_from(s.max_request_body_size.as_u64())
            .map_err(|_| InterceptorConfigError::MaxRequestBodyTooLarge)?;
        let total_body_budget_bytes = usize::try_from(s.total_body_budget.as_u64())
            .map_err(|_| InterceptorConfigError::TotalBodyBudgetTooLarge)?;
        let https_mitm = HttpsMitmConfig::try_from(s.https_mitm)?;
        let max_request_body_bytes = NonZeroUsize::new(max_request_body_bytes)
            .ok_or(InterceptorConfigError::ZeroMaxRequestBody)?;
        if s.max_decompressed_body_size.as_u64() == 0 {
            return Err(InterceptorConfigError::ZeroMaxDecompressedBody);
        }
        // The decoder reads one byte past the limit to detect overflow, so
        // `usize::MAX` is rejected along with sizes that do not fit `usize`.
        let max_decompressed_body_bytes = usize::try_from(s.max_decompressed_body_size.as_u64())
            .ok()
            .filter(|&bytes| bytes != usize::MAX)
            .and_then(NonZeroUsize::new)
            .ok_or(InterceptorConfigError::MaxDecompressedBodyTooLarge)?;
        let total_body_budget_bytes = NonZeroUsize::new(total_body_budget_bytes)
            .ok_or(InterceptorConfigError::ZeroTotalBodyBudget)?;
        let config = Self {
            mode: s.mode,
            listen_addr: s.listen_addr,
            socket_path: s.socket_path,
            drain_timeout: s.drain_timeout,
            max_request_body_bytes,
            max_decompressed_body_bytes,
            connect_relay: s.connect_relay.into(),
            https_mitm,
            total_body_budget_bytes,
        };
        if config.total_body_budget_bytes < config.max_request_body_bytes {
            return Err(InterceptorConfigError::TotalBodyBudgetBelowRequest);
        }
        #[cfg(unix)]
        if config.mode == InterceptorMode::UnixSocket {
            match &config.socket_path {
                Some(p) if p.as_os_str().is_empty() => {
                    return Err(InterceptorConfigError::SocketPathEmpty);
                }
                // An absent socket_path is valid: the lifecycle runtime layout
                // supplies the default socket path at startup.
                _ => {}
            }
        }
        Ok(config)
    }
}

impl InterceptorConfig {
    #[must_use]
    pub fn max_decompressed_body_bytes(&self) -> NonZeroUsize {
        self.max_decompressed_body_bytes
    }
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        let d = schema_ic::InterceptorConfig::default();
        Self {
            mode: d.mode,
            listen_addr: d.listen_addr,
            socket_path: d.socket_path,
            drain_timeout: d.drain_timeout,
            max_request_body_bytes: usize::try_from(d.max_request_body_size.as_u64())
                .ok()
                .and_then(NonZeroUsize::new)
                .unwrap_or(const { NonZeroUsize::new(4 * 1024 * 1024).unwrap() }),
            max_decompressed_body_bytes: usize::try_from(d.max_decompressed_body_size.as_u64())
                .ok()
                .and_then(NonZeroUsize::new)
                .unwrap_or(const { NonZeroUsize::new(16 * 1024 * 1024).unwrap() }),
            connect_relay: ConnectRelayConfig::default(),
            https_mitm: HttpsMitmConfig::default(),
            total_body_budget_bytes: usize::try_from(d.total_body_budget.as_u64())
                .ok()
                .and_then(NonZeroUsize::new)
                .unwrap_or(const { NonZeroUsize::new(64 * 1024 * 1024).unwrap() }),
        }
    }
}

/// Timeout controls for CONNECT tunnel and MITM relay sessions.
#[derive(Debug, Clone)]
pub struct ConnectRelayConfig {
    /// Timeout for CONNECT upgrade and upstream connect/TLS setup.
    pub(crate) setup_timeout: NonZeroDuration,
    /// Hard cap for the full tunnel/MITM session lifetime.
    pub(crate) session_max: NonZeroDuration,
}

impl From<schema_ic::ConnectRelayConfig> for ConnectRelayConfig {
    fn from(s: schema_ic::ConnectRelayConfig) -> Self {
        Self {
            setup_timeout: s.setup_timeout,
            session_max: s.session_max,
        }
    }
}

impl Default for ConnectRelayConfig {
    fn default() -> Self {
        let d = schema_ic::ConnectRelayConfig::default();
        Self {
            setup_timeout: d.setup_timeout,
            session_max: d.session_max,
        }
    }
}

/// HTTPS MITM controls for the HTTP proxy interceptor.
///
/// When disabled, HTTPS `CONNECT` requests are handled as blind tunnels.
/// When enabled, hosts matched by `intercept_hosts` are decrypted and
/// re-encrypted by the sidecar.
///
/// CA material always lives at `firma-ca.crt` and `firma-ca.key` under
/// [`CaConfig::dir`]; neither path is configurable here.
#[derive(Debug, Clone)]
pub struct HttpsMitmConfig {
    /// Enables TLS MITM interception for selected hosts.
    pub(crate) enabled: bool,
    /// Host patterns that should be intercepted (supports `*` wildcard).
    pub(crate) intercept_hosts: Vec<String>,
    /// Host patterns that should bypass interception and use CONNECT tunnel.
    pub(crate) bypass_hosts: Vec<String>,
    /// Dynamic leaf certificate TTL.
    pub(crate) cert_ttl: Duration,
    /// Maximum number of cached leaf certificates.
    pub(crate) cert_cache_capacity: usize,
    /// Host patterns that must be intercepted; failures are hard deny.
    pub(crate) strict_hosts: Vec<String>,
}

/// Error validating an [`HttpsMitmConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpsMitmConfigError {
    /// A configured host pattern was invalid.
    #[error(transparent)]
    HostPattern(#[from] HostPatternError),
    /// `cert_ttl` was zero while interception was active.
    #[error("interceptor.https_mitm.cert_ttl must be > 0")]
    ZeroCertTtl,
    /// `cert_cache_capacity` was zero while interception was active.
    #[error("interceptor.https_mitm.cert_cache_capacity must be > 0")]
    ZeroCertCacheCapacity,
}

impl TryFrom<schema_ic::HttpsMitmConfig> for HttpsMitmConfig {
    type Error = HttpsMitmConfigError;

    fn try_from(s: schema_ic::HttpsMitmConfig) -> Result<Self, Self::Error> {
        let config = Self {
            enabled: s.enabled,
            intercept_hosts: s.intercept_hosts,
            bypass_hosts: s.bypass_hosts,
            cert_ttl: s.cert_ttl,
            cert_cache_capacity: s.cert_cache_capacity,
            strict_hosts: s.strict_hosts,
        };
        validate_host_patterns(
            "interceptor.https_mitm.intercept_hosts",
            &config.intercept_hosts,
            HostSyntax::Dns,
        )?;
        validate_host_patterns(
            "interceptor.https_mitm.bypass_hosts",
            &config.bypass_hosts,
            HostSyntax::DnsOrUnderscore,
        )?;
        validate_host_patterns(
            "interceptor.https_mitm.strict_hosts",
            &config.strict_hosts,
            HostSyntax::Dns,
        )?;
        // Empty intercept_hosts → MITM inactive (see `is_active`); skip the
        // active-only invariants below instead of rejecting the config.
        if config.is_active() {
            if config.cert_ttl.is_zero() {
                return Err(HttpsMitmConfigError::ZeroCertTtl);
            }
            if config.cert_cache_capacity == 0 {
                return Err(HttpsMitmConfigError::ZeroCertCacheCapacity);
            }
        }
        Ok(config)
    }
}

impl HttpsMitmConfig {
    /// Returns `true` when MITM interception is effectively in force.
    ///
    /// MITM is active only when explicitly enabled *and* at least one
    /// `intercept_hosts` pattern is configured. An enabled MITM with an
    /// empty host list has nothing to intercept, so it is treated as
    /// disabled rather than as a fatal misconfiguration.
    ///
    /// Nothing generates that shape: `firma config` writes no `intercept_hosts`
    /// at all, and the default is every host. Writing `intercept_hosts = []` by
    /// hand is therefore a deliberate opt-out of interception for every host,
    /// and the only one that `enabled` does not spell out — it is kept because
    /// an empty selection is not ambiguous, not because a generated file needs
    /// it.
    ///
    /// Neither spelling survives `firma config`, which strips `enabled`,
    /// `intercept_hosts` and `strict_hosts` on every run. The global opt-out
    /// that does is `bypass_hosts = ["*"]`: the pattern matches every host and
    /// is checked before interception, so every tunnel is relayed uninspected
    /// while the key itself is merged rather than removed.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && !self.intercept_hosts.is_empty()
    }

    /// Sets whether TLS MITM interception is enabled.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Replaces the host patterns that should be intercepted.
    #[must_use]
    pub fn with_intercept_hosts(mut self, hosts: Vec<String>) -> Self {
        self.intercept_hosts = hosts;
        self
    }

    /// Replaces the host patterns that bypass interception.
    #[must_use]
    pub fn with_bypass_hosts(mut self, hosts: Vec<String>) -> Self {
        self.bypass_hosts = hosts;
        self
    }

    /// Replaces the host patterns whose interception failures are hard denials.
    #[must_use]
    pub fn with_strict_hosts(mut self, hosts: Vec<String>) -> Self {
        self.strict_hosts = hosts;
        self
    }
}

impl Default for HttpsMitmConfig {
    fn default() -> Self {
        let d = schema_ic::HttpsMitmConfig::default();
        Self {
            enabled: d.enabled,
            intercept_hosts: d.intercept_hosts,
            bypass_hosts: d.bypass_hosts,
            cert_ttl: d.cert_ttl,
            cert_cache_capacity: d.cert_cache_capacity,
            strict_hosts: d.strict_hosts,
        }
    }
}

/// Policy source settings.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Directory containing `.cedar` policy files.
    dir: PathBuf,
}

/// Error validating a [`PolicyConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyConfigError {
    /// `sidecar.policy.dir` was empty.
    #[error("policy.dir must not be empty")]
    EmptyDir,
}

impl TryFrom<schema_infra::PolicyConfig> for PolicyConfig {
    type Error = PolicyConfigError;

    fn try_from(s: schema_infra::PolicyConfig) -> Result<Self, Self::Error> {
        if s.dir.as_os_str().is_empty() {
            return Err(PolicyConfigError::EmptyDir);
        }
        Ok(Self { dir: s.dir })
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            dir: schema_infra::PolicyConfig::default().dir,
        }
    }
}

/// Certificate authority directory settings.
#[derive(Debug, Clone)]
pub struct CaConfig {
    /// Directory containing the HTTPS MITM CA key material.
    ///
    /// Always resolved: an unset `sidecar.ca.dir` becomes the state
    /// directory's `generated-firma-ca`.
    pub(crate) dir: PathBuf,
}

/// Error validating a [`CaConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaConfigError {
    /// `sidecar.ca.dir` was set but empty.
    #[error("ca.dir must not be empty when set")]
    EmptyDir,
}

impl CaConfig {
    /// Validate `schema`, defaulting an unset directory to the state
    /// directory's generated CA.
    ///
    /// `firma config` writes that same path into `firma.toml`, so a
    /// hand-written config and a scaffolded one mint one CA rather than two.
    ///
    /// # Errors
    ///
    /// Returns [`CaConfigError::EmptyDir`] when the directory is set but empty.
    fn resolve(
        schema: schema_infra::CaConfig,
        state: &firma_runtime_state::RuntimeLayout,
    ) -> Result<Self, CaConfigError> {
        match schema.dir {
            Some(dir) if dir.as_os_str().is_empty() => Err(CaConfigError::EmptyDir),
            Some(dir) => Ok(Self { dir }),
            None => Ok(Self {
                dir: state.generated_ca_dir(),
            }),
        }
    }
}

/// Credential injection entry for a single external target.
///
/// Each entry selects a mode (`basic` or `vault`) and provides the
/// fields that mode requires. At proxy time, matching outbound requests
/// have the specified header injected.
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// Injection mode. Default: `basic`.
    pub(crate) mode: CredentialMode,
    /// Host that this credential applies to.
    pub(crate) target_host: String,
    /// HTTP header name to inject (e.g. `Authorization`).
    pub(crate) header: HeaderName,
    /// Optional prefix prepended to the resolved value
    /// (e.g. `"Bearer "`).
    pub(crate) prefix: Option<String>,
    /// Optional transform applied to the resolved secret before injection.
    pub(crate) transform: Option<CredentialTransform>,
    // -- basic mode fields --
    /// Environment variable whose value is injected (basic mode).
    pub(crate) value_from_env: Option<String>,
    // -- vault mode fields --
    /// Filesystem path to the secret file rendered by Vault Agent
    /// (vault mode).
    pub(crate) secret_path: Option<PathBuf>,
}

/// Error validating a [`CredentialConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialConfigError {
    /// `target_host` was empty.
    #[error("target_host must not be empty")]
    EmptyTargetHost,
    /// `header` was not a valid HTTP header name.
    #[error("header '{header}' is invalid")]
    InvalidHeader {
        /// The rejected header string.
        header: String,
    },
    /// `prefix` was combined with `transform`.
    #[error("prefix cannot be combined with transform")]
    PrefixWithTransform,
    /// `basic` mode was selected without `value_from_env`.
    #[error("value_from_env is required for basic mode")]
    ValueFromEnvRequired,
    /// `vault` mode was selected without `secret_path`.
    #[error("secret_path is required for vault mode")]
    SecretPathRequired,
}

impl TryFrom<schema_infra::CredentialConfig> for CredentialConfig {
    type Error = CredentialConfigError;

    fn try_from(s: schema_infra::CredentialConfig) -> Result<Self, Self::Error> {
        if s.target_host.trim().is_empty() {
            return Err(CredentialConfigError::EmptyTargetHost);
        }
        let header =
            s.header
                .parse::<HeaderName>()
                .map_err(|_| CredentialConfigError::InvalidHeader {
                    header: s.header.clone(),
                })?;
        if s.transform.is_some() && s.prefix.is_some() {
            return Err(CredentialConfigError::PrefixWithTransform);
        }
        match s.mode {
            CredentialMode::Basic => {
                if s.value_from_env.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(CredentialConfigError::ValueFromEnvRequired);
                }
            }
            CredentialMode::Vault => {
                if s.secret_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(CredentialConfigError::SecretPathRequired);
                }
            }
        }
        Ok(Self {
            mode: s.mode,
            target_host: s.target_host,
            header,
            prefix: s.prefix,
            transform: s.transform,
            value_from_env: s.value_from_env,
            secret_path: s.secret_path,
        })
    }
}

/// Error validating a host-pattern list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostPatternError {
    /// A pattern entry was empty.
    #[error("{field}[{index}] must not be empty")]
    Empty {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
    },
    /// A `*.` wildcard had no suffix.
    #[error("{field}[{index}] wildcard pattern must include a suffix after '*.'")]
    WildcardMissingSuffix {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
    },
    /// A wildcard pattern had more than a single leading `*.`.
    #[error("{field}[{index}] wildcard pattern supports only a single leading '*.'")]
    WildcardMultiple {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
    },
    /// A wildcard suffix was an IP literal.
    #[error("{field}[{index}] wildcard patterns do not support IP literals")]
    WildcardIpLiteral {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
    },
    /// A wildcard suffix had fewer than two DNS labels.
    #[error("{field}[{index}] wildcard suffix must contain at least two DNS labels")]
    WildcardTooFewLabels {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
    },
    /// A non-leading `*` appeared in a pattern.
    #[error("{field}[{index}] wildcard patterns must use only a leading '*.'")]
    WildcardNotLeading {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
    },
    /// A pattern was not a valid DNS hostname.
    #[error("{field}[{index}]: {source}")]
    Dns {
        /// The offending field.
        field: &'static str,
        /// Index of the offending entry.
        index: usize,
        /// The DNS validation failure.
        #[source]
        source: DnsHostnameError,
    },
}

/// Which host literals a host-pattern field accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostSyntax {
    /// Strict DNS names only.
    ///
    /// Used by the fields that select hosts *for* interception, and by leaf
    /// certificate issuance itself: the Sidecar has to issue a certificate for
    /// a host it intercepts, and a name outside strict DNS has no certificate
    /// to carry it.
    Dns,
    /// Strict DNS names plus underscore labels.
    ///
    /// Used by `bypass_hosts`, which is the only way out of the
    /// intercept-everything default. It must be able to name a host the
    /// Sidecar *cannot* intercept, and the underscore names common in
    /// internal DNS are exactly that: [`HostSyntax::Dns`] rejects them and
    /// certificate issuance fails on them, so with no way to list one the
    /// host would be denied with no escape hatch.
    DnsOrUnderscore,
}

fn validate_host_patterns(
    field: &'static str,
    patterns: &[String],
    syntax: HostSyntax,
) -> Result<(), HostPatternError> {
    for (index, pattern) in patterns.iter().enumerate() {
        let normalized = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(HostPatternError::Empty { field, index });
        }
        if normalized == "*" {
            continue;
        }
        if let Some(suffix) = normalized.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err(HostPatternError::WildcardMissingSuffix { field, index });
            }
            if suffix.contains('*') {
                return Err(HostPatternError::WildcardMultiple { field, index });
            }
            if suffix.parse::<IpAddr>().is_ok() {
                return Err(HostPatternError::WildcardIpLiteral { field, index });
            }
            if suffix.split('.').count() < 2 {
                return Err(HostPatternError::WildcardTooFewLabels { field, index });
            }
            validate_dns_hostname(suffix, syntax).map_err(|source| HostPatternError::Dns {
                field,
                index,
                source,
            })?;
            continue;
        }
        if normalized.contains('*') {
            return Err(HostPatternError::WildcardNotLeading { field, index });
        }
        if normalized.parse::<IpAddr>().is_ok() {
            continue;
        }
        validate_dns_hostname(&normalized, syntax).map_err(|source| HostPatternError::Dns {
            field,
            index,
            source,
        })?;
    }
    Ok(())
}

/// Error validating a DNS hostname.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsHostnameError {
    /// The hostname was empty.
    #[error("invalid DNS hostname: empty value")]
    Empty,
    /// The hostname exceeded 253 characters.
    #[error("invalid DNS hostname: exceeds 253-character limit")]
    TooLong,
    /// The hostname contained an empty label.
    #[error("invalid DNS hostname: contains empty label")]
    EmptyLabel,
    /// A label exceeded 63 characters.
    #[error("invalid DNS hostname: label '{label}' exceeds 63-character limit")]
    LabelTooLong {
        /// The offending label.
        label: String,
    },
    /// A label started or ended with `-`.
    #[error("invalid DNS hostname: label '{label}' starts/ends with '-'")]
    LabelHyphen {
        /// The offending label.
        label: String,
    },
    /// A label contained non-DNS characters.
    #[error("invalid DNS hostname: label '{label}' contains non-DNS characters")]
    LabelInvalidChars {
        /// The offending label.
        label: String,
    },
}

/// Checks `host` against the DNS label rules `syntax` admits.
///
/// Shared with leaf certificate issuance
/// (`interceptor::https_mitm::leaf_certificate_params`), which validates the
/// name it is about to put in a SAN. The length limits, hyphen rules and
/// allowed characters are the same question there, asked of a single host
/// rather than of a configured pattern, so there is one implementation and
/// `syntax` is the only thing that varies.
pub(crate) fn validate_dns_hostname(
    host: &str,
    syntax: HostSyntax,
) -> Result<(), DnsHostnameError> {
    if host.is_empty() {
        return Err(DnsHostnameError::Empty);
    }
    if host.len() > 253 {
        return Err(DnsHostnameError::TooLong);
    }

    for label in host.split('.') {
        if label.is_empty() {
            return Err(DnsHostnameError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(DnsHostnameError::LabelTooLong {
                label: label.to_string(),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DnsHostnameError::LabelHyphen {
                label: label.to_string(),
            });
        }
        let label_is_valid = label.chars().all(|c| match c {
            '_' => syntax == HostSyntax::DnsOrUnderscore,
            c => c.is_ascii_alphanumeric() || c == '-',
        });
        if !label_is_valid {
            return Err(DnsHostnameError::LabelInvalidChars {
                label: label.to_string(),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Local-exec governance endpoint configuration
// ---------------------------------------------------------------------------

/// Configuration for the local-exec governance UDS endpoint.
///
/// When present in `SidecarConfig`, the sidecar binds an additional Unix
/// domain socket that `firma-run` clients contact for pre-execution governance
/// decisions. This is the server-side counterpart to the
/// `sidecar_local_exec` section in the `firma-run` profile config.
#[derive(Debug, Clone)]
pub struct LocalExecConfig {
    /// Absolute path to the Unix domain socket file.
    pub(crate) socket_path: PathBuf,
    /// Policy applied to every fresh local-exec request.
    pub(crate) default_action: firma_config_schema::sidecar::local_exec::DefaultAction,
    /// Approval token time-to-live.
    pub(crate) token_ttl: NonZeroDuration,
    /// Suggested retry interval returned to `firma-run` in `pending_hitl`
    /// responses, in the millisecond wire unit (default: 500).
    pub(crate) retry_after_ms: NonZeroU64,
}

/// Error validating a [`LocalExecConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalExecConfigError {
    /// `socket_path` was not absolute.
    #[error("local_exec.socket_path must be absolute, got: {}", .0.display())]
    SocketPathNotAbsolute(PathBuf),
    /// `token_ttl` was zero.
    #[error("local_exec.token_ttl must be > 0")]
    ZeroTokenTtl,
    /// `retry_after` was positive but shorter than the millisecond wire unit.
    #[error("local_exec.retry_after must be at least 1ms")]
    RetryAfterBelowOneMillisecond,
    /// `retry_after` cannot be represented by the millisecond wire field.
    #[error("local_exec.retry_after exceeds the supported millisecond range")]
    RetryAfterTooLarge,
}

impl TryFrom<schema_le::LocalExecConfig> for LocalExecConfig {
    type Error = LocalExecConfigError;

    fn try_from(s: schema_le::LocalExecConfig) -> Result<Self, Self::Error> {
        if !s.socket_path.is_absolute() {
            return Err(LocalExecConfigError::SocketPathNotAbsolute(s.socket_path));
        }
        let token_ttl =
            NonZeroDuration::new(s.token_ttl).map_err(|_| LocalExecConfigError::ZeroTokenTtl)?;
        let retry_after_ms = u64::try_from(s.retry_after.duration().as_millis())
            .map_err(|_| LocalExecConfigError::RetryAfterTooLarge)?;
        let retry_after_ms = NonZeroU64::new(retry_after_ms)
            .ok_or(LocalExecConfigError::RetryAfterBelowOneMillisecond)?;
        Ok(Self {
            socket_path: s.socket_path,
            default_action: s.default_action,
            token_ttl,
            retry_after_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bytesize::ByteSize;
    use firma_config_schema::sidecar::{AuditSink, SessionStateBackend};

    use super::*;

    /// A default schema-level sidecar config, the deserialize target that the
    /// validated [`SidecarConfig`] is built from by [`SidecarConfig::resolve`].
    fn schema_sidecar() -> firma_config_schema::sidecar::SidecarConfig {
        let mut schema = firma_config_schema::sidecar::SidecarConfig::default();
        schema.authority.url = Some("http://127.0.0.1:50051".to_string());
        schema
    }

    /// A fixed state root. These cases are about validation and re-basing, so
    /// the resolved defaults only need to be predictable and absolute.
    fn state() -> firma_runtime_state::RuntimeLayout {
        firma_runtime_state::RuntimeLayout::from_root("/state")
    }

    /// A validated config with nothing configured.
    fn resolved_default() -> SidecarConfig {
        SidecarConfig::resolve(schema_sidecar(), &state()).expect("defaults are valid")
    }

    // -- SidecarConfig ------------------------------------------------------

    #[test]
    fn rebase_rewrites_default_policy_dir_only() {
        use std::path::PathBuf;
        let mut c = resolved_default();
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(c.policy.dir, PathBuf::from("/cfg/policies"));
    }

    #[test]
    fn rebase_preserves_explicit_policy_dir() {
        use std::path::PathBuf;
        let mut c = resolved_default();
        c.policy.dir = PathBuf::from("/explicit/policies");
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(c.policy.dir, PathBuf::from("/explicit/policies"));
    }

    #[test]
    fn rebase_leaves_ca_dir_alone() {
        use std::path::PathBuf;
        let mut c = resolved_default();
        let before = c.ca.dir.clone();
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(c.ca.dir, before);
    }

    #[test]
    fn rebase_rewrites_relative_authority_ca_cert_path() {
        use std::path::PathBuf;
        let mut c = resolved_default();
        c.authority.ca_cert_path = Some(PathBuf::from("authority-ca.crt"));
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(
            c.authority.ca_cert_path,
            Some(PathBuf::from("/cfg/authority-ca.crt"))
        );
    }

    #[test]
    fn rebase_rewrites_resource_paths_and_preserves_state_paths() {
        let mut c = resolved_default();
        c.authority.tls_client_cert_path = Some(PathBuf::from("tls/client.crt"));
        c.authority.tls_client_key_path = Some(PathBuf::from("tls/client.key"));
        c.credentials.insert(
            "vault".to_string(),
            CredentialConfig {
                mode: CredentialMode::Vault,
                target_host: "api.example.com".to_string(),
                header: "authorization".parse().unwrap(),
                prefix: None,
                transform: None,
                value_from_env: None,
                secret_path: Some(PathBuf::from("secrets/token")),
            },
        );
        c.interceptor.socket_path = Some(PathBuf::from("runtime/sidecar.sock"));
        c.audit.buffer_path = Some(PathBuf::from("state/audit-buffer.jsonl"));
        c.enforcement.constraint_enforcement.path = Some(PathBuf::from("state/sessions"));
        c.ca.dir = PathBuf::from("state/ca");

        c.rebase_defaults(std::path::Path::new("/cfg"));

        assert_eq!(
            c.authority.tls_client_cert_path,
            Some(PathBuf::from("/cfg/tls/client.crt"))
        );
        assert_eq!(
            c.authority.tls_client_key_path,
            Some(PathBuf::from("/cfg/tls/client.key"))
        );
        assert_eq!(
            c.credentials["vault"].secret_path,
            Some(PathBuf::from("/cfg/secrets/token"))
        );
        assert_eq!(
            c.interceptor.socket_path,
            Some(PathBuf::from("runtime/sidecar.sock"))
        );
        assert_eq!(
            c.audit.buffer_path,
            Some(PathBuf::from("/cfg/state/audit-buffer.jsonl"))
        );
        assert_eq!(
            c.enforcement.constraint_enforcement.path,
            Some(PathBuf::from("state/sessions"))
        );
        assert_eq!(c.ca.dir, PathBuf::from("state/ca"));
    }

    #[test]
    fn test_sidecar_config_defaults_valid() {
        let config = SidecarConfig::resolve(schema_sidecar(), &state()).expect("defaults valid");
        assert!(
            config.interceptor.https_mitm.enabled,
            "MITM should be enabled by default"
        );
        assert_eq!(
            config.interceptor.https_mitm.intercept_hosts,
            vec!["*".to_string()],
            "every host is intercepted by default"
        );
        assert_eq!(
            config.interceptor.https_mitm.strict_hosts,
            vec!["*".to_string()],
            "a host that cannot be intercepted is denied, not tunnelled"
        );
        assert!(
            config.interceptor.https_mitm.bypass_hosts.is_empty(),
            "narrowing the default is an explicit operator decision"
        );
    }

    #[test]
    fn bypass_hosts_accept_an_underscore_host_the_sidecar_cannot_intercept() {
        // `intercept_hosts` defaults to every host, and certificate issuance
        // fails on a name outside strict DNS. `bypass_hosts` is the only way
        // out of that default, so it has to be able to name such a host —
        // otherwise the host is denied with no escape hatch.
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.bypass_hosts = vec!["my_service.internal".to_string()];
        let config = SidecarConfig::resolve(schema, &state()).expect("underscore bypass accepted");
        assert_eq!(
            config.interceptor.https_mitm.bypass_hosts,
            vec!["my_service.internal".to_string()]
        );
    }

    #[test]
    fn intercept_hosts_still_reject_an_underscore_host() {
        // Selecting a host *for* interception commits the Sidecar to issuing a
        // leaf certificate for it, which strict DNS has to allow.
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.intercept_hosts = vec!["my_service.internal".to_string()];
        let err =
            SidecarConfig::resolve(schema, &state()).expect_err("underscore intercept rejected");
        assert!(
            format!("{err}").contains("non-DNS characters"),
            "expected a DNS character error, got: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_seeds_require_public_key() {
        let mut schema = schema_sidecar();
        schema.capability_seed.paths = vec![std::path::PathBuf::from("./capability.toml")];
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::MissingPublicKeyForSeeds)
        ));
    }

    #[test]
    fn test_sidecar_config_seeds_with_public_key_valid() {
        let mut schema = schema_sidecar();
        schema.capability_seed.paths = vec![std::path::PathBuf::from("./capability.toml")];
        schema.authority.public_key_path = Some(std::path::PathBuf::from("./authority.pub"));
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    fn credential(mode: CredentialMode) -> schema_infra::CredentialConfig {
        schema_infra::CredentialConfig {
            mode,
            target_host: "api.example.com".to_string(),
            header: "authorization".to_string(),
            prefix: None,
            transform: None,
            value_from_env: None,
            secret_path: None,
        }
    }

    #[test]
    fn test_sidecar_config_invalid_credential_basic() {
        let mut schema = schema_sidecar();
        schema.credentials.insert(
            "bad".to_string(),
            schema_infra::CredentialConfig {
                target_host: String::new(),
                value_from_env: Some("KEY".to_string()),
                ..credential(CredentialMode::Basic)
            },
        );
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Credential { label, source: CredentialConfigError::EmptyTargetHost })
                if label == "bad"
        ));
    }

    #[test]
    fn test_sidecar_config_invalid_credential_basic_missing_env() {
        let mut schema = schema_sidecar();
        schema
            .credentials
            .insert("noenv".to_string(), credential(CredentialMode::Basic));
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Credential {
                source: CredentialConfigError::ValueFromEnvRequired,
                ..
            })
        ));
    }

    #[test]
    fn test_sidecar_config_credential_transform_rejects_prefix() {
        let mut schema = schema_sidecar();
        schema.credentials.insert(
            "github".to_string(),
            schema_infra::CredentialConfig {
                target_host: "github.com".to_string(),
                value_from_env: Some("GITHUB_TOKEN".to_string()),
                prefix: Some("Bearer ".to_string()),
                transform: Some(CredentialTransform::GithubPatBasic),
                ..credential(CredentialMode::Basic)
            },
        );
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Credential {
                source: CredentialConfigError::PrefixWithTransform,
                ..
            })
        ));
    }

    #[test]
    fn test_sidecar_config_invalid_credential_vault_missing_path() {
        let mut schema = schema_sidecar();
        schema
            .credentials
            .insert("novault".to_string(), credential(CredentialMode::Vault));
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Credential {
                source: CredentialConfigError::SecretPathRequired,
                ..
            })
        ));
    }

    #[test]
    fn test_sidecar_config_zero_max_request_body_rejected() {
        let mut schema = schema_sidecar();
        schema.interceptor.max_request_body_size = ByteSize::b(0);
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::ZeroMaxRequestBody
            ))
        ));
    }

    #[test]
    fn test_sidecar_config_zero_max_decompressed_body_rejected() {
        let mut schema = schema_sidecar();
        schema.interceptor.max_decompressed_body_size = ByteSize::b(0);
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::ZeroMaxDecompressedBody
            ))
        ));
    }

    #[test]
    fn test_sidecar_config_zero_total_body_budget_rejected() {
        let mut schema = schema_sidecar();
        schema.interceptor.total_body_budget = ByteSize::b(0);
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::ZeroTotalBodyBudget
            ))
        ));
    }

    #[test]
    fn test_sidecar_config_budget_smaller_than_max_body_rejected() {
        let mut schema = schema_sidecar();
        schema.interceptor.max_request_body_size = ByteSize::mib(8);
        schema.interceptor.total_body_budget = ByteSize::mib(4);
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::TotalBodyBudgetBelowRequest
            ))
        ));
    }

    #[test]
    fn test_sidecar_config_budget_equals_max_body_valid() {
        let mut schema = schema_sidecar();
        schema.interceptor.max_request_body_size = ByteSize::mib(4);
        schema.interceptor.total_body_budget = ByteSize::mib(4);
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[test]
    fn test_https_mitm_enabled_with_empty_intercept_hosts_is_disabled_not_fatal() {
        // `firma config` emits an empty intercept_hosts list.
        // Standalone `firma sidecar --config` must not crash on it; an enabled
        // MITM with no hosts to intercept is treated as effectively disabled.
        let mitm = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: Vec::new(),
            ..HttpsMitmConfig::default()
        };
        assert!(
            !mitm.is_active(),
            "MITM with no intercept hosts must be inactive"
        );
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.enabled = true;
        schema.interceptor.https_mitm.intercept_hosts = Vec::new();
        assert!(
            SidecarConfig::resolve(schema, &state()).is_ok(),
            "empty intercept_hosts must not be fatal"
        );
    }

    #[test]
    fn test_https_mitm_enabled_with_intercept_hosts_is_active() {
        let mitm = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec!["api.openai.com".to_string()],
            ..HttpsMitmConfig::default()
        };
        assert!(mitm.is_active(), "MITM with intercept hosts must be active");
    }

    #[test]
    fn test_https_mitm_rejects_empty_host_pattern() {
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.enabled = true;
        schema.interceptor.https_mitm.intercept_hosts = vec![" ".to_string()];
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::HttpsMitm(HttpsMitmConfigError::HostPattern(
                    HostPatternError::Empty {
                        field: "interceptor.https_mitm.intercept_hosts",
                        ..
                    }
                ))
            ))
        ));
    }

    #[test]
    fn test_https_mitm_rejects_non_leading_wildcard_pattern() {
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.enabled = true;
        schema.interceptor.https_mitm.intercept_hosts = vec!["api.*.openai.com".to_string()];
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::HttpsMitm(HttpsMitmConfigError::HostPattern(
                    HostPatternError::WildcardNotLeading { .. }
                ))
            ))
        ));
    }

    #[test]
    fn test_https_mitm_rejects_top_level_wildcard_suffix() {
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.enabled = true;
        schema.interceptor.https_mitm.intercept_hosts = vec!["*.com".to_string()];
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::HttpsMitm(HttpsMitmConfigError::HostPattern(
                    HostPatternError::WildcardTooFewLabels { .. }
                ))
            ))
        ));
    }

    #[test]
    fn test_https_mitm_enabled_config_valid() {
        let mut schema = schema_sidecar();
        schema.interceptor.https_mitm.enabled = true;
        schema.interceptor.https_mitm.intercept_hosts = vec!["api.openai.com".to_string()];
        schema.interceptor.https_mitm.bypass_hosts = vec!["example.com".to_string()];
        schema.interceptor.https_mitm.strict_hosts = vec!["api.openai.com".to_string()];
        schema.interceptor.https_mitm.cert_ttl = Duration::from_mins(1);
        schema.interceptor.https_mitm.cert_cache_capacity = 8;
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_socket_mode_allows_absent_path() {
        // An absent socket_path is valid; the lifecycle runtime layout supplies
        // the default socket path at startup.
        let mut schema = schema_sidecar();
        schema.interceptor.mode = InterceptorMode::UnixSocket;
        schema.interceptor.socket_path = None;
        let config = SidecarConfig::resolve(schema, &state()).expect("absent path is valid");
        assert_eq!(config.interceptor.socket_path, None);
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_socket_mode_rejects_empty_path() {
        let mut schema = schema_sidecar();
        schema.interceptor.mode = InterceptorMode::UnixSocket;
        schema.interceptor.socket_path = Some(PathBuf::new());
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::Interceptor(
                InterceptorConfigError::SocketPathEmpty
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_socket_mode_valid() {
        let mut schema = schema_sidecar();
        schema.interceptor.mode = InterceptorMode::UnixSocket;
        schema.interceptor.socket_path = Some(PathBuf::from("/tmp/firma.sock"));
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[test]
    fn test_grpc_mode_defaults_valid() {
        let mut schema = schema_sidecar();
        schema.interceptor.mode = InterceptorMode::Grpc;
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single end-to-end HTTP proxy TOML fixture is easier to review in one test"
    )]
    fn test_full_toml_deserialization_http_proxy() {
        let toml_str = r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"
drain_timeout = "15s"
max_request_body_size = "2 MiB"

[interceptor.connect_relay]
setup_timeout = "12s"
session_max = "15m"

[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.openai.com"]
bypass_hosts = ["example.com"]
strict_hosts = ["api.openai.com"]
cert_ttl = "2m"
cert_cache_capacity = 16

[policy]
dir = "/etc/firma/policies"

[authority]
url = "https://authority.example.com"
ca_cert_path = "/etc/firma/authority-ca.pem"

[ca]
dir = "/etc/firma/ca"

[credentials.openai]
target_host = "api.openai.com"
header = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix = "Bearer "

[revocation]
capacity = 500000
fpr = 0.001
lru_capacity = 50000

[audit]
sink = "grpc"
grpc_url = "https://audit.example.com"
buffer_path = "/var/lib/firma/audit-buffer.jsonl"
buffer_max_size = "50 MiB"
signing_key_path = "/etc/firma/audit.pem"
"#;
        let schema: firma_config_schema::sidecar::SidecarConfig =
            toml::from_str(toml_str).unwrap_or_else(|e| panic!("parse failed: {e}"));
        let config = SidecarConfig::resolve(schema, &state())
            .unwrap_or_else(|e| panic!("validation failed: {e}"));

        assert_eq!(config.interceptor.mode, InterceptorMode::HttpProxy);
        assert_eq!(
            config.interceptor.listen_addr,
            "127.0.0.1:9090".parse().unwrap_or_else(|e| panic!("{e}"))
        );
        assert_eq!(
            config.interceptor.drain_timeout.duration(),
            Duration::from_secs(15)
        );
        assert_eq!(config.interceptor.max_request_body_bytes.get(), 2_097_152);
        assert_eq!(
            config.interceptor.connect_relay.setup_timeout.duration(),
            Duration::from_secs(12)
        );
        assert_eq!(
            config.interceptor.connect_relay.session_max.duration(),
            Duration::from_mins(15)
        );
        assert!(config.interceptor.https_mitm.enabled);
        assert_eq!(
            config.interceptor.https_mitm.intercept_hosts,
            vec!["api.openai.com".to_string()]
        );
        assert_eq!(
            config.interceptor.https_mitm.bypass_hosts,
            vec!["example.com".to_string()]
        );
        assert_eq!(
            config.interceptor.https_mitm.strict_hosts,
            vec!["api.openai.com".to_string()]
        );
        assert_eq!(
            config.interceptor.https_mitm.cert_ttl,
            Duration::from_mins(2)
        );
        assert_eq!(config.interceptor.https_mitm.cert_cache_capacity, 16);
        assert_eq!(config.policy.dir, PathBuf::from("/etc/firma/policies"));
        assert_eq!(config.authority.url, "https://authority.example.com");
        assert_eq!(
            config.authority.ca_cert_path.as_deref(),
            Some(std::path::Path::new("/etc/firma/authority-ca.pem"))
        );
        assert_eq!(config.ca.dir, PathBuf::from("/etc/firma/ca"));
        assert_eq!(config.credentials.len(), 1);
        let openai = &config.credentials["openai"];
        assert_eq!(openai.target_host, "api.openai.com");
        assert_eq!(openai.prefix.as_deref(), Some("Bearer "));
        // New AARM R2 G4 session-state fields default when unset.
        assert_eq!(
            config.enforcement.constraint_enforcement.capacity.get(),
            8192
        );
        assert_eq!(
            config.enforcement.constraint_enforcement.backend,
            SessionStateBackend::Lru
        );
        assert!(config.enforcement.constraint_enforcement.path.is_none());
        assert_eq!(config.revocation.capacity.get(), 500_000);
        assert!((config.revocation.fpr - 0.001).abs() < f64::EPSILON);
        assert_eq!(config.revocation.lru_capacity.get(), 50_000);
        assert_eq!(config.audit.sink, AuditSink::Grpc);
        assert_eq!(
            config.audit.grpc_url.as_deref(),
            Some("https://audit.example.com")
        );
        assert_eq!(
            config.audit.buffer_path.as_deref(),
            Some(std::path::Path::new("/var/lib/firma/audit-buffer.jsonl"))
        );
        assert_eq!(config.audit.buffer_max_bytes, 52_428_800);
        assert_eq!(
            config.audit.signing_key,
            AuditSigningKey::Path(PathBuf::from("/etc/firma/audit.pem"))
        );
    }

    #[test]
    fn test_full_toml_deserialization_grpc() {
        let toml_str = r#"
[interceptor]
mode = "grpc"
listen_addr = "127.0.0.1:9091"
drain_timeout = "10s"
[authority]
url = "http://127.0.0.1:50051"
"#;
        let schema: firma_config_schema::sidecar::SidecarConfig =
            toml::from_str(toml_str).unwrap_or_else(|e| panic!("parse failed: {e}"));
        let config = SidecarConfig::resolve(schema, &state())
            .unwrap_or_else(|e| panic!("validation failed: {e}"));
        assert_eq!(config.interceptor.mode, InterceptorMode::Grpc);
        assert_eq!(
            config.interceptor.listen_addr,
            "127.0.0.1:9091".parse().unwrap_or_else(|e| panic!("{e}"))
        );
    }

    #[test]
    fn authority_http_remote_requires_explicit_opt_in() {
        let mut schema = schema_sidecar();
        schema.authority.url = Some("http://authority.example.com:50051".to_string());
        assert!(matches!(
            SidecarConfig::resolve(schema, &state()),
            Err(SidecarConfigError::InsecureNonLoopbackAuthority)
        ));
    }

    #[test]
    fn authority_http_remote_allowed_with_explicit_opt_in() {
        let mut schema = schema_sidecar();
        schema.authority.url = Some("http://authority.example.com:50051".to_string());
        schema.authority.allow_insecure_remote_authority = true;
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[test]
    fn authority_http_loopback_allowed_without_opt_in() {
        let mut schema = schema_sidecar();
        schema.authority.url = Some("http://127.0.0.1:50051".to_string());
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[test]
    fn authority_http_ipv6_loopback_allowed_without_opt_in() {
        let mut schema = schema_sidecar();
        schema.authority.url = Some("http://[::1]:50051".to_string());
        assert!(SidecarConfig::resolve(schema, &state()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_full_toml_deserialization_unix_socket() {
        let toml_str = r#"
[interceptor]
mode = "unix_socket"
socket_path = "/tmp/firma.sock"
drain_timeout = "10s"
[authority]
url = "http://127.0.0.1:50051"
"#;
        let schema: firma_config_schema::sidecar::SidecarConfig =
            toml::from_str(toml_str).unwrap_or_else(|e| panic!("parse failed: {e}"));
        let config = SidecarConfig::resolve(schema, &state())
            .unwrap_or_else(|e| panic!("validation failed: {e}"));
        assert_eq!(config.interceptor.mode, InterceptorMode::UnixSocket);
        assert_eq!(
            config.interceptor.socket_path.as_deref(),
            Some(std::path::Path::new("/tmp/firma.sock"))
        );
    }
}
