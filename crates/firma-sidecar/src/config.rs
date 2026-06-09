//! Sidecar configuration types.
//!
//! All configuration for the sidecar binary is defined here and
//! deserialized from a single TOML file at startup.
//!
//! The top-level [`SidecarConfig`] embeds the enforcement-specific
//! [`EnforcementConfig`] via `#[serde(flatten)]`, so enforcement
//! sections (`[mapping]`, `[capability_validation]`,
//! `[constraint_enforcement]`) appear as top-level TOML tables rather
//! than nested under an `[enforcement]` prefix.
//!
//! Validated eagerly at startup via [`SidecarConfig::validate`] to
//! surface misconfigurations before the first request arrives.

mod audit;
mod authority;
mod capability_seed;
mod connector;
mod enforcement;
mod revocation;

pub use self::audit::{AuditConfig, AuditSink};
pub use self::authority::AuthorityConfig;
pub use self::capability_seed::{CapabilitySeedConfig, SeedFile};
pub use self::connector::ConnectorConfig;

pub use self::enforcement::{EnforcementConfig, MappingRuleConfig, MappingRulesFile};
pub use self::revocation::RevocationConfig;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use hyper::Uri;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level sidecar configuration
// ---------------------------------------------------------------------------

/// Enforcement mode for the sidecar.
///
/// `enforce` (default): normal fail-closed operation — DENY blocks the call.
/// `monitor`: observe-only — all calls are allowed through, but the pipeline
/// still classifies and evaluates every request. Decisions that would have
/// been DENY are logged as ALLOW with a `monitor_mode: <reason>` annotation
/// so operators can audit traffic before tightening policy.
///
/// **Never deploy `monitor` to production.** The sidecar emits a startup
/// warning when this mode is active.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SidecarMode {
    /// Normal fail-closed enforcement (default).
    #[default]
    Enforce,
    /// Observe-only: classify and log every call, but never block.
    Monitor,
}

/// Top-level sidecar configuration deserialized from TOML.
///
/// Contains both infrastructure settings (interceptor, policy, CA,
/// logging, credentials) and enforcement-engine settings (mapping,
/// capability validation, constraint enforcement) via
/// [`EnforcementConfig`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SidecarConfig {
    /// Enforcement mode: `"enforce"` (default) or `"monitor"`.
    ///
    /// Set `mode = "monitor"` in `firma.toml` to enable observe-only mode.
    /// Never use in production.
    #[serde(default)]
    pub mode: SidecarMode,
    /// Interceptor settings (mode, listen address or socket path,
    /// drain timeout).
    #[serde(default)]
    pub interceptor: InterceptorConfig,
    /// Policy directory and optional authority URL.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Certificate authority directory.
    #[serde(default)]
    pub ca: CaConfig,
    /// Log settings (level only; file/filter come from CLI args).
    #[serde(default)]
    pub log: LogConfig,
    /// Per-target credential injection entries, keyed by an arbitrary
    /// label (e.g. `[credentials.openai]`).
    #[serde(default)]
    pub credentials: HashMap<String, CredentialConfig>,
    /// Outbound connector settings (default timeout + per-host
    /// overrides with rate limits).
    #[serde(default)]
    pub connector: ConnectorConfig,
    /// Background Authority stream client tuning.
    #[serde(default)]
    pub authority: AuthorityConfig,
    /// Enforcement engine settings (mapping rules, capability
    /// validation, constraint enforcement).
    #[serde(flatten)]
    pub enforcement: EnforcementConfig,
    /// Revocation cache settings (bloom filter + LRU sizing).
    #[serde(default)]
    pub revocation: RevocationConfig,
    /// Static capability provisioning for the demo path. Until the
    /// sidecar wires the gRPC `IssueCapability` client, operators can
    /// pre-issue tokens via `firma-authority issue` and list the
    /// resulting TOML files here.
    #[serde(default)]
    pub capability_seed: CapabilitySeedConfig,
    /// Audit event emitter settings.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Local-exec governance endpoint configuration.
    ///
    /// When set, the sidecar binds a UDS endpoint that `firma-run` clients
    /// contact for pre-execution governance decisions. If absent, the
    /// local-exec endpoint is not started.
    #[serde(default)]
    pub local_exec: Option<LocalExecConfig>,
}

impl SidecarConfig {
    /// Load a sidecar configuration from a TOML file and validate it.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the TOML is invalid, or
    /// validation fails.
    pub fn load_from_path(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the entire configuration tree.
    ///
    /// Call immediately after deserialization to surface
    /// misconfigurations at startup rather than at request time.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the first invalid
    /// field.
    pub fn validate(&self) -> Result<(), String> {
        self.interceptor.validate()?;
        self.policy.validate()?;
        self.ca.validate()?;
        self.log.validate()?;
        for (label, cred) in &self.credentials {
            cred.validate()
                .map_err(|e| format!("credentials.{label}: {e}"))?;
        }
        self.connector
            .validate()
            .map_err(|e| format!("connector: {e}"))?;
        self.authority
            .validate()
            .map_err(|e| format!("authority: {e}"))?;
        self.enforcement.validate()?;
        self.revocation.validate()?;
        self.capability_seed
            .validate()
            .map_err(|e| format!("capability_seed: {e}"))?;
        if !self.capability_seed.paths.is_empty() && self.authority.public_key_path.is_none() {
            return Err(
                "authority.public_key_path must be set when capability_seed.paths is non-empty"
                    .to_string(),
            );
        }
        if let Some(ref url) = self.authority.url {
            let uri: Uri = url
                .parse()
                .map_err(|e| format!("authority.url must be a valid URI: {e}"))?;
            match uri.scheme_str() {
                Some("https") => {
                    if self.authority.ca_cert_path.is_none() {
                        return Err(
                            "authority.ca_cert_path must be set when authority.url uses https://"
                                .to_string(),
                        );
                    }
                }
                Some("http") => {
                    let host = uri.host().ok_or_else(|| {
                        "authority.url with http:// must include a host".to_string()
                    })?;
                    let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
                    let is_loopback = host.eq_ignore_ascii_case("localhost")
                        || host_unbracketed
                            .parse::<IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback());
                    if !is_loopback && !self.authority.allow_insecure_remote_authority {
                        return Err("authority.url uses insecure http:// for a non-loopback host; either switch to https:// or set authority.allow_insecure_remote_authority = true".to_string());
                    }
                }
                Some(other) => {
                    return Err(format!(
                        "authority.url scheme must be http or https, got {other}"
                    ));
                }
                None => return Err("authority.url must include a scheme".to_string()),
            }
        }
        self.audit.validate().map_err(|e| format!("audit: {e}"))?;
        if let Some(ref le) = self.local_exec {
            le.validate().map_err(|e| format!("local_exec: {e}"))?;
        }
        Ok(())
    }

    /// Re-base every relative resource path against `config_dir`;
    /// absolute paths are left untouched. No default-name sentinel
    /// check — relative always means "relative to the config file's
    /// directory" for consistency.
    ///
    /// `ca.dir` is intentionally excluded — it is state-managed (its
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
        if let Some(p) = self.audit.signing_key_path.as_mut() {
            rebase(p);
        }
        if let Some(p) = self.audit.file_path.as_mut() {
            rebase(p);
        }
        for p in &mut self.capability_seed.paths {
            rebase(p);
        }
        self.enforcement.rebase_defaults(config_dir);
    }
}

// ---------------------------------------------------------------------------
// Infrastructure sections
// ---------------------------------------------------------------------------

/// Interception mode selector.
///
/// Determines which transport the sidecar uses to capture outbound
/// agent traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptorMode {
    /// Pingora-based HTTP forward proxy. The agent sets
    /// `HTTP_PROXY=http://localhost:<port>`.
    HttpProxy,
    /// Tonic gRPC hook server. The agent calls the `Intercept` RPC
    /// directly.
    Grpc,
    /// Unix domain socket. Avoids TCP port binding in containers.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    UnixSocket,
}

impl Default for InterceptorMode {
    #[cfg(unix)]
    fn default() -> Self {
        Self::UnixSocket
    }
    #[cfg(not(unix))]
    fn default() -> Self {
        Self::HttpProxy
    }
}

impl fmt::Display for InterceptorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpProxy => write!(f, "http_proxy"),
            Self::Grpc => write!(f, "grpc"),
            #[cfg(unix)]
            Self::UnixSocket => write!(f, "unix_socket"),
        }
    }
}

/// Interceptor settings.
///
/// Selects the interception mode and supplies mode-specific
/// parameters:
///
/// | Mode | Required fields |
/// |------|-----------------|
/// | `http_proxy` | `listen_addr` |
/// | `grpc` | `listen_addr` |
/// | `unix_socket` | `socket_path` |
///
/// `drain_timeout_secs` is shared across all modes.
#[derive(Debug, Clone, Deserialize)]
pub struct InterceptorConfig {
    /// Interception mode. Default: `http_proxy`.
    #[serde(default)]
    pub mode: InterceptorMode,
    /// Socket address used by `http_proxy` and `grpc` modes.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    /// Path to the Unix domain socket file, used by `unix_socket`
    /// mode.
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    /// Seconds to wait for in-flight requests to drain on shutdown.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
    /// Maximum request body size accepted by proxy interceptors.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    /// CONNECT/MITM relay timeout controls.
    #[serde(default)]
    pub connect_relay: ConnectRelayConfig,
    /// HTTPS MITM settings used by the HTTP proxy interceptor.
    #[serde(default)]
    pub https_mitm: HttpsMitmConfig,
    /// Global ceiling for the total bytes of request bodies buffered
    /// concurrently across all in-flight proxy connections.  When the
    /// budget is full, new requests receive an immediate 403 denial
    /// with an audit trail rather than silently unbounded buffering
    /// that could OOM-kill the enforcer.
    #[serde(default = "default_total_body_budget_bytes")]
    pub total_body_budget_bytes: usize,
}

impl InterceptorConfig {
    fn validate(&self) -> Result<(), String> {
        if self.drain_timeout_secs == 0 {
            return Err("interceptor.drain_timeout_secs must be > 0".into());
        }
        if self.max_request_body_bytes == 0 {
            return Err("interceptor.max_request_body_bytes must be > 0".into());
        }
        if self.total_body_budget_bytes == 0 {
            return Err("interceptor.total_body_budget_bytes must be > 0".into());
        }
        if self.total_body_budget_bytes < self.max_request_body_bytes {
            return Err(
                "interceptor.total_body_budget_bytes must be >= interceptor.max_request_body_bytes"
                    .into(),
            );
        }
        self.connect_relay.validate()?;
        self.https_mitm.validate()?;
        #[cfg(unix)]
        if self.mode == InterceptorMode::UnixSocket {
            match &self.socket_path {
                Some(p) if p.as_os_str().is_empty() => {
                    return Err(
                        "interceptor.socket_path must not be empty when mode is unix_socket".into(),
                    );
                }
                None => {
                    return Err(
                        "interceptor.socket_path is required when mode is unix_socket".into(),
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            mode: InterceptorMode::default(),
            listen_addr: default_listen_addr(),
            socket_path: Some(default_socket_path()),
            drain_timeout_secs: default_drain_timeout(),
            max_request_body_bytes: default_max_request_body_bytes(),
            connect_relay: ConnectRelayConfig::default(),
            https_mitm: HttpsMitmConfig::default(),
            total_body_budget_bytes: default_total_body_budget_bytes(),
        }
    }
}

/// Timeout controls for CONNECT tunnel and MITM relay sessions.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectRelayConfig {
    /// Timeout for CONNECT upgrade and upstream connect/TLS setup.
    #[serde(default = "default_connect_setup_timeout_secs")]
    pub setup_timeout_secs: u64,
    /// Hard cap for the full tunnel/MITM session lifetime.
    #[serde(default = "default_connect_session_max_secs")]
    pub session_max_secs: u64,
}

impl ConnectRelayConfig {
    fn validate(&self) -> Result<(), String> {
        if self.setup_timeout_secs == 0 {
            return Err("interceptor.connect_relay.setup_timeout_secs must be > 0".into());
        }
        if self.session_max_secs == 0 {
            return Err("interceptor.connect_relay.session_max_secs must be > 0".into());
        }
        Ok(())
    }
}

impl Default for ConnectRelayConfig {
    fn default() -> Self {
        Self {
            setup_timeout_secs: default_connect_setup_timeout_secs(),
            session_max_secs: default_connect_session_max_secs(),
        }
    }
}

/// HTTPS MITM controls for the HTTP proxy interceptor.
///
/// When disabled, HTTPS `CONNECT` requests are handled as blind tunnels.
/// When enabled, hosts matched by `intercept_hosts` are decrypted and
/// re-encrypted by the sidecar.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpsMitmConfig {
    /// Enables TLS MITM interception for selected hosts.
    #[serde(default = "default_https_mitm_enabled")]
    pub enabled: bool,
    /// Optional explicit CA certificate path. Defaults under `ca.dir`.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Optional explicit CA private key path. Defaults under `ca.dir`.
    #[serde(default)]
    pub ca_key_path: Option<PathBuf>,
    /// Host patterns that should be intercepted (supports `*` wildcard).
    #[serde(default = "default_https_mitm_intercept_hosts")]
    pub intercept_hosts: Vec<String>,
    /// Host patterns that should bypass interception and use CONNECT tunnel.
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
    /// Dynamic leaf certificate TTL in seconds.
    #[serde(default = "default_https_mitm_cert_ttl_secs")]
    pub cert_ttl_secs: u64,
    /// Maximum number of cached leaf certificates.
    #[serde(default = "default_https_mitm_cert_cache_capacity")]
    pub cert_cache_capacity: usize,
    /// Host patterns that must be intercepted; failures are hard deny.
    #[serde(default = "default_https_mitm_strict_hosts")]
    pub strict_hosts: Vec<String>,
}

impl HttpsMitmConfig {
    /// Returns `true` when MITM interception is effectively in force.
    ///
    /// MITM is active only when explicitly enabled *and* at least one
    /// `intercept_hosts` pattern is configured. An enabled MITM with an
    /// empty host list has nothing to intercept, so it is treated as
    /// disabled rather than as a fatal misconfiguration:
    /// this lets a `firma config`-scaffolded `firma.toml` — which emits an
    /// empty `intercept_hosts` — start cleanly under standalone
    /// `firma sidecar --config`.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && !self.intercept_hosts.is_empty()
    }

    fn validate(&self) -> Result<(), String> {
        validate_host_patterns(
            "interceptor.https_mitm.intercept_hosts",
            &self.intercept_hosts,
        )?;
        validate_host_patterns("interceptor.https_mitm.bypass_hosts", &self.bypass_hosts)?;
        validate_host_patterns("interceptor.https_mitm.strict_hosts", &self.strict_hosts)?;

        // Empty intercept_hosts → MITM inactive (see `is_active`); skip the
        // active-only invariants below instead of rejecting the config.
        if !self.is_active() {
            return Ok(());
        }

        if self.cert_ttl_secs == 0 {
            return Err("interceptor.https_mitm.cert_ttl_secs must be > 0".to_string());
        }
        if self.cert_cache_capacity == 0 {
            return Err("interceptor.https_mitm.cert_cache_capacity must be > 0".to_string());
        }

        Ok(())
    }
}

impl Default for HttpsMitmConfig {
    fn default() -> Self {
        Self {
            enabled: default_https_mitm_enabled(),
            ca_cert_path: None,
            ca_key_path: None,
            intercept_hosts: default_https_mitm_intercept_hosts(),
            bypass_hosts: Vec::new(),
            cert_ttl_secs: default_https_mitm_cert_ttl_secs(),
            cert_cache_capacity: default_https_mitm_cert_cache_capacity(),
            strict_hosts: default_https_mitm_strict_hosts(),
        }
    }
}

/// Policy source settings.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// Directory containing `.cedar` policy files.
    #[serde(default = "default_policy_dir")]
    pub dir: PathBuf,
}

impl PolicyConfig {
    fn validate(&self) -> Result<(), String> {
        if self.dir.as_os_str().is_empty() {
            return Err("policy.dir must not be empty".into());
        }
        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            dir: default_policy_dir(),
        }
    }
}

/// Certificate authority directory settings.
#[derive(Debug, Clone, Deserialize)]
pub struct CaConfig {
    /// Directory containing CA key material.
    #[serde(default = "default_ca_dir")]
    pub dir: PathBuf,
}

impl CaConfig {
    fn validate(&self) -> Result<(), String> {
        if self.dir.as_os_str().is_empty() {
            return Err("ca.dir must not be empty".into());
        }
        Ok(())
    }
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: default_ca_dir(),
        }
    }
}

/// Log settings sourced from the TOML file.
///
/// The log level set here acts as the base; CLI args (`--log-level`)
/// override it.
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    /// Log level: `trace`, `debug`, `info`, `warn`, or `error`.
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl LogConfig {
    fn validate(&self) -> Result<(), String> {
        let valid = ["trace", "debug", "info", "warn", "error"];
        if !valid.contains(&self.level.to_lowercase().as_str()) {
            return Err(format!(
                "log.level '{}' is invalid; expected one of: {}",
                self.level,
                valid.join(", ")
            ));
        }
        Ok(())
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

/// Credential injection mode selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// Static credential read from an environment variable at startup.
    #[default]
    Basic,
    /// Secret file rendered by Vault Agent, read from disk per-call.
    Vault,
}

/// Credential injection entry for a single external target.
///
/// Each entry selects a mode (`basic` or `vault`) and provides the
/// fields that mode requires. At proxy time, matching outbound requests
/// have the specified header injected.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialConfig {
    /// Injection mode. Default: `basic`.
    #[serde(default)]
    pub mode: CredentialMode,
    /// Host that this credential applies to.
    pub target_host: String,
    /// HTTP header name to inject (e.g. `Authorization`).
    pub header: String,
    /// Optional prefix prepended to the resolved value
    /// (e.g. `"Bearer "`).
    #[serde(default)]
    pub prefix: Option<String>,
    // -- basic mode fields --
    /// Environment variable whose value is injected (basic mode).
    #[serde(default)]
    pub value_from_env: Option<String>,
    // -- vault mode fields --
    /// Filesystem path to the secret file rendered by Vault Agent
    /// (vault mode).
    #[serde(default)]
    pub secret_path: Option<PathBuf>,
}

impl CredentialConfig {
    fn validate(&self) -> Result<(), String> {
        if self.target_host.trim().is_empty() {
            return Err("target_host must not be empty".into());
        }
        if self.header.trim().is_empty() {
            return Err("header must not be empty".into());
        }
        match self.mode {
            CredentialMode::Basic => {
                let env = self.value_from_env.as_deref().unwrap_or("");
                if env.trim().is_empty() {
                    return Err("value_from_env is required for basic mode".into());
                }
            }
            CredentialMode::Vault => {
                let path = self
                    .secret_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .unwrap_or("");
                if path.trim().is_empty() {
                    return Err("secret_path is required for vault mode".into());
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

pub(crate) fn default_socket_path() -> PathBuf {
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()));
    PathBuf::from(xdg).join("firma/sidecar.sock")
}

const fn default_drain_timeout() -> u64 {
    30
}

const fn default_max_request_body_bytes() -> usize {
    4 * 1024 * 1024
}

const fn default_total_body_budget_bytes() -> usize {
    64 * 1024 * 1024
}

const fn default_connect_setup_timeout_secs() -> u64 {
    10
}

const fn default_connect_session_max_secs() -> u64 {
    600
}

const fn default_https_mitm_cert_ttl_secs() -> u64 {
    86_400
}

const fn default_https_mitm_cert_cache_capacity() -> usize {
    1_024
}

const fn default_https_mitm_enabled() -> bool {
    true
}

fn default_https_mitm_intercept_hosts() -> Vec<String> {
    vec![
        "chatgpt.com".to_string(),
        "auth.openai.com".to_string(),
        "api.openai.com".to_string(),
        "api.anthropic.com".to_string(),
        "platform.claude.com".to_string(),
        "claude.ai".to_string(),
        "console.anthropic.com".to_string(),
        "openrouter.ai".to_string(),
        "api.groq.com".to_string(),
        "api.mistral.ai".to_string(),
        "api.cohere.com".to_string(),
        "generativelanguage.googleapis.com".to_string(),
        "aiplatform.googleapis.com".to_string(),
        "api.deepseek.com".to_string(),
        "api.together.xyz".to_string(),
        "api.fireworks.ai".to_string(),
        "api.replicate.com".to_string(),
        "api.perplexity.ai".to_string(),
        "api.x.ai".to_string(),
        "api.supabase.com".to_string(),
        "*.supabase.co".to_string(),
        "api.resend.com".to_string(),
        "api.twilio.com".to_string(),
        "api.sendgrid.com".to_string(),
        "api.stripe.com".to_string(),
        "api.slack.com".to_string(),
        "hooks.slack.com".to_string(),
        "github.com".to_string(),
        "api.github.com".to_string(),
        "uploads.github.com".to_string(),
        "downloads.claude.ai".to_string(),
    ]
}

fn default_https_mitm_strict_hosts() -> Vec<String> {
    default_https_mitm_intercept_hosts()
}

/// Sentinel: unset `policy.dir`.
pub(crate) const DEFAULT_POLICY_DIR: &str = "./policies/";
/// Sentinel: unset `ca.dir` (state-managed; never re-based).
pub(crate) const DEFAULT_CA_DIR: &str = "./firma-ca/";

fn default_policy_dir() -> PathBuf {
    PathBuf::from(DEFAULT_POLICY_DIR)
}

fn default_ca_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CA_DIR)
}

fn default_log_level() -> String {
    "info".to_string()
}

fn validate_host_patterns(field: &str, patterns: &[String]) -> Result<(), String> {
    for (idx, pattern) in patterns.iter().enumerate() {
        let normalized = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(format!("{field}[{idx}] must not be empty"));
        }
        if normalized == "*" {
            continue;
        }
        if let Some(suffix) = normalized.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err(format!(
                    "{field}[{idx}] wildcard pattern must include a suffix after '*.'"
                ));
            }
            if suffix.contains('*') {
                return Err(format!(
                    "{field}[{idx}] wildcard pattern supports only a single leading '*.'"
                ));
            }
            if suffix.parse::<IpAddr>().is_ok() {
                return Err(format!(
                    "{field}[{idx}] wildcard patterns do not support IP literals"
                ));
            }
            if suffix.split('.').count() < 2 {
                return Err(format!(
                    "{field}[{idx}] wildcard suffix must contain at least two DNS labels"
                ));
            }
            validate_dns_hostname(&normalized, suffix)?;
            continue;
        }
        if normalized.contains('*') {
            return Err(format!(
                "{field}[{idx}] wildcard patterns must use only a leading '*.'"
            ));
        }
        if normalized.parse::<IpAddr>().is_ok() {
            continue;
        }
        validate_dns_hostname(&normalized, &normalized)?;
    }
    Ok(())
}

fn validate_dns_hostname(full: &str, host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err(format!("invalid DNS hostname '{full}': empty value"));
    }
    if host.len() > 253 {
        return Err(format!(
            "invalid DNS hostname '{full}': exceeds 253-character limit"
        ));
    }

    for label in host.split('.') {
        if label.is_empty() {
            return Err(format!(
                "invalid DNS hostname '{full}': contains empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "invalid DNS hostname '{full}': label '{label}' exceeds 63-character limit"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "invalid DNS hostname '{full}': label '{label}' starts/ends with '-'"
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "invalid DNS hostname '{full}': label '{label}' contains non-DNS characters"
            ));
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
#[derive(Debug, Clone, Deserialize)]
pub struct LocalExecConfig {
    /// Absolute path to the Unix domain socket file.
    ///
    /// Example: `/run/firma/local-exec.sock`
    pub socket_path: PathBuf,

    /// Policy applied to every fresh local-exec request.
    ///
    /// - `"allow"` — allow all executions unconditionally.
    /// - `"deny"` — deny all executions unconditionally.
    /// - `"pending_hitl"` — require HITL approval via the token flow.
    #[serde(default = "LocalExecConfig::default_action")]
    pub default_action: crate::local_exec::handler::DefaultAction,

    /// Approval token time-to-live in seconds (default: 300).
    #[serde(default = "LocalExecConfig::default_token_ttl_secs")]
    pub token_ttl_secs: u64,

    /// Suggested retry interval returned to `firma-run` in `pending_hitl`
    /// responses (milliseconds, default: 500).
    #[serde(default = "LocalExecConfig::default_retry_after_ms")]
    pub retry_after_ms: u64,
}

impl LocalExecConfig {
    fn default_action() -> crate::local_exec::handler::DefaultAction {
        crate::local_exec::handler::DefaultAction::Deny
    }

    const fn default_token_ttl_secs() -> u64 {
        300
    }

    const fn default_retry_after_ms() -> u64 {
        500
    }

    /// Validate the local-exec configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket path is not absolute.
    pub fn validate(&self) -> Result<(), String> {
        if !self.socket_path.is_absolute() {
            return Err(format!(
                "socket_path must be absolute, got: {}",
                self.socket_path.display()
            ));
        }
        if self.token_ttl_secs == 0 {
            return Err("token_ttl_secs must be > 0".to_string());
        }
        if self.retry_after_ms == 0 {
            return Err("retry_after_ms must be > 0".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- SidecarConfig ------------------------------------------------------

    #[test]
    fn rebase_rewrites_default_policy_dir_only() {
        use std::path::PathBuf;
        let mut c = SidecarConfig::default();
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(c.policy.dir, PathBuf::from("/cfg/policies"));
    }

    #[test]
    fn rebase_preserves_explicit_policy_dir() {
        use std::path::PathBuf;
        let mut c = SidecarConfig::default();
        c.policy.dir = PathBuf::from("/explicit/policies");
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(c.policy.dir, PathBuf::from("/explicit/policies"));
    }

    #[test]
    fn rebase_leaves_ca_dir_alone() {
        use std::path::PathBuf;
        let mut c = SidecarConfig::default();
        let before = c.ca.dir.clone();
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(c.ca.dir, before);
    }

    #[test]
    fn rebase_rewrites_relative_authority_ca_cert_path() {
        use std::path::PathBuf;
        let mut c = SidecarConfig::default();
        c.authority.ca_cert_path = Some(PathBuf::from("authority-ca.crt"));
        c.rebase_defaults(&PathBuf::from("/cfg"));
        assert_eq!(
            c.authority.ca_cert_path,
            Some(PathBuf::from("/cfg/authority-ca.crt"))
        );
    }

    #[test]
    fn test_sidecar_config_defaults_valid() {
        let config = SidecarConfig::default();
        assert!(config.validate().is_ok());
        assert!(
            config.interceptor.https_mitm.enabled,
            "MITM should be enabled by default"
        );
        assert!(
            !config.interceptor.https_mitm.intercept_hosts.is_empty(),
            "default MITM intercept list should not be empty"
        );
        assert!(
            config
                .interceptor
                .https_mitm
                .intercept_hosts
                .contains(&"auth.openai.com".to_string()),
            "default MITM intercept list should include auth.openai.com"
        );
        assert!(
            config
                .interceptor
                .https_mitm
                .intercept_hosts
                .contains(&"platform.claude.com".to_string()),
            "default MITM intercept list should include platform.claude.com"
        );
        assert!(
            config
                .interceptor
                .https_mitm
                .intercept_hosts
                .contains(&"api.anthropic.com".to_string()),
            "default MITM intercept list should include api.anthropic.com"
        );
        assert!(
            config.interceptor.https_mitm.bypass_hosts.is_empty(),
            "default MITM bypass list should be empty"
        );
    }

    #[test]
    fn test_sidecar_config_seeds_require_public_key() {
        let config = SidecarConfig {
            capability_seed: CapabilitySeedConfig {
                paths: vec![std::path::PathBuf::from("./capability.toml")],
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("authority.public_key_path"),
            "error should mention authority.public_key_path: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_seeds_with_public_key_valid() {
        let mut config = SidecarConfig {
            capability_seed: CapabilitySeedConfig {
                paths: vec![std::path::PathBuf::from("./capability.toml")],
            },
            ..SidecarConfig::default()
        };
        config.authority.public_key_path = Some(std::path::PathBuf::from("./authority.pub"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sidecar_config_invalid_log_level() {
        let config = SidecarConfig {
            log: LogConfig {
                level: "verbose".to_string(),
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("log.level"),
            "error should mention log.level: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_invalid_credential_basic() {
        let mut creds = HashMap::new();
        creds.insert(
            "bad".to_string(),
            CredentialConfig {
                mode: CredentialMode::Basic,
                target_host: String::new(),
                header: "Authorization".to_string(),
                value_from_env: Some("KEY".to_string()),
                prefix: None,
                secret_path: None,
            },
        );
        let config = SidecarConfig {
            credentials: creds,
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("credentials.bad"),
            "error should mention credential label: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_invalid_credential_basic_missing_env() {
        let mut creds = HashMap::new();
        creds.insert(
            "noenv".to_string(),
            CredentialConfig {
                mode: CredentialMode::Basic,
                target_host: "api.example.com".to_string(),
                header: "Authorization".to_string(),
                value_from_env: None,
                prefix: None,
                secret_path: None,
            },
        );
        let config = SidecarConfig {
            credentials: creds,
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("value_from_env"),
            "error should mention value_from_env: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_invalid_credential_vault_missing_path() {
        let mut creds = HashMap::new();
        creds.insert(
            "novault".to_string(),
            CredentialConfig {
                mode: CredentialMode::Vault,
                target_host: "api.example.com".to_string(),
                header: "Authorization".to_string(),
                value_from_env: None,
                prefix: None,
                secret_path: None,
            },
        );
        let config = SidecarConfig {
            credentials: creds,
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("secret_path"),
            "error should mention secret_path: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_zero_drain_timeout_rejected() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                drain_timeout_secs: 0,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("drain_timeout_secs"),
            "error should mention drain_timeout_secs: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_zero_max_request_body_rejected() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                max_request_body_bytes: 0,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("max_request_body_bytes"),
            "error should mention max_request_body_bytes: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_zero_total_body_budget_rejected() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                total_body_budget_bytes: 0,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("total_body_budget_bytes"),
            "error should mention total_body_budget_bytes: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_budget_smaller_than_max_body_rejected() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                max_request_body_bytes: 8 * 1024 * 1024,
                total_body_budget_bytes: 4 * 1024 * 1024,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("total_body_budget_bytes"),
            "error should mention total_body_budget_bytes: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_budget_equals_max_body_valid() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                max_request_body_bytes: 4 * 1024 * 1024,
                total_body_budget_bytes: 4 * 1024 * 1024,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        assert!(
            config.validate().is_ok(),
            "budget equal to max_body should be valid"
        );
    }

    #[test]
    fn test_sidecar_config_zero_connect_setup_timeout_rejected() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                connect_relay: ConnectRelayConfig {
                    setup_timeout_secs: 0,
                    ..ConnectRelayConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("connect_relay.setup_timeout_secs"),
            "error should mention connect relay setup timeout: {err}"
        );
    }

    #[test]
    fn test_sidecar_config_zero_connect_session_max_rejected() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                connect_relay: ConnectRelayConfig {
                    session_max_secs: 0,
                    ..ConnectRelayConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("connect_relay.session_max_secs"),
            "error should mention connect relay session timeout: {err}"
        );
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
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                https_mitm: mitm,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        assert!(
            config.validate().is_ok(),
            "empty intercept_hosts must not be fatal: {:?}",
            config.validate()
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
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                https_mitm: HttpsMitmConfig {
                    enabled: true,
                    intercept_hosts: vec![" ".to_string()],
                    ..HttpsMitmConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("interceptor.https_mitm.intercept_hosts"),
            "error should mention MITM host pattern list: {err}"
        );
    }

    #[test]
    fn test_https_mitm_rejects_non_leading_wildcard_pattern() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                https_mitm: HttpsMitmConfig {
                    enabled: true,
                    intercept_hosts: vec!["api.*.openai.com".to_string()],
                    ..HttpsMitmConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("leading '*.'"),
            "error should mention wildcard format: {err}"
        );
    }

    #[test]
    fn test_https_mitm_rejects_top_level_wildcard_suffix() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                https_mitm: HttpsMitmConfig {
                    enabled: true,
                    intercept_hosts: vec!["*.com".to_string()],
                    ..HttpsMitmConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("at least two DNS labels"),
            "error should mention wildcard suffix labels: {err}"
        );
    }

    #[test]
    fn test_https_mitm_enabled_config_valid() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                https_mitm: HttpsMitmConfig {
                    enabled: true,
                    intercept_hosts: vec!["api.openai.com".to_string()],
                    bypass_hosts: vec!["example.com".to_string()],
                    strict_hosts: vec!["api.openai.com".to_string()],
                    cert_ttl_secs: 60,
                    cert_cache_capacity: 8,
                    ..HttpsMitmConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_socket_mode_requires_socket_path() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                mode: InterceptorMode::UnixSocket,
                socket_path: None,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("socket_path"),
            "error should mention socket_path: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_socket_mode_rejects_empty_path() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                mode: InterceptorMode::UnixSocket,
                socket_path: Some(PathBuf::new()),
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("socket_path"),
            "error should mention socket_path: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_socket_mode_valid() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                mode: InterceptorMode::UnixSocket,
                socket_path: Some(PathBuf::from("/tmp/firma.sock")),
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_grpc_mode_defaults_valid() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                mode: InterceptorMode::Grpc,
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_full_toml_deserialization_http_proxy() {
        let toml_str = r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"
drain_timeout_secs = 15
max_request_body_bytes = 2097152

[interceptor.connect_relay]
setup_timeout_secs = 12
session_max_secs = 900

[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.openai.com"]
bypass_hosts = ["example.com"]
strict_hosts = ["api.openai.com"]
cert_ttl_secs = 120
cert_cache_capacity = 16

[policy]
dir = "/etc/firma/policies"

[authority]
url = "https://authority.example.com"
ca_cert_path = "/etc/firma/authority-ca.pem"

[ca]
dir = "/etc/firma/ca"

[log]
level = "debug"

[credentials.openai]
target_host = "api.openai.com"
header = "Authorization"
value_from_env = "OPENAI_API_KEY"
prefix = "Bearer "

[mapping]
rules_path = "/etc/firma/rules.toml"
default_protected = false

[capability_validation]
clock_skew_tolerance_seconds = 5

[constraint_enforcement]
bundle_ttl_seconds = 60

[revocation]
capacity = 500000
fpr = 0.001
lru_capacity = 50000

[audit]
sink = "wal"
grpc_url = "https://audit.example.com"
wal_path = "/var/lib/firma/wal"
wal_max_bytes = 52428800
signing_key_path = "/etc/firma/audit.pem"
"#;
        let config: SidecarConfig =
            toml::from_str(toml_str).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert!(config.validate().is_ok());

        assert_eq!(config.interceptor.mode, InterceptorMode::HttpProxy);
        assert_eq!(
            config.interceptor.listen_addr,
            "127.0.0.1:9090".parse().unwrap_or_else(|e| panic!("{e}"))
        );
        assert_eq!(config.interceptor.drain_timeout_secs, 15);
        assert_eq!(config.interceptor.max_request_body_bytes, 2_097_152);
        assert_eq!(config.interceptor.connect_relay.setup_timeout_secs, 12);
        assert_eq!(config.interceptor.connect_relay.session_max_secs, 900);
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
        assert_eq!(config.interceptor.https_mitm.cert_ttl_secs, 120);
        assert_eq!(config.interceptor.https_mitm.cert_cache_capacity, 16);
        assert_eq!(config.policy.dir, PathBuf::from("/etc/firma/policies"));
        assert_eq!(
            config.authority.url.as_deref(),
            Some("https://authority.example.com")
        );
        assert_eq!(
            config.authority.ca_cert_path.as_deref(),
            Some(std::path::Path::new("/etc/firma/authority-ca.pem"))
        );
        assert_eq!(config.ca.dir, PathBuf::from("/etc/firma/ca"));
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.credentials.len(), 1);
        let openai = &config.credentials["openai"];
        assert_eq!(openai.target_host, "api.openai.com");
        assert_eq!(openai.prefix.as_deref(), Some("Bearer "));
        assert_eq!(
            config.enforcement.mapping.rules_path,
            "/etc/firma/rules.toml"
        );
        assert!(!config.enforcement.mapping.default_protected);
        assert_eq!(
            config
                .enforcement
                .capability_validation
                .clock_skew_tolerance_seconds,
            5
        );
        assert_eq!(
            config.enforcement.constraint_enforcement.bundle_ttl_seconds,
            60
        );
        assert_eq!(config.revocation.capacity, 500_000);
        assert!((config.revocation.fpr - 0.001).abs() < f64::EPSILON);
        assert_eq!(config.revocation.lru_capacity, 50_000);
        assert_eq!(config.audit.sink, audit::AuditSink::Wal);
        assert_eq!(
            config.audit.grpc_url.as_deref(),
            Some("https://audit.example.com")
        );
        assert_eq!(
            config.audit.wal_path.as_deref(),
            Some(std::path::Path::new("/var/lib/firma/wal"))
        );
        assert_eq!(config.audit.wal_max_bytes, 52_428_800);
        assert_eq!(
            config.audit.signing_key_path.as_deref(),
            Some(std::path::Path::new("/etc/firma/audit.pem"))
        );
        assert!(config.audit.signing_key_env.is_none());
    }

    #[test]
    fn test_full_toml_deserialization_grpc() {
        let toml_str = r#"
[interceptor]
mode = "grpc"
listen_addr = "127.0.0.1:9091"
drain_timeout_secs = 10
"#;
        let config: SidecarConfig =
            toml::from_str(toml_str).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert!(config.validate().is_ok());
        assert_eq!(config.interceptor.mode, InterceptorMode::Grpc);
        assert_eq!(
            config.interceptor.listen_addr,
            "127.0.0.1:9091".parse().unwrap_or_else(|e| panic!("{e}"))
        );
    }

    #[test]
    fn authority_http_remote_requires_explicit_opt_in() {
        let mut config = SidecarConfig::default();
        config.authority.url = Some("http://authority.example.com:50051".to_string());
        let err = config.validate().unwrap_err();
        assert!(err.contains("allow_insecure_remote_authority"));
    }

    #[test]
    fn authority_http_remote_allowed_with_explicit_opt_in() {
        let mut config = SidecarConfig::default();
        config.authority.url = Some("http://authority.example.com:50051".to_string());
        config.authority.allow_insecure_remote_authority = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn authority_http_loopback_allowed_without_opt_in() {
        let mut config = SidecarConfig::default();
        config.authority.url = Some("http://127.0.0.1:50051".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn authority_http_ipv6_loopback_allowed_without_opt_in() {
        let mut config = SidecarConfig::default();
        config.authority.url = Some("http://[::1]:50051".to_string());
        assert!(config.validate().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_full_toml_deserialization_unix_socket() {
        let toml_str = r#"
[interceptor]
mode = "unix_socket"
socket_path = "/tmp/firma.sock"
drain_timeout_secs = 10
"#;
        let config: SidecarConfig =
            toml::from_str(toml_str).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert!(config.validate().is_ok());
        assert_eq!(config.interceptor.mode, InterceptorMode::UnixSocket);
        assert_eq!(
            config.interceptor.socket_path.as_deref(),
            Some(std::path::Path::new("/tmp/firma.sock"))
        );
    }
}
