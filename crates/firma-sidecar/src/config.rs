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

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level sidecar configuration
// ---------------------------------------------------------------------------

/// Top-level sidecar configuration deserialized from TOML.
///
/// Contains both infrastructure settings (interceptor, policy, CA,
/// logging, credentials) and enforcement-engine settings (mapping,
/// capability validation, constraint enforcement) via
/// [`EnforcementConfig`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SidecarConfig {
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
    /// Optional pre-flight capability token provisioning.
    ///
    /// When set, the sidecar contacts the Authority at startup to issue
    /// a capability token for the configured agent. This populates Stage 1
    /// with a real token and verifier instead of the stub defaults.
    #[serde(default)]
    pub preflight: Option<PreflightConfig>,
}

impl SidecarConfig {
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
        self.audit.validate().map_err(|e| format!("audit: {e}"))?;
        if let Some(ref pf) = self.preflight {
            pf.validate().map_err(|e| format!("preflight: {e}"))?;
        }
        Ok(())
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
}

impl InterceptorConfig {
    fn validate(&self) -> Result<(), String> {
        if self.drain_timeout_secs == 0 {
            return Err("interceptor.drain_timeout_secs must be > 0".into());
        }
        if self.max_request_body_bytes == 0 {
            return Err("interceptor.max_request_body_bytes must be > 0".into());
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
    #[serde(default)]
    pub strict_hosts: Vec<String>,
}

impl HttpsMitmConfig {
    fn validate(&self) -> Result<(), String> {
        validate_host_patterns(
            "interceptor.https_mitm.intercept_hosts",
            &self.intercept_hosts,
        )?;
        validate_host_patterns("interceptor.https_mitm.bypass_hosts", &self.bypass_hosts)?;
        validate_host_patterns("interceptor.https_mitm.strict_hosts", &self.strict_hosts)?;

        if !self.enabled {
            return Ok(());
        }

        if self.intercept_hosts.is_empty() {
            return Err(
                "interceptor.https_mitm.intercept_hosts must not be empty when MITM is enabled"
                    .to_string(),
            );
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
            strict_hosts: Vec::new(),
        }
    }
}

/// Policy source settings.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// Directory containing `.cedar` policy files.
    #[serde(default = "default_policy_dir")]
    pub dir: PathBuf,
    /// Optional Authority gRPC URL. When set, the sidecar streams
    /// policy bundles and revocations from the Authority.
    #[serde(default)]
    pub authority_url: Option<String>,
}

impl PolicyConfig {
    fn validate(&self) -> Result<(), String> {
        if self.dir.as_os_str().is_empty() {
            return Err("policy.dir must not be empty".into());
        }
        if let Some(ref url) = self.authority_url
            && url.trim().is_empty()
        {
            return Err("policy.authority_url must not be empty when set".into());
        }
        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            dir: default_policy_dir(),
            authority_url: None,
        }
    }
}

/// Pre-flight capability token provisioning settings.
///
/// When present, the sidecar calls `IssueCapability` on the Authority at
/// startup to obtain a real PASETO v4 token and build a live `CapabilityMap`.
/// Requires `policy.authority_url` to also be set.
#[derive(Debug, Clone, Deserialize)]
pub struct PreflightConfig {
    /// Agent identity string (e.g. `"demo0-agent"`).
    pub agent_id: String,
    /// Session identifier for the pre-flight token.
    #[serde(default = "default_preflight_session_id")]
    pub session_id: String,
    /// Action classes the agent is requesting authorization for.
    pub requested_actions: Vec<String>,
    /// Resource scope requested (e.g. `"*"` for any resource).
    #[serde(default = "default_resource_scope")]
    pub resource_scope: String,
    /// Path to the Authority's Ed25519 public key file (32 raw bytes).
    pub authority_pub_key_path: PathBuf,
    /// Requested token TTL in seconds.
    #[serde(default = "default_preflight_ttl_seconds")]
    pub ttl_seconds: i32,
}

impl PreflightConfig {
    /// Validate preflight config fields.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are empty.
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.trim().is_empty() {
            return Err("preflight.agent_id must not be empty".into());
        }
        if self.requested_actions.is_empty() {
            return Err("preflight.requested_actions must not be empty".into());
        }
        if self.authority_pub_key_path.as_os_str().is_empty() {
            return Err("preflight.authority_pub_key_path must not be empty".into());
        }
        Ok(())
    }
}

fn default_preflight_session_id() -> String {
    "preflight-session".to_string()
}

fn default_resource_scope() -> String {
    "*".to_string()
}

const fn default_preflight_ttl_seconds() -> i32 {
    3600
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
        "api.github.com".to_string(),
        "uploads.github.com".to_string(),
    ]
}

fn default_policy_dir() -> PathBuf {
    PathBuf::from("./policies/")
}

fn default_ca_dir() -> PathBuf {
    PathBuf::from("./firma-ca/")
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- SidecarConfig ------------------------------------------------------

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
    fn test_https_mitm_enabled_requires_intercept_hosts() {
        let config = SidecarConfig {
            interceptor: InterceptorConfig {
                https_mitm: HttpsMitmConfig {
                    enabled: true,
                    intercept_hosts: Vec::new(),
                    ..HttpsMitmConfig::default()
                },
                ..InterceptorConfig::default()
            },
            ..SidecarConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("intercept_hosts"),
            "error should mention intercept_hosts: {err}"
        );
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
authority_url = "https://authority.example.com"

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
            config.policy.authority_url.as_deref(),
            Some("https://authority.example.com")
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
