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
mod connector;
mod enforcement;
mod revocation;

pub use self::audit::{AuditConfig, AuditSink};
pub use self::authority::AuthorityConfig;
pub use self::connector::ConnectorConfig;

pub use self::enforcement::{EnforcementConfig, MappingRulesFile};

#[cfg(test)]
pub use self::enforcement::MappingRuleConfig;
pub use self::revocation::RevocationConfig;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
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
    /// Audit event emitter settings.
    #[serde(default)]
    pub audit: AuditConfig,
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
        self.audit.validate().map_err(|e| format!("audit: {e}"))?;
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptorMode {
    /// Pingora-based HTTP forward proxy (default). The agent sets
    /// `HTTP_PROXY=http://localhost:<port>`.
    #[default]
    HttpProxy,
    /// Tonic gRPC hook server. The agent calls the `Intercept` RPC
    /// directly.
    Grpc,
    /// Unix domain socket. Avoids TCP port binding in containers.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    UnixSocket,
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
}

impl InterceptorConfig {
    fn validate(&self) -> Result<(), String> {
        if self.drain_timeout_secs == 0 {
            return Err("interceptor.drain_timeout_secs must be > 0".into());
        }
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
            socket_path: None,
            drain_timeout_secs: default_drain_timeout(),
        }
    }
}

/// Policy source settings.
///
/// The sidecar never loads bundles from disk — the Authority owns the
/// disk source and pushes bundles over `WatchPolicyBundle` (Component
/// Reference §4.6). The sidecar only needs the Authority endpoint plus
/// freshness tuning; freshness lives under
/// `[constraint_enforcement]` alongside Stage 2 settings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    /// Optional Authority gRPC URL. When set, the sidecar streams
    /// policy bundles and revocations from the Authority. Without it
    /// the sidecar boots in a standalone mode where Stage 2 fails
    /// closed with `POLICY_BUNDLE_STALE` until some bundle is
    /// installed.
    #[serde(default)]
    pub authority_url: Option<String>,
}

impl PolicyConfig {
    fn validate(&self) -> Result<(), String> {
        if let Some(ref url) = self.authority_url {
            if url.trim().is_empty() {
                return Err("policy.authority_url must not be empty when set".into());
            }
        }
        Ok(())
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
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

const fn default_drain_timeout() -> u64 {
    30
}

fn default_ca_dir() -> PathBuf {
    PathBuf::from("./firma-ca/")
}

fn default_log_level() -> String {
    "info".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SidecarConfig ------------------------------------------------------

    #[test]
    fn test_sidecar_config_defaults_valid() {
        let config = SidecarConfig::default();
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
    fn test_full_toml_deserialization_http_proxy() {
        let toml_str = r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"
drain_timeout_secs = 15

[policy]
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
