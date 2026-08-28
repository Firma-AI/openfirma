//! Schema for `[sidecar.interceptor]` and its sub-tables.
//!
//! Schema value types own intrinsic invariants. `firma-sidecar` validates
//! cross-field constraints and parses these values into its own interceptor
//! configuration types.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

use crate::utils::NonZeroDuration;

const DEFAULT_DRAIN_TIMEOUT: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(30));
const DEFAULT_CONNECT_SETUP_TIMEOUT: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(10));
const DEFAULT_CONNECT_SESSION_MAX: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_mins(10));

/// Interception mode selector.
///
/// Determines which transport the sidecar uses to capture outbound agent
/// traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptorMode {
    /// HTTP forward proxy (tokio/hyper listener). The agent sets
    /// `HTTP_PROXY=http://localhost:<port>`.
    HttpProxy,
    /// Tonic gRPC hook server. The agent calls the `Intercept` RPC directly.
    Grpc,
    /// Unix domain socket. Avoids TCP port binding in containers.
    #[cfg(unix)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptorConfig {
    /// Interception mode. Default: platform-dependent.
    #[serde(default)]
    pub mode: InterceptorMode,
    /// Socket address used by `http_proxy` and `grpc` modes.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    /// Path to the Unix domain socket file, used by `unix_socket` mode.
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    /// Time to wait for in-flight requests to drain on shutdown.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: NonZeroDuration,
    /// Maximum request body size accepted by proxy interceptors.
    #[serde(
        deserialize_with = "crate::utils::byte_size::deserialize",
        default = "default_max_request_body_size"
    )]
    pub max_request_body_size: ByteSize,
    /// Maximum size a single request or response body may expand to when
    /// decompressed for secret placeholder rehydration or masking. Bounds the
    /// memory a decompression bomb can force the Sidecar to allocate.
    #[serde(
        deserialize_with = "crate::utils::byte_size::deserialize",
        default = "default_max_decompressed_body_size"
    )]
    pub max_decompressed_body_size: ByteSize,
    /// CONNECT/MITM relay timeout controls.
    #[serde(default)]
    pub connect_relay: ConnectRelayConfig,
    /// HTTPS MITM settings used by the HTTP proxy interceptor.
    #[serde(default)]
    pub https_mitm: HttpsMitmConfig,
    /// Global ceiling for the total bytes of request bodies buffered
    /// concurrently across all in-flight proxy connections.
    #[serde(
        deserialize_with = "crate::utils::byte_size::deserialize",
        default = "default_total_body_budget"
    )]
    pub total_body_budget: ByteSize,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            mode: InterceptorMode::default(),
            listen_addr: default_listen_addr(),
            // Match serde: an absent `socket_path` deserializes to `None`. The
            // validating constructor in `firma-sidecar` resolves the default
            // path when `unix_socket` mode leaves it unset.
            socket_path: None,
            drain_timeout: default_drain_timeout(),
            max_request_body_size: default_max_request_body_size(),
            max_decompressed_body_size: default_max_decompressed_body_size(),
            connect_relay: ConnectRelayConfig::default(),
            https_mitm: HttpsMitmConfig::default(),
            total_body_budget: default_total_body_budget(),
        }
    }
}

/// Timeout controls for CONNECT tunnel and MITM relay sessions.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectRelayConfig {
    /// Timeout for CONNECT upgrade and upstream connect/TLS setup.
    #[serde(default = "default_connect_setup_timeout")]
    pub setup_timeout: NonZeroDuration,
    /// Hard cap for the full tunnel/MITM session lifetime.
    #[serde(default = "default_connect_session_max")]
    pub session_max: NonZeroDuration,
}

impl Default for ConnectRelayConfig {
    fn default() -> Self {
        Self {
            setup_timeout: default_connect_setup_timeout(),
            session_max: default_connect_session_max(),
        }
    }
}

/// HTTPS MITM controls for the HTTP proxy interceptor.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsMitmConfig {
    /// Enables TLS MITM interception for selected hosts.
    #[serde(default = "default_https_mitm_enabled")]
    pub enabled: bool,
    /// Optional explicit CA certificate path. Defaults under `sidecar.ca.dir`.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Optional explicit CA private key path. Defaults under `sidecar.ca.dir`.
    #[serde(default)]
    pub ca_key_path: Option<PathBuf>,
    /// Host patterns that should be intercepted (supports `*` wildcard).
    #[serde(default = "default_https_mitm_intercept_hosts")]
    pub intercept_hosts: Vec<String>,
    /// Host patterns that should bypass interception and use CONNECT tunnel.
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
    /// Dynamic leaf certificate TTL.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_https_mitm_cert_ttl"
    )]
    pub cert_ttl: Duration,
    /// Maximum number of cached leaf certificates.
    #[serde(default = "default_https_mitm_cert_cache_capacity")]
    pub cert_cache_capacity: usize,
    /// Host patterns that must be intercepted; failures are hard deny.
    #[serde(default = "default_https_mitm_strict_hosts")]
    pub strict_hosts: Vec<String>,
}

impl Default for HttpsMitmConfig {
    fn default() -> Self {
        Self {
            enabled: default_https_mitm_enabled(),
            ca_cert_path: None,
            ca_key_path: None,
            intercept_hosts: default_https_mitm_intercept_hosts(),
            bypass_hosts: Vec::new(),
            cert_ttl: default_https_mitm_cert_ttl(),
            cert_cache_capacity: default_https_mitm_cert_cache_capacity(),
            strict_hosts: default_https_mitm_strict_hosts(),
        }
    }
}

fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

/// Default Unix domain socket path, derived from `XDG_RUNTIME_DIR`/`HOME`.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()));
    PathBuf::from(xdg).join("firma/sidecar.sock")
}

const fn default_drain_timeout() -> NonZeroDuration {
    DEFAULT_DRAIN_TIMEOUT
}

const fn default_max_request_body_size() -> ByteSize {
    ByteSize::mib(4)
}

const fn default_max_decompressed_body_size() -> ByteSize {
    ByteSize::mb(16)
}

const fn default_total_body_budget() -> ByteSize {
    ByteSize::mib(64)
}

const fn default_connect_setup_timeout() -> NonZeroDuration {
    DEFAULT_CONNECT_SETUP_TIMEOUT
}

const fn default_connect_session_max() -> NonZeroDuration {
    DEFAULT_CONNECT_SESSION_MAX
}

const fn default_https_mitm_cert_ttl() -> Duration {
    Duration::from_hours(24)
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
