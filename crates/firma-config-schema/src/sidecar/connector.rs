//! Schema for `[sidecar.connector]`.
//!
//! Representation only. Describes the default dispatch timeout applied to
//! unconfigured hosts and the per-host overrides. `firma-sidecar` validates
//! non-zero timeouts / rate limits and rejects duplicate hosts.

use serde::{Deserialize, Serialize};

/// Default dispatch timeout (30s) applied to the registry default connector.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Top-level connector configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Timeout in milliseconds applied to the registry default.
    #[serde(default = "default_timeout_ms")]
    pub default_timeout_ms: u64,
    /// Per-host overrides.
    #[serde(default)]
    pub hosts: Vec<HostConnectorConfig>,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: default_timeout_ms(),
            hosts: Vec::new(),
        }
    }
}

/// Per-host connector configuration.
///
/// All fields are required for explicit host entries — operators state their
/// per-host constraints explicitly rather than inherit global defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostConnectorConfig {
    /// Target host this entry applies to (exact match against the host portion
    /// of the envelope resource).
    pub host: String,
    /// Sustained refill rate for the token-bucket rate limiter, in requests
    /// per second.
    pub rps: u32,
    /// Token-bucket capacity. Bounds the instantaneous burst.
    pub burst: u32,
    /// Dispatch timeout in milliseconds applied to this host.
    pub timeout_ms: u64,
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}
