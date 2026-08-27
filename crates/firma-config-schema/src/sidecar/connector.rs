//! Schema for `[sidecar.connector]`.
//!
//! Representation only. Describes the default dispatch timeout applied to
//! unconfigured hosts and the per-host overrides. `firma-sidecar` validates
//! non-zero timeouts / rate limits and rejects duplicate hosts.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default dispatch timeout (30s) applied to the registry default connector.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Top-level connector configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Timeout applied to the registry default.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_timeout"
    )]
    pub default_timeout: Duration,
    /// Per-host overrides.
    #[serde(default)]
    pub hosts: Vec<HostConnectorConfig>,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            default_timeout: default_timeout(),
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

const fn default_timeout() -> Duration {
    DEFAULT_TIMEOUT
}
