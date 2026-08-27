//! Schema for `[sidecar.connector]`.
//!
//! Describes the default dispatch timeout applied to unconfigured hosts and the
//! per-host overrides. Schema value types own intrinsic invariants;
//! `firma-sidecar` validates rate limits, host names, and duplicate hosts.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::utils::NonZeroDuration;

/// Default dispatch timeout (30s) applied to the registry default connector.
const DEFAULT_TIMEOUT: NonZeroDuration = NonZeroDuration::from_static(Duration::from_secs(30));

/// Top-level connector configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Timeout applied to the registry default.
    #[serde(default = "default_timeout")]
    pub default_timeout: NonZeroDuration,
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
    /// Dispatch timeout applied to this host.
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub timeout: Duration,
}

const fn default_timeout() -> NonZeroDuration {
    DEFAULT_TIMEOUT
}
