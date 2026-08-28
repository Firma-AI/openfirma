//! Schema for `[sidecar.tenancy]`.
//!
//! Representation only. The sidecar partitions state across agents; V1 enforces
//! a one-sidecar-one-agent invariant.

use serde::{Deserialize, Serialize};

/// Tenancy mode for the sidecar.
///
/// `SingleAgent` (default): the sidecar serves exactly one `agent_id` for its
/// entire lifetime. The first request to arrive establishes the bound
/// `agent_id`; every subsequent request whose verified token claims a
/// different `agent_id` is denied.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenancyMode {
    /// Single agent per sidecar process. The sidecar binds to the first
    /// `agent_id` it observes and denies any subsequent request that presents a
    /// different one. Default.
    #[default]
    SingleAgent,
}

/// Tenancy configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenancyConfig {
    /// Tenancy mode. Default: [`TenancyMode::SingleAgent`].
    #[serde(default)]
    pub mode: TenancyMode,
}
