//! Tenancy configuration for the sidecar.

use serde::Deserialize;

/// Tenancy mode for the sidecar.
///
/// `single_agent` (default): the sidecar serves exactly one `agent_id` for its
/// entire lifetime. Any request bearing a different `agent_id` is denied. This
/// enforces the architectural invariant (V1 ADR §2) that one Sidecar process
/// serves one agent, preventing session-state cross-contamination in the LRU.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenancyMode {
    /// Single agent per sidecar process (default).
    #[default]
    SingleAgent,
}

/// Tenancy configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenancyConfig {
    /// Tenancy mode. Default: `single_agent`.
    #[serde(default)]
    pub mode: TenancyMode,
}

impl TenancyConfig {
    /// Validate the tenancy configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<(), String> {
        // Currently no validation needed for tenancy mode.
        // Future modes may require additional validation.
        Ok(())
    }
}
