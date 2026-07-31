//! Tenancy configuration for the sidecar.
//!
//! Defines how the sidecar partitions state across agents. V1 enforces a
//! one-sidecar-one-agent invariant: each sidecar process serves exactly one
//! `agent_id` for its entire lifetime. To serve multiple agents, run multiple
//! sidecar processes (one per agent) — do not multiplex them through a single
//! process.

use serde::Deserialize;

/// Tenancy mode for the sidecar.
///
/// `SingleAgent` (default): the sidecar serves exactly one `agent_id` for its
/// entire lifetime. The first request to arrive establishes the bound
/// `agent_id`; every subsequent request whose verified token claims a
/// different `agent_id` is denied with `DenyReason::TenantMismatch`.
///
/// # Why this exists
///
/// The sidecar holds per-session runtime state in an LRU
/// ([`SessionStateStore`](crate::enforcement::SessionStateStore)) that
/// Stage 2 (Cedar policy) reads to make decisions — for example, escalating
/// risk when an agent suddenly issues many calls in a short window. If two
/// agents shared one sidecar, agent A's call count would be visible to
/// agent B's policy evaluation, letting one agent influence another's
/// enforcement outcomes. `SingleAgent` makes that partition structural
/// instead of policy-driven, so it cannot be bypassed by a misconfigured
/// Cedar rule.
///
/// # Behavior
///
/// - First request to arrive: its verified `agent_id` is recorded as the
///   bound agent. The request proceeds normally.
/// - Subsequent request with the same `agent_id`: proceeds normally.
/// - Subsequent request with a different `agent_id`: denied with
///   `DenyReason::TenantMismatch` at the
///   [`TokenValidation`](crate::enforcement::decision::CapabilityValidationStage::TokenValidation)
///   stage. The deny carries the presenting agent's verified identity so the
///   audit record is attributable.
/// - The bound is process-lifetime: a sidecar restart resets it.
///
/// # Configuration
///
/// ```toml
/// [tenancy]
/// mode = "single_agent"  # default; currently the only supported mode
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenancyMode {
    /// Single agent per sidecar process. The sidecar binds to the first
    /// `agent_id` it observes and denies any subsequent request that
    /// presents a different one. Default.
    #[default]
    SingleAgent,
}

/// Tenancy configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenancyConfig {
    /// Tenancy mode. Default: [`TenancyMode::SingleAgent`].
    #[serde(default)]
    pub(crate) mode: TenancyMode,
}
