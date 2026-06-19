use std::time::Duration;

use crate::audit::{self, ExecutionEvent};
use crate::mock::HttpCaptures;
use crate::setup::ScenarioSetup;

// ── PhaseOutput ───────────────────────────────────────────────────────────────

/// Combined output from one scenario phase: agent result + mock HTTP captures.
pub struct PhaseOutput {
    pub agent: AgentOutput,
    pub http_requests: HttpCaptures,
}

// ── FirmaAudit ────────────────────────────────────────────────────────────────

/// Sidecar audit events from the enforcement phase.
pub struct FirmaAudit {
    pub(crate) events: Vec<ExecutionEvent>,
}

impl FirmaAudit {
    /// Audit events where the sidecar issued an ALLOW decision.
    #[must_use]
    pub fn allow_events(&self) -> Vec<&ExecutionEvent> {
        audit::allow_events(&self.events)
    }

    /// Audit events where the sidecar issued a DENY decision.
    #[must_use]
    pub fn deny_events(&self) -> Vec<&ExecutionEvent> {
        audit::deny_events(&self.events)
    }

    /// Audit events whose `action` contains `fragment`.
    #[must_use]
    pub fn events_for_action(&self, fragment: &str) -> Vec<&ExecutionEvent> {
        self.events
            .iter()
            .filter(|e| e.action.contains(fragment))
            .collect()
    }
}

// ── EnforcementScenario trait ─────────────────────────────────────────────────

#[allow(async_fn_in_trait)]
pub trait EnforcementScenario: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// Maximum wall-clock time allowed for the enforcement phase.
    fn timeout(&self) -> Duration {
        Duration::from_mins(5)
    }

    /// Return `true` if the scenario requires structural network confinement
    /// (i.e. bwrap `--unshare-net`) to produce a meaningful enforcement result.
    fn requires_structural_network(&self) -> bool {
        false
    }

    /// Configure the scenario: register HTTP mock routes, add mapping rules,
    /// append Cedar policy rules, configure sandbox mounts, etc.
    fn setup(&self, _ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Called before each phase (baseline and enforcement).
    fn before_assert(&self, _ctx: &ScenarioSetup) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Natural-language prompt sent to the agent.
    fn prompt(&self, ctx: &ScenarioSetup) -> String;

    fn assert_baseline(&self, output: &PhaseOutput) -> Result<(), anyhow::Error>;

    fn assert_enforcement(
        &self,
        output: &PhaseOutput,
        audit: &FirmaAudit,
    ) -> Result<(), anyhow::Error>;
}

// ── Output / result types ─────────────────────────────────────────────────────

pub struct AgentOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

pub struct ScenarioResult {
    pub scenario_name: String,
    pub baseline_passed: bool,
    pub baseline_output: PhaseOutput,
    pub enforcement_passed: bool,
    pub enforcement_error: Option<String>,
    pub enforcement_output: PhaseOutput,
    pub firma_audit: FirmaAudit,
}
