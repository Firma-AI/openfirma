use std::time::Duration;

use crate::audit::FirmaAuditTrail;
use crate::runner::RunOutput;
use crate::setup::ScenarioSetup;

/// Combined output from one scenario phase: agent result + mock HTTP captures.
pub struct PhaseOutput {
    pub agent: RunOutput,
    pub http_requests: Vec<wiremock::Request>,
    /// TCP connections the raw-TCP proxy accepted during this phase. A raw
    /// `connect()` that reaches the socket increments this even when no HTTP
    /// request is parsed.
    pub tcp_connections: usize,
}

pub trait EnforcementScenario: Send + Sync {
    fn name(&self) -> &'static str;

    /// Maximum wall-clock time allowed for the enforcement phase.
    fn timeout(&self) -> Duration {
        Duration::from_mins(5)
    }

    /// Configure the scenario: register HTTP mock routes, add mapping rules,
    /// append Cedar policy rules, configure sandbox mounts, etc.
    fn setup(&mut self, _ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Called before each phase (baseline and enforcement).
    fn before_assert(&self, _ctx: &ScenarioSetup) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Natural-language prompt sent to the agent.
    fn prompt(&self, ctx: &ScenarioSetup) -> String;

    fn assert_baseline(
        &self,
        ctx: &ScenarioSetup,
        output: &PhaseOutput,
    ) -> Result<(), anyhow::Error>;

    fn assert_enforcement(
        &self,
        ctx: &ScenarioSetup,
        output: &PhaseOutput,
        audit: &FirmaAuditTrail,
    ) -> Result<(), anyhow::Error>;
}

/// Which run of a scenario produced an output: the unenforced baseline or the
/// firma-enforced run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum Phase {
    Baseline,
    Enforcement,
}
