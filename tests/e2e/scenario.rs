use std::time::Duration;

use crate::audit::FirmaAuditTrail;
use crate::runner::RunOutput;
use crate::setup::ScenarioSetup;

/// Combined output from one scenario phase: agent result + mock HTTP captures.
pub struct PhaseOutput {
    pub agent: RunOutput,
    pub http_requests: Vec<wiremock::Request>,
}

#[allow(async_fn_in_trait)]
pub trait EnforcementScenario: Send + Sync {
    fn name(&self) -> &'static str;

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
