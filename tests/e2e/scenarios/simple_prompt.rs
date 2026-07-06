use crate::audit::FirmaAuditTrail;
use crate::scenario::{EnforcementScenario, PhaseOutput};
use crate::setup::ScenarioSetup;

pub struct SimplePrompt;

impl EnforcementScenario for SimplePrompt {
    fn name(&self) -> &'static str {
        "simple_prompt"
    }

    fn setup(&mut self, ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        ctx.git_init_workspace()?;
        ctx.firma_config().run()?;
        Ok(())
    }

    fn prompt(&self, _ctx: &ScenarioSetup) -> String {
        "Hi, what's up?".to_string()
    }

    fn assert_baseline(
        &self,
        _ctx: &ScenarioSetup,
        output: &PhaseOutput,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("agent failed");
        }
        Ok(())
    }

    fn assert_enforcement(
        &self,
        ctx: &ScenarioSetup,
        output: &PhaseOutput,
        audit: &FirmaAuditTrail,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("agent failed");
        }
        audit.assert_snapshot(self.name(), ctx);
        Ok(())
    }
}
