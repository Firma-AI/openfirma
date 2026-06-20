use crate::audit::FirmaAuditTrail;
use crate::scenario::{EnforcementScenario, PhaseOutput};
use crate::setup::ScenarioSetup;

pub struct SimplePrompt;

impl EnforcementScenario for SimplePrompt {
    fn name(&self) -> &'static str {
        "simple_prompt"
    }

    fn setup(&self, ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        ctx.git_init_workspace()?;
        ctx.firma_config().run()?;
        Ok(())
    }

    fn prompt(&self, _ctx: &ScenarioSetup) -> String {
        "Hi, what's up?".to_string()
    }

    fn assert_baseline(&self, output: &PhaseOutput) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("baseline agent failed: {}", output.agent.stderr);
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
            anyhow::bail!("enforcement agent failed: {}", output.agent.stderr);
        }
        insta::assert_debug_snapshot!(ctx.agent.kind.as_ref(), &audit);
        Ok(())
    }
}
