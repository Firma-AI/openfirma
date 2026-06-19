use crate::scenario::{EnforcementScenario, FirmaAudit, PhaseOutput};
use crate::setup::ScenarioSetup;

pub struct SimplePrompt;

impl EnforcementScenario for SimplePrompt {
    fn name(&self) -> &'static str {
        "simple_prompt"
    }

    fn description(&self) -> &'static str {
        "Agent sends greeting to LLM provider → firma ALLOWs the call"
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
        audit: &FirmaAudit,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("enforcement agent failed: {}", output.agent.stderr);
        }
        let snapshot_name = format!("{}_{}", ctx.agent.profile(), self.name());
        insta::assert_json_snapshot!(snapshot_name, &audit.events, {
            "[].event_id"               => "[event_id]",
            "[].session_id"             => "[session_id]",
            "[].token_id"               => "[token_id]",
            "[].agent_id"               => "[agent_id]",
            "[].resource"               => "[resource]",
            "[].enforcement_latency_us" => "[latency_us]",
            "[].context_hash"           => "[context_hash]",
            "[].bundle_version"         => "[bundle_version]",
            "[].timestamp"              => "[timestamp]",
            "[].dispatch_latency_us"    => "[dispatch_latency_us]",
            "[].response_size"          => "[response_size]",
            "[].sandbox_id"             => "[sandbox_id]",
            "[].signature"              => "[signature]",
        });
        Ok(())
    }
}
