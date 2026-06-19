use crate::scenario::{EnforcementScenario, FirmaAudit, PhaseOutput};
use crate::setup::ScenarioSetup;

pub struct NormalLlmCall;

impl EnforcementScenario for NormalLlmCall {
    fn name(&self) -> &'static str {
        "normal_llm_call"
    }

    fn description(&self) -> &'static str {
        "Agent makes a normal GET request to an allowed host → ALLOW"
    }

    fn setup(&self, ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        ctx.git_init_workspace()?;
        ctx.firma_config().run()?;
        let addr = ctx.http_mock().addr();
        ctx.add_mapping_rule(&addr, "GET", "*", "communication.external.send")?;
        ctx.http_mock().serve("GET", "/llm", |m| {
            m.with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"ok":true}"#)
        });
        Ok(())
    }

    fn prompt(&self, ctx: &ScenarioSetup) -> String {
        format!(
            "Use curl to GET {} and print the full response body.",
            ctx.mock_url_for("/llm")
        )
    }

    fn assert_baseline(&self, output: &PhaseOutput) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("baseline agent failed: {}", output.agent.stderr);
        }
        if !output.http_requests.any() {
            anyhow::bail!("baseline: no HTTP request reached mock server");
        }
        Ok(())
    }

    fn assert_enforcement(
        &self,
        output: &PhaseOutput,
        audit: &FirmaAudit,
    ) -> Result<(), anyhow::Error> {
        if !output.http_requests.any() {
            anyhow::bail!(
                "HTTP request did not reach mock server — expected ALLOW to let it through"
            );
        }
        let allows = audit.allow_events();
        if allows.is_empty() {
            anyhow::bail!("expected at least one ALLOW event, got none");
        }
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/e2e/scenarios/snapshots"),
        );
        for field in &[
            ".event_id",
            ".session_id",
            ".token_id",
            ".agent_id",
            ".resource",
            ".enforcement_latency_us",
            ".context_hash",
            ".bundle_version",
            ".timestamp",
            ".dispatch_status",
        ] {
            settings.add_redaction(field, format!("[{}]", field.trim_start_matches('.')));
        }
        settings.bind(|| {
            insta::assert_json_snapshot!("normal_llm_call_allow", allows[0]);
        });
        Ok(())
    }
}
