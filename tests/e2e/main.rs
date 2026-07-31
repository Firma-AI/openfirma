#![allow(dead_code)]

mod agent;
mod audit;
mod config;
mod policy;
mod runner;
mod scenario;
mod scenarios;
mod setup;
mod tcp_proxy;

use std::path::PathBuf;

use agent::AgentKind;
use anyhow::Context;
use runner::run_scenario;
use scenarios::EnforcementScenario;

// ── Utilities ────────────────────────────────────────────────────────────────

/// Path to the `firma` binary under test.
///
/// Cargo builds the package's `[[bin]]` when compiling this integration test and
/// exposes its path via `CARGO_BIN_EXE_firma`, so nextest always runs the
/// just-built debug binary.
#[must_use]
pub fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

// ── Test driver ──────────────────────────────────────────────────────────────

fn default_agent(kind: AgentKind) -> agent::Agent {
    match kind {
        AgentKind::Claude => agent::Agent::claude().args([
            "--permission-mode",
            "bypassPermissions",
            // Suppresses analytics only — normal agent behavior is unaffected.
            "--settings",
            r#"{"env":{"DISABLE_TELEMETRY":"1"}}"#,
        ]),
        AgentKind::Codex => agent::Agent::codex().args(["--sandbox", "danger-full-access"]),
    }
}

async fn drive_scenario_for_agent(
    scenario: &mut dyn EnforcementScenario,
    kind: AgentKind,
) -> Result<(), anyhow::Error> {
    let agent = default_agent(kind);

    run_scenario(scenario, &agent)
        .await
        .with_context(|| format!("[{}] scenario {}", agent.kind.as_ref(), scenario.name()))
}

// ── Scenario registration ────────────────────────────────────────────────────
//
// Pass the agent list as the first argument. Each ident becomes the sub-module
// name and maps to an `AgentKind` variant via `agent_kind!`.
//
//   scenario_tests! [claude, codex] { ... }   // all agents
//   scenario_tests! [claude]        { ... }   // claude only
macro_rules! agent_kind {
    (claude) => {
        agent::AgentKind::Claude
    };
    (codex) => {
        agent::AgentKind::Codex
    };
}

macro_rules! scenario_tests {
    // $scenarios is a single tt (the parenthesised block), not a repetition,
    // so it can be passed inside the $agent repetition without a depth conflict.
    ([$($agent:ident),+]; $scenarios:tt) => {
        $( scenario_tests!(@agent $agent $scenarios); )+
    };
    (@agent $agent:ident ($($name:ident => $scenario:expr),* $(,)?)) => {
        mod $agent {
            use super::*;
            $(
                #[tokio::test]
                #[ignore = "integration test — run with --include-ignored"]
                async fn $name() -> Result<(), anyhow::Error> {
                    super::drive_scenario_for_agent(&mut $scenario, agent_kind!($agent)).await
                }
            )*
        }
    };
}

scenario_tests! {
    [claude, codex];
    (
        simple_prompt                => scenarios::SimplePrompt,
        allow_http_call              => scenarios::AllowHttpCall,
        deny_forbidden_http_resource => scenarios::DenyForbiddenHttpResource,
        deny_unclassified_intent     => scenarios::DenyUnclassifiedIntent,
        deny_http_call               => scenarios::DenyHttpCall,
        block_raw_tcp_egress         => scenarios::BlockRawTcpEgress,
        block_loopback_egress        => scenarios::BlockLoopbackEgress,
        fs_read_deny                 => scenarios::FsReadDeny::default(),
        fs_delete_deny               => scenarios::FsDeleteDeny::default(),
        cargo_build                  => scenarios::CargoBuild,
    )
}
