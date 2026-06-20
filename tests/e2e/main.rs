#![allow(dead_code)]

mod agent;
mod audit;
mod config;
mod policy;
mod runner;
mod scenario;
mod scenarios;
mod setup;

use std::path::PathBuf;
use std::process::Command;

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

#[must_use]
pub fn firma() -> Command {
    Command::new(firma_bin())
}

#[must_use]
pub fn bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .is_ok()
}

// ── Test driver ──────────────────────────────────────────────────────────────

fn default_agent(kind: AgentKind) -> agent::Agent {
    match kind {
        AgentKind::Claude => {
            agent::Agent::claude().args(["--permission-mode", "bypassPermissions"])
        }
        AgentKind::Codex => agent::Agent::codex().args(["--sandbox", "danger-full-access"]),
    }
}

async fn drive_scenario_for_agent(
    scenario: &dyn EnforcementScenario,
    kind: AgentKind,
) -> Result<(), anyhow::Error> {
    let agent = default_agent(kind);

    if scenario.requires_structural_network() && !bwrap_available() {
        eprintln!(
            "skip {} [{}]: requires structural network confinement (bwrap), \
             not available on this platform",
            scenario.name(),
            agent.command(),
        );
        return Ok(());
    }

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
                    super::drive_scenario_for_agent(&$scenario, agent_kind!($agent)).await
                }
            )*
        }
    };
}

scenario_tests! {
    [claude, codex];
    (
        simple_prompt => scenarios::SimplePrompt,
    )
}
