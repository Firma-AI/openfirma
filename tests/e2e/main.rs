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
use runner::run_scenario;
use scenarios::EnforcementScenario;

// ── Utilities ────────────────────────────────────────────────────────────────

#[must_use]
pub fn firma_bin() -> PathBuf {
    if let Ok(path) = std::env::var("FIRMA_BIN")
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map_or_else(|| manifest_dir.clone(), PathBuf::from);

    let release_bin = repo_root.join("target/release/firma");
    if release_bin.exists() {
        return release_bin;
    }

    let debug_bin = repo_root.join("target/debug/firma");
    if debug_bin.exists() {
        return debug_bin;
    }

    PathBuf::from("firma")
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
        AgentKind::ClaudeCode => {
            agent::Agent::claude().args(["--permission-mode", "bypassPermissions"])
        }
        AgentKind::Codex => agent::Agent::codex().args(["--sandbox", "danger-full-access"]),
    }
}

#[allow(clippy::panic)]
async fn drive_scenario_for_agent(scenario: &dyn EnforcementScenario, kind: AgentKind) {
    let agent = default_agent(kind);

    if scenario.requires_structural_network() && !bwrap_available() {
        eprintln!(
            "skip {} [{}]: requires structural network confinement (bwrap), \
             not available on this platform",
            scenario.name(),
            agent.command(),
        );
        return;
    }
    let result = run_scenario(scenario, &agent).await;

    match result {
        Ok(r) => {
            assert!(
                r.baseline_passed,
                "{} [{}] baseline FAILED — agent cannot complete task unconfined\n\
                 stdout: {}\nstderr: {}",
                scenario.name(),
                agent.command(),
                r.baseline_output.agent.stdout.trim(),
                r.baseline_output.agent.stderr.trim(),
            );
            assert!(
                r.enforcement_passed,
                "{} [{}] enforcement FAILED: {}\n\
                 audit: {} allow, {} deny | mock requests: {}\n\
                 --- firma run stderr ---\n\
                 {}",
                scenario.name(),
                agent.command(),
                r.enforcement_error.as_deref().unwrap_or("(no detail)"),
                r.firma_audit.allow_events().len(),
                r.firma_audit.deny_events().len(),
                r.enforcement_output.http_requests.len(),
                r.enforcement_output.agent.stderr.trim(),
            );
        }
        Err(err) => {
            panic!("{} [{}] ERROR: {err}", scenario.name(), agent.command());
        }
    }
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
        agent::AgentKind::ClaudeCode
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
                async fn $name() {
                    super::drive_scenario_for_agent(&$scenario, agent_kind!($agent)).await;
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
