#![allow(dead_code)]

mod audit;
mod config;
mod harness;
mod scenarios;

use std::path::PathBuf;
use std::process::Command;

use harness::run_scenario;
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

/// Default agent configuration by command name.
#[allow(clippy::panic)]
fn default_agent(agent_cmd: &str) -> harness::Agent {
    match agent_cmd {
        "claude" => harness::Agent::claude().args(["--permission-mode", "bypassPermissions"]),
        "codex" => harness::Agent::codex().args(["--sandbox", "danger-full-access"]),
        other => panic!("unknown agent: {other}"),
    }
}

#[allow(clippy::panic)]
async fn drive_scenario_for_agent(scenario: &dyn EnforcementScenario, agent_cmd: &str) {
    if scenario.requires_structural_network() && !bwrap_available() {
        eprintln!(
            "skip {} [{}]: requires structural network confinement (bwrap), \
             not available on this platform",
            scenario.name(),
            agent_cmd,
        );
        return;
    }

    let agent = default_agent(agent_cmd);
    let result = run_scenario(scenario, &agent).await;

    match result {
        Ok(r) => {
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
                r.enforcement_output.http_requests.all().len(),
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
// Pass the agent list as the first argument. Each ident becomes both the module
// name and — via `stringify!` — the string passed to `drive_scenario_for_agent`.
//
//   scenario_tests! [claude, codex] { ... }   // all agents
//   scenario_tests! [claude]        { ... }   // claude only
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
                    super::drive_scenario_for_agent(&$scenario, stringify!($agent)).await;
                }
            )*
        }
    };
}

scenario_tests! {
    [claude, codex];
    (
        normal_llm_call     => scenarios::NormalLlmCall,
        block_paste_service => scenarios::BlockPasteService,
        block_unlisted_host => scenarios::BlockUnlistedHost,
        tool_call_exfil     => scenarios::ToolCallExfil,
        direct_tcp_bypass   => scenarios::DirectTcpBypass,
        fs_read_deny        => scenarios::FsReadDeny::new(),
        fs_delete_deny      => scenarios::FsDeleteDeny::new(),
        code_fibonacci      => scenarios::CodeFibonacci::new(),
    )
}
