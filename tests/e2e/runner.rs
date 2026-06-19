use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use tokio::sync::oneshot;

use crate::agent::Agent;
use crate::audit;
use crate::firma_bin;
use crate::mock::{CaptureState, HttpCaptures, run_capture_server};
use crate::scenario::{AgentOutput, EnforcementScenario, FirmaAudit, PhaseOutput, ScenarioResult};
use crate::setup::ScenarioSetup;

/// Run a full two-phase scenario for `agent`.
///
/// Phase 1 (baseline): agent runs directly — no firma proxy.
/// Phase 2 (enforcement): agent runs through `firma run`.
#[allow(clippy::too_many_lines)]
pub async fn run_scenario(
    scenario: &dyn EnforcementScenario,
    agent: &Agent,
) -> Result<ScenarioResult, anyhow::Error> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .with_context(|| "bind capture server")?;
    let port = listener
        .local_addr()
        .with_context(|| "get capture server port")?
        .port();

    let capture_state = Arc::new(Mutex::new(CaptureState::default()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(run_capture_server(
        listener,
        Arc::clone(&capture_state),
        shutdown_rx,
    ));

    let cfg_tmp = tempfile::tempdir()?;
    let state_tmp = tempfile::tempdir()?;
    let workspace_tmp = tempfile::tempdir()?;
    let protected_tmp = tempfile::tempdir()?;

    let cfg_dir = cfg_tmp.path().to_path_buf();
    let state_dir = state_tmp.path().to_path_buf();
    let workspace = workspace_tmp.path().to_path_buf();
    let protected_dir = protected_tmp.path().to_path_buf();

    let mut ctx = ScenarioSetup {
        workspace_dir: workspace,
        protected_dir,
        capability_seed: None,
        capability_session_id: None,
        mock_host: "127.0.0.1".to_string(),
        mock_port: port,
        mock_specs: Vec::new(),
        config_dir: cfg_dir.clone(),
        state_dir: state_dir.clone(),
        agent: agent.clone(),
    };

    scenario.setup(&mut ctx)?;
    let agent_args = agent.prompt_args(&scenario.prompt(&ctx));

    scenario.before_assert(&ctx)?;

    // Phase 1: baseline — run agent directly, no firma proxy.
    let baseline_agent_output = tokio::time::timeout(
        scenario.timeout(),
        run_agent_direct(agent.command(), &agent_args, &ctx.workspace_dir),
    )
    .await
    .unwrap_or_else(|_| {
        eprintln!("[baseline] timed out after {:?}", scenario.timeout());
        AgentOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "timed out".to_string(),
            elapsed: scenario.timeout(),
        }
    });

    let baseline_http = capture_state
        .lock()
        .map_err(|e| anyhow::anyhow!("capture lock: {e}"))?
        .received
        .clone();

    let baseline_phase = PhaseOutput {
        agent: baseline_agent_output,
        http_requests: HttpCaptures {
            requests: baseline_http,
        },
    };

    let baseline_passed = match scenario.assert_baseline(&baseline_phase) {
        Ok(()) => true,
        Err(err) => {
            eprintln!(
                "[baseline] {} FAIL: {err}\nstdout: {}\nstderr: {}",
                agent.command(),
                baseline_phase.agent.stdout.trim(),
                baseline_phase.agent.stderr.trim()
            );
            false
        }
    };

    // Transfer mock specs into capture server; clear baseline captures.
    {
        let mut state = capture_state
            .lock()
            .map_err(|e| anyhow::anyhow!("capture lock: {e}"))?;
        state.mocks = std::mem::take(&mut ctx.mock_specs);
        state.received.clear();
    }

    scenario.before_assert(&ctx)?;

    // Phase 2: enforcement with timeout.
    let enforcement_agent_output = tokio::time::timeout(
        scenario.timeout(),
        run_enforcement(&firma_bin(), &ctx, &agent_args),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "enforcement timed out after {:?} (scenario: {})",
            scenario.timeout(),
            scenario.name()
        )
    })??;

    let enforcement_http = capture_state
        .lock()
        .map_err(|e| anyhow::anyhow!("capture lock: {e}"))?
        .received
        .clone();

    let enforcement_phase = PhaseOutput {
        agent: enforcement_agent_output,
        http_requests: HttpCaptures {
            requests: enforcement_http,
        },
    };

    let audit_path = state_dir.join("audit.jsonl");
    let firma_audit = FirmaAudit {
        events: audit::parse_audit_log(&audit_path).unwrap_or_default(),
    };

    let (enforcement_passed, enforcement_error) =
        match scenario.assert_enforcement(&enforcement_phase, &firma_audit) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(format!("{e:#}"))),
        };

    let _ = shutdown_tx.send(());

    Ok(ScenarioResult {
        scenario_name: scenario.name().to_string(),
        baseline_passed,
        enforcement_passed,
        enforcement_error,
        enforcement_output: enforcement_phase,
        firma_audit,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn agent_available(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}

async fn run_agent_direct(agent_cmd: &str, agent_args: &[String], workspace: &Path) -> AgentOutput {
    if !agent_available(agent_cmd) {
        eprintln!("[baseline] agent '{agent_cmd}' not found on PATH — skip");
        return AgentOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("agent '{agent_cmd}' not found on PATH"),
            elapsed: std::time::Duration::from_secs(0),
        };
    }

    let start = std::time::Instant::now();
    let output = tokio::process::Command::new(agent_cmd)
        .args(agent_args)
        .current_dir(workspace)
        .output()
        .await;
    let elapsed = start.elapsed();

    match output {
        Ok(out) => AgentOutput {
            success: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            elapsed,
        },
        Err(err) => AgentOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("spawn failed: {err}"),
            elapsed,
        },
    }
}

async fn run_enforcement(
    firma_bin: &Path,
    ctx: &ScenarioSetup,
    agent_args: &[String],
) -> Result<AgentOutput, anyhow::Error> {
    let config_path = ctx.config_dir().join("firma.toml");
    let start = std::time::Instant::now();
    let mut cmd = tokio::process::Command::new(firma_bin);
    cmd.args(["run", "--profile", ctx.agent.profile(), "--config"])
        .arg(&config_path);
    if !crate::bwrap_available() {
        cmd.arg("--allow-non-structural");
    }
    if let Some(cap) = &ctx.capability_seed {
        cmd.args(["--capability-file"]).arg(cap);
    }
    if let Some(session_id) = &ctx.capability_session_id {
        cmd.env("FIRMA_RUN_SESSION_ID", session_id);
    }
    cmd.arg("--")
        .arg(ctx.agent.command())
        .args(agent_args)
        .current_dir(&ctx.workspace_dir);
    let output = cmd
        .output()
        .await
        .with_context(|| format!("spawn firma run --profile {}", ctx.agent.profile()))?;
    let elapsed = start.elapsed();
    Ok(AgentOutput {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        elapsed,
    })
}
