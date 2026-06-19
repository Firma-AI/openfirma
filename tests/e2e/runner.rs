use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::io::AsyncReadExt;
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
    let baseline_agent_output = run_agent_direct(
        agent.command(),
        &agent_args,
        &ctx.workspace_dir,
        scenario.timeout(),
    )
    .await;

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

    // Phase 2: enforcement.
    let enforcement_agent_output =
        run_enforcement(&firma_bin(), &ctx, &agent_args, scenario.timeout()).await?;

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
        match scenario.assert_enforcement(&ctx, &enforcement_phase, &firma_audit) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(format!("{e:#}"))),
        };

    let _ = shutdown_tx.send(());

    Ok(ScenarioResult {
        scenario_name: scenario.name().to_string(),
        baseline_passed,
        baseline_output: baseline_phase,
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

/// Spawn `cmd` and wait up to `timeout`. On timeout: kill the process and
/// collect whatever partial stdout/stderr was written.
async fn run_with_timeout(
    mut cmd: tokio::process::Command,
    timeout: Duration,
    label: &str,
) -> Result<AgentOutput, anyhow::Error> {
    let start = Instant::now();
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {label}"))?;

    let mut stdout_handle = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdout not piped"))?;
    let mut stderr_handle = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("stderr not piped"))?;

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_handle.read_to_end(&mut buf).await;
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_handle.read_to_end(&mut buf).await;
        buf
    });

    // Use child.wait() (borrows) so child remains owned if the sleep arm fires.
    let timed_out = tokio::select! {
        _ = child.wait() => false,
        () = tokio::time::sleep(timeout) => true,
    };

    if timed_out {
        eprintln!("[{label}] timed out after {timeout:?} — killing");
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    let stdout_bytes = stdout_task.await.unwrap_or_default();
    let stderr_bytes = stderr_task.await.unwrap_or_default();
    let elapsed = start.elapsed();

    // Re-query exit status (only valid when not timed out).
    let status = if timed_out {
        None
    } else {
        child.try_wait().ok().flatten()
    };

    Ok(status.map_or_else(
        || {
            if timed_out {
                AgentOutput {
                    success: false,
                    exit_code: None,
                    stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
                    stderr: format!(
                        "timed out after {timeout:?}\n--- partial stderr ---\n{}",
                        String::from_utf8_lossy(&stderr_bytes)
                    ),
                    elapsed: timeout,
                }
            } else {
                AgentOutput {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: "process wait failed".to_string(),
                    elapsed,
                }
            }
        },
        |s| AgentOutput {
            success: s.success(),
            exit_code: s.code(),
            stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
            stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
            elapsed,
        },
    ))
}

async fn run_agent_direct(
    agent_cmd: &str,
    agent_args: &[String],
    workspace: &Path,
    timeout: Duration,
) -> AgentOutput {
    if !agent_available(agent_cmd) {
        eprintln!("[baseline] agent '{agent_cmd}' not found on PATH — skip");
        return AgentOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("agent '{agent_cmd}' not found on PATH"),
            elapsed: Duration::from_secs(0),
        };
    }

    let mut cmd = tokio::process::Command::new(agent_cmd);
    cmd.args(agent_args).current_dir(workspace);
    run_with_timeout(cmd, timeout, "baseline")
        .await
        .unwrap_or_else(|e| AgentOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("spawn failed: {e}"),
            elapsed: Duration::from_secs(0),
        })
}

async fn run_enforcement(
    firma_bin: &Path,
    ctx: &ScenarioSetup,
    agent_args: &[String],
    timeout: Duration,
) -> Result<AgentOutput, anyhow::Error> {
    let config_path = ctx.config_dir().join("firma.toml");
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
    run_with_timeout(
        cmd,
        timeout,
        &format!("firma run --profile {}", ctx.agent.profile()),
    )
    .await
}
