use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use tokio::io::AsyncReadExt;
use wiremock::MockServer;

use crate::agent::Agent;
use crate::audit::FirmaAuditTrail;
use crate::firma_bin;
use crate::scenario::{EnforcementScenario, Phase, PhaseOutput, ScenarioResult};
use crate::setup::ScenarioSetup;

/// Captured result of running a phase process (bare agent or firma wrapper) to
/// completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

/// Returned when a phase process exceeds its allotted wall-clock time and is
/// killed before exiting. Carries whatever partial output was captured.
#[derive(Debug, Clone, thiserror::Error)]
#[error("[{phase}] run timed out after {elapsed:?}")]
pub struct RunTimeoutError {
    pub phase: Phase,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

/// Run a full two-phase scenario for `agent`.
///
/// Phase 1 (baseline): agent runs directly — no firma proxy.
/// Phase 2 (enforcement): agent runs through `firma run`.
#[allow(clippy::too_many_lines)]
pub async fn run_scenario(
    scenario: &dyn EnforcementScenario,
    agent: &Agent,
) -> Result<ScenarioResult, anyhow::Error> {
    let mock_server = Arc::new(MockServer::start().await);

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
        mock_server: Arc::clone(&mock_server),
        mocks: Vec::new(),
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
    .await?;

    let baseline_phase = PhaseOutput {
        agent: baseline_agent_output,
        http_requests: mock_server.received_requests().await.unwrap_or_default(),
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

    // Clear baseline captures; mount enforcement mocks built during setup.
    mock_server.reset().await;
    for m in ctx.mocks.drain(..) {
        m.mount(&mock_server).await;
    }

    scenario.before_assert(&ctx)?;

    // Phase 2: enforcement.
    let enforcement_agent_output =
        run_enforcement(&firma_bin(), &ctx, &agent_args, scenario.timeout()).await?;

    let enforcement_phase = PhaseOutput {
        agent: enforcement_agent_output,
        http_requests: mock_server.received_requests().await.unwrap_or_default(),
    };

    let audit_path = state_dir.join("audit.jsonl");
    let firma_audit = FirmaAuditTrail::try_new(&audit_path)?;

    let (enforcement_passed, enforcement_error) =
        match scenario.assert_enforcement(&ctx, &enforcement_phase, &firma_audit) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(format!("{e:#}"))),
        };

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

/// Spawn `cmd` and wait up to `timeout`. On timeout: kill the process and
/// collect whatever partial stdout/stderr was written.
async fn run_with_timeout(
    phase: Phase,
    mut cmd: tokio::process::Command,
    timeout: Duration,
) -> Result<RunOutput, anyhow::Error> {
    let start = Instant::now();
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {phase}"))?;

    let mut stdout_handle = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdout not piped"))?;
    let mut stderr_handle = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("stderr not piped"))?;

    let stdout = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_handle.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    });

    let stderr = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_handle.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    });

    let exit_status = tokio::select! {
        status = child.wait() => Some(status?),
        () = tokio::time::sleep(timeout) => {
            eprintln!("[{phase}] timed out after {timeout:?} - killing");
            let _ = child.kill().await;
            let _ = child.wait().await;
            None
        },
    };

    let elapsed = start.elapsed();
    let stdout = stdout.await?;
    let stderr = stderr.await?;

    let Some(exit_status) = exit_status else {
        return Err(RunTimeoutError {
            phase,
            stdout,
            stderr,
            elapsed,
        }
        .into());
    };

    Ok(RunOutput {
        success: exit_status.success(),
        exit_code: exit_status.code(),
        stdout,
        stderr,
        elapsed,
    })
}

async fn run_agent_direct(
    agent_cmd: &str,
    agent_args: &[String],
    workspace: &Path,
    timeout: Duration,
) -> Result<RunOutput, anyhow::Error> {
    if !agent_available(agent_cmd) {
        bail!("[baseline] agent '{agent_cmd}' not found on PATH");
    }

    let mut cmd = tokio::process::Command::new(agent_cmd);
    cmd.args(agent_args).current_dir(workspace);
    run_with_timeout(Phase::Baseline, cmd, timeout).await
}

async fn run_enforcement(
    firma_bin: &Path,
    ctx: &ScenarioSetup,
    agent_args: &[String],
    timeout: Duration,
) -> Result<RunOutput, anyhow::Error> {
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
    run_with_timeout(Phase::Enforcement, cmd, timeout).await
}

fn agent_available(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}
