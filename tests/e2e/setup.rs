use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::agent::{Agent, AgentKind};
use crate::mock::{HttpMock, MockSpec};
use crate::policy::PolicyBuilder;
use crate::{config, firma_bin};

// ── ScenarioSetup ─────────────────────────────────────────────────────────────

pub struct ScenarioSetup {
    pub workspace_dir: PathBuf,
    pub protected_dir: PathBuf,
    pub capability_seed: Option<PathBuf>,
    pub capability_session_id: Option<String>,

    pub(crate) mock_host: String,
    pub(crate) mock_port: u16,
    pub(crate) mock_specs: Vec<MockSpec>,
    pub(crate) config_dir: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) agent: Agent,
}

impl ScenarioSetup {
    #[must_use]
    pub fn mock_addr(&self) -> String {
        format!("{}:{}", self.mock_host, self.mock_port)
    }

    #[must_use]
    pub fn mock_url_for(&self, path: &str) -> String {
        format!("http://{}:{}{}", self.mock_host, self.mock_port, path)
    }

    pub fn http_mock(&mut self) -> HttpMock<'_> {
        HttpMock {
            host: &self.mock_host,
            port: self.mock_port,
            mock_specs: &mut self.mock_specs,
        }
    }

    pub fn add_mapping_rule(
        &self,
        host_port: &str,
        method: &str,
        path: &str,
        action_class: &str,
    ) -> Result<(), anyhow::Error> {
        config::add_mapping_rule(&self.config_dir, host_port, method, path, action_class)?;
        config::add_mapping_rule(&self.config_dir, host_port, "CONNECT", "", action_class)?;
        Ok(())
    }

    #[must_use]
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn policy(&self) -> PolicyBuilder<'_> {
        PolicyBuilder::new(self)
    }

    pub fn issue_capability(
        &mut self,
        agent_id: &str,
        session_id: &str,
        action: &str,
        scope: &str,
        ttl_secs: u64,
    ) -> Result<(), anyhow::Error> {
        let bin = crate::firma_bin();
        let seed_path = config::issue_capability(
            &bin,
            &self.state_dir,
            &self.config_dir,
            agent_id,
            session_id,
            action,
            scope,
            ttl_secs,
        )?;
        self.capability_seed = Some(seed_path);
        self.capability_session_id = Some(session_id.to_string());
        Ok(())
    }

    /// Initialize a git repository in `workspace_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if `git init` fails.
    pub fn git_init_workspace(&self) -> Result<(), anyhow::Error> {
        let out = std::process::Command::new("git")
            .args(["init"])
            .current_dir(&self.workspace_dir)
            .output()
            .with_context(|| "spawn git init")?;
        anyhow::ensure!(
            out.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }

    /// Run `firma doctor` against this scenario's config and fail if it exits non-zero.
    pub fn doctor(&self) -> Result<(), anyhow::Error> {
        let out = std::process::Command::new(firma_bin())
            .arg("doctor")
            .args(["--config"])
            .arg(self.config_dir.join("firma.toml"))
            .output()
            .with_context(|| "spawn firma doctor")?;
        anyhow::ensure!(
            out.status.success(),
            "firma doctor failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }

    /// Start building a `firma config init` invocation.
    #[must_use]
    pub fn firma_config(&self) -> FirmaConfigBuilder<'_> {
        FirmaConfigBuilder::new(self)
    }
}

// ── FirmaConfigBuilder ────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct FirmaConfigBuilder<'a> {
    ctx: &'a ScenarioSetup,
    mode: &'static str,
    posture: &'static str,
    mappings: Vec<&'static str>,
    workspace: Option<&'a Path>,
    authority_listen: &'static str,
}

impl<'a> FirmaConfigBuilder<'a> {
    pub(crate) fn new(ctx: &'a ScenarioSetup) -> Self {
        let mappings = if matches!(ctx.agent.kind, AgentKind::Codex) {
            vec!["openai", "github"]
        } else {
            vec!["anthropic"]
        };
        Self {
            ctx,
            mode: "agent-local",
            posture: "dev",
            mappings,
            workspace: Some(&ctx.workspace_dir),
            authority_listen: "127.0.0.1:0",
        }
    }

    /// Override the Cedar posture (default: `"dev"`).
    #[must_use]
    pub fn posture(mut self, posture: &'static str) -> Self {
        self.posture = posture;
        self
    }

    /// Override the workspace mount path (default: `ctx.workspace_dir`).
    #[must_use]
    pub fn workspace(mut self, path: &'a Path) -> Self {
        self.workspace = Some(path);
        self
    }

    /// Clear the workspace mount.
    #[must_use]
    pub fn no_workspace(mut self) -> Self {
        self.workspace = None;
        self
    }

    /// Replace the mapping selection.
    #[must_use]
    pub fn mappings(mut self, mappings: Vec<&'static str>) -> Self {
        self.mappings = mappings;
        self
    }

    /// Clear the mapping selection.
    #[must_use]
    pub fn no_mappings(mut self) -> Self {
        self.mappings.clear();
        self
    }

    /// Set the authority listen address (default: `"127.0.0.1:0"`).
    #[must_use]
    pub fn authority_listen(mut self, addr: &'static str) -> Self {
        self.authority_listen = addr;
        self
    }

    /// Execute `firma config init` with the configured options.
    ///
    /// # Errors
    ///
    /// Returns an error if the `firma config init` process fails or
    /// the audit path cannot be configured.
    pub fn run(self) -> Result<(), anyhow::Error> {
        let firma = firma_bin();
        let mut cmd = std::process::Command::new(&firma);
        cmd.args([
            "config",
            "--yes",
            "--mode",
            self.mode,
            "--profile",
            self.ctx.agent.profile(),
            "--posture",
            self.posture,
            "-o",
        ])
        .arg(&self.ctx.config_dir)
        .args(["--state-dir"])
        .arg(&self.ctx.state_dir);

        cmd.args(["--authority-listen", self.authority_listen]);

        for mapping in &self.mappings {
            cmd.args(["--mapping", mapping]);
        }
        if let Some(ws) = self.workspace {
            cmd.args(["--workspace"]).arg(ws);
        }

        let output = cmd.output().with_context(|| "spawn firma config")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("firma config failed: {stderr}");
        }

        config::configure_audit_path(
            &self.ctx.config_dir,
            &self.ctx.state_dir.join("audit.jsonl"),
        )?;
        Ok(())
    }
}
