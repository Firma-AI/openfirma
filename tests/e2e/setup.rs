use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use firma_sidecar::config::MappingRuleConfig;
use wiremock::{Mock, MockServer};

use crate::agent::{Agent, AgentKind};
use crate::policy::PolicyBuilder;
use crate::tcp_proxy::RawTcpProxy;
use crate::{config, firma_bin};

// ── ScenarioSetup ─────────────────────────────────────────────────────────────

pub struct ScenarioSetup {
    pub workspace_dir: PathBuf,
    pub protected_dir: PathBuf,
    pub capability_seed: Option<PathBuf>,
    pub capability_session_id: Option<String>,

    /// Shared mock server. Scenarios push built `Mock` objects into `mocks`;
    /// the runner mounts them between the baseline and enforcement phases.
    pub mock_server: Arc<MockServer>,
    pub mocks: Vec<Mock>,

    /// Counting TCP proxy fronting `mock_server`. Egress scenarios point the
    /// agent at `raw_tcp.address()` and assert on the accepted-connection count —
    /// a real "socket reached us" signal that raw (non-HTTP) sockets produce and
    /// wiremock alone cannot record.
    pub raw_tcp: Arc<crate::tcp_proxy::RawTcpProxy>,

    pub(crate) config_dir: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) agent: Agent,
}

impl ScenarioSetup {
    pub fn add_mapping_rule(
        &self,
        host_port: &str,
        method: &str,
        path: &str,
        action_class: &str,
    ) -> Result<(), anyhow::Error> {
        config::add_mapping_rules(
            &self.config_dir,
            vec![
                MappingRuleConfig {
                    method: Some(method.to_string()),
                    host: host_port.to_string(),
                    path: Some(path.to_string()),
                    action_class: action_class.to_string(),
                },
                // Companion CONNECT rule so the TLS tunnel itself is classified.
                MappingRuleConfig {
                    method: Some("CONNECT".to_string()),
                    host: host_port.to_string(),
                    path: Some(String::new()),
                    action_class: action_class.to_string(),
                },
            ],
        )
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
        actions: &[&str],
        scope: &str,
        ttl_secs: u64,
    ) -> Result<(), anyhow::Error> {
        let seed_path = config::issue_capability(
            &self.config_dir,
            agent_id,
            session_id,
            actions,
            scope,
            ttl_secs,
        )?;
        self.capability_seed = Some(seed_path);
        self.capability_session_id = Some(session_id.to_string());
        Ok(())
    }

    /// Reset `workspace_dir` to an empty directory.
    ///
    /// Use from `before_assert` for scenarios whose baseline run mutates the
    /// workspace (e.g. `cargo init`), so the enforcement phase starts clean.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be recreated.
    pub fn reset_workspace(&self) -> Result<(), anyhow::Error> {
        fs_err::remove_dir_all(&self.workspace_dir)?;
        fs_err::create_dir_all(&self.workspace_dir)?;
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

    /// Rebind the raw-TCP proxy on `ip` (still forwarding to `mock_server`).
    ///
    /// Loopback (the default) exercises the seccomp loopback guard; a routable
    /// host IP exercises the network-namespace egress boundary. Call from
    /// `setup` before the phases run.
    ///
    /// # Errors
    ///
    /// Returns an error if a listener cannot bind on `ip`.
    pub fn set_raw_tcp_bind_ip(&mut self, ip: IpAddr) -> Result<(), anyhow::Error> {
        self.raw_tcp = Arc::new(RawTcpProxy::start_on(ip, *self.mock_server.address())?);
        Ok(())
    }

    /// Start building a `firma config init` invocation.
    #[must_use]
    pub fn firma_config(&self) -> FirmaConfigBuilder<'_> {
        FirmaConfigBuilder::new(self)
    }
}

// ── FirmaConfigBuilder ────────────────────────────────────────────────────────

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
        let mut cmd = std::process::Command::new(firma_bin());
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

        Ok(())
    }
}
