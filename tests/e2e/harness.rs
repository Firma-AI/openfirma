use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::sync::oneshot;

use crate::audit::{self, ExecutionEvent};
use crate::{config, firma_bin};

// ── Agent ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentKind {
    ClaudeCode,
    Codex,
}

/// An agent that the harness can run, optionally carrying extra CLI flags.
///
/// Flags passed via `.args()` are always inserted before the subcommand so
/// they are treated as global flags by the agent binary.
#[derive(Debug, Clone)]
pub struct Agent {
    kind: AgentKind,
    args: Vec<String>,
}

impl Agent {
    #[must_use]
    pub fn claude() -> Self {
        Self {
            kind: AgentKind::ClaudeCode,
            args: Vec::new(),
        }
    }

    #[must_use]
    pub fn codex() -> Self {
        Self {
            kind: AgentKind::Codex,
            args: Vec::new(),
        }
    }

    /// Attach CLI flags inserted before the subcommand / prompt flag.
    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn command(&self) -> &'static str {
        match self.kind {
            AgentKind::ClaudeCode => "claude",
            AgentKind::Codex => "codex",
        }
    }

    #[must_use]
    pub fn profile(&self) -> &'static str {
        match self.kind {
            AgentKind::ClaudeCode => "claude-code",
            AgentKind::Codex => "codex",
        }
    }

    pub fn prompt_args(&self, prompt: &str) -> Vec<String> {
        let mut result = self.args.clone();
        match self.kind {
            AgentKind::ClaudeCode => {
                result.push("-p".to_string());
                result.push(prompt.to_string());
            }
            AgentKind::Codex => {
                result.push("exec".to_string());
                result.push(prompt.to_string());
            }
        }
        result
    }
}

// ── Mock response builder ─────────────────────────────────────────────────────

/// Configures the HTTP response returned by the capture server for a mock route.
pub struct MockResponseBuilder {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponseBuilder {
    fn new() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }
}

// ── Mock spec ─────────────────────────────────────────────────────────────────

struct MockSpec {
    method: String,
    path: String,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

// ── HttpMock short-lived handle ───────────────────────────────────────────────

/// Short-lived handle returned by [`ScenarioSetup::http_mock`].
pub struct HttpMock<'a> {
    host: &'a str,
    port: u16,
    mock_specs: &'a mut Vec<MockSpec>,
}

impl HttpMock<'_> {
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    #[must_use]
    pub fn url_for(&self, path: &str) -> String {
        format!("{}{}", self.url(), path)
    }

    #[must_use]
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    #[must_use]
    pub fn host(&self) -> &str {
        self.host
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Register an HTTP mock route. The `configure` closure receives a
    /// [`MockResponseBuilder`] and should chain `.with_status()`, `.with_body()`,
    /// etc. Routes are activated in the capture server after the baseline phase.
    pub fn serve(
        &mut self,
        method: impl Into<String>,
        path: impl Into<String>,
        configure: impl FnOnce(MockResponseBuilder) -> MockResponseBuilder,
    ) {
        let response = configure(MockResponseBuilder::new());
        self.mock_specs.push(MockSpec {
            method: method.into(),
            path: path.into(),
            status: response.status,
            headers: response.headers,
            body: response.body,
        });
    }
}

// ── Capture server ────────────────────────────────────────────────────────────

#[derive(Default)]
struct CaptureState {
    mocks: Vec<MockSpec>,
    received: Vec<ReceivedRequest>,
}

/// An HTTP request captured by the mock server during the enforcement phase.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ReceivedRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

impl ReceivedRequest {
    #[must_use]
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or_default()
    }

    #[must_use]
    pub fn body_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

async fn run_capture_server(
    listener: tokio::net::TcpListener,
    state: Arc<Mutex<CaptureState>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accept = listener.accept() => {
                let Ok((stream, _)) = accept else { break; };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req: Request<Incoming>| {
                            let s = Arc::clone(&state);
                            handle_capture_request(req, s)
                        }))
                        .await;
                });
            }
        }
    }
}

async fn handle_capture_request(
    req: Request<Incoming>,
    state: Arc<Mutex<CaptureState>>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Collect the full request body before acquiring the lock.
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("body read: {e}"))?
        .to_bytes()
        .to_vec();

    // Lock briefly — no await while held.
    let (status, headers, body) = {
        let mut locked = state
            .lock()
            .map_err(|e| anyhow::anyhow!("capture lock poisoned: {e}"))?;
        locked.received.push(ReceivedRequest {
            method: method.clone(),
            path: path.clone(),
            body: body_bytes,
        });
        locked
            .mocks
            .iter()
            .find(|m| m.method.eq_ignore_ascii_case(&method) && m.path == path)
            .map_or_else(
                || (404_u16, Vec::new(), b"no mock registered".to_vec()),
                |m| (m.status, m.headers.clone(), m.body.clone()),
            )
    };

    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let response = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| anyhow::anyhow!("response build: {e}"))?;
    Ok(response)
}

// ── HttpCaptures ──────────────────────────────────────────────────────────────

/// HTTP requests captured by the mock server during a scenario phase.
pub struct HttpCaptures {
    requests: Vec<ReceivedRequest>,
}

impl HttpCaptures {
    /// All captured HTTP requests.
    #[must_use]
    pub fn all(&self) -> &[ReceivedRequest] {
        &self.requests
    }

    /// Captured requests whose path exactly matches `path`.
    #[must_use]
    pub fn for_path(&self, path: &str) -> Vec<&ReceivedRequest> {
        self.requests.iter().filter(|r| r.path == path).collect()
    }

    /// True when at least one request reached the mock server.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.requests.is_empty()
    }
}

// ── PhaseOutput ───────────────────────────────────────────────────────────────

/// Combined output from one scenario phase: agent result + mock HTTP captures.
/// Passed to both [`EnforcementScenario::assert_baseline`] and
/// [`EnforcementScenario::assert_enforcement`].
pub struct PhaseOutput {
    pub agent: AgentOutput,
    pub http_requests: HttpCaptures,
}

// ── FirmaAudit ────────────────────────────────────────────────────────────────

/// Sidecar audit events from the enforcement phase.
/// Passed only to [`EnforcementScenario::assert_enforcement`].
pub struct FirmaAudit {
    events: Vec<ExecutionEvent>,
}

impl FirmaAudit {
    /// Audit events where the sidecar issued an ALLOW decision.
    #[must_use]
    pub fn allow_events(&self) -> Vec<&ExecutionEvent> {
        audit::allow_events(&self.events)
    }

    /// Audit events where the sidecar issued a DENY decision.
    #[must_use]
    pub fn deny_events(&self) -> Vec<&ExecutionEvent> {
        audit::deny_events(&self.events)
    }

    /// Audit events whose `action` contains `fragment`.
    #[must_use]
    pub fn events_for_action(&self, fragment: &str) -> Vec<&ExecutionEvent> {
        self.events
            .iter()
            .filter(|e| e.action.contains(fragment))
            .collect()
    }
}

// ── EnforcementScenario trait ─────────────────────────────────────────────────

#[allow(async_fn_in_trait)]
pub trait EnforcementScenario: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// Maximum wall-clock time allowed for the enforcement phase.
    fn timeout(&self) -> Duration {
        Duration::from_mins(5)
    }

    /// Return `true` if the scenario requires structural network confinement
    /// (i.e. bwrap `--unshare-net`) to produce a meaningful enforcement result.
    /// Scenarios that return `true` are skipped on backends that provide only
    /// proxy-based network enforcement (macOS vz, WSL2).
    fn requires_structural_network(&self) -> bool {
        false
    }

    /// Configure the scenario: register HTTP mock routes, add mapping rules,
    /// append Cedar policy rules, configure sandbox mounts, etc.
    fn setup(&self, _ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Called before each phase (baseline and enforcement).
    /// Use to create or recreate any per-phase filesystem state the agent
    /// will interact with (e.g. a file the agent is expected to delete).
    fn before_assert(&self, _ctx: &ScenarioSetup) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Natural-language prompt sent to the agent.
    fn prompt(&self, ctx: &ScenarioSetup) -> String;

    fn assert_baseline(&self, output: &PhaseOutput) -> Result<(), anyhow::Error>;

    fn assert_enforcement(
        &self,
        output: &PhaseOutput,
        audit: &FirmaAudit,
    ) -> Result<(), anyhow::Error>;
}

// ── ScenarioSetup ─────────────────────────────────────────────────────────────

pub struct ScenarioSetup {
    pub workspace_dir: PathBuf,
    pub protected_dir: PathBuf,
    pub capability_seed: Option<PathBuf>,
    pub capability_session_id: Option<String>,

    mock_host: String,
    mock_port: u16,
    mock_specs: Vec<MockSpec>,
    config_dir: PathBuf,
    state_dir: PathBuf,
    agent: Agent,
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
        // REST rule — normalizer keeps host:port for HTTP requests.
        config::add_mapping_rule(&self.config_dir, host_port, method, path, action_class)?;
        // CONNECT rule — host:port for TLS tunnel establishment.
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
    /// Required by agents (e.g. codex) that refuse to run outside a git repo.
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
        let out = std::process::Command::new(crate::firma_bin())
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
    ///
    /// Call `.run()` on the returned builder to execute.
    /// Defaults: `--mode agent-local`, `--posture dev`, `--workspace <workspace_dir>`.
    #[must_use]
    pub fn firma_config(&self) -> FirmaConfigBuilder<'_> {
        FirmaConfigBuilder::new(self)
    }
}

// ── FirmaConfigBuilder ────────────────────────────────────────────────────────

/// Builder for `firma config init` invocations.
///
/// ```ignore
/// ctx.firma_config()
///     .posture("dev-with-delete-watch")
///     .run()?;
/// ```
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
    fn new(ctx: &'a ScenarioSetup) -> Self {
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

// ── PolicyBuilder ─────────────────────────────────────────────────────────────

/// Entry point for building Cedar policy rules programmatically.
///
/// ```ignore
/// ctx.policy()
///     .forbid("communication.external.send")
///     .when(|w| w.resource_like("paste.rs*"))
///     .add()?;
/// ```
pub struct PolicyBuilder<'a> {
    ctx: &'a ScenarioSetup,
    name: Option<&'static str>,
}

impl<'a> PolicyBuilder<'a> {
    fn new(ctx: &'a ScenarioSetup) -> Self {
        Self { ctx, name: None }
    }

    /// Attach an annotation comment to the generated Cedar rule.
    #[must_use]
    pub fn named(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// Start a `forbid` rule for a single action class.
    #[must_use]
    pub fn forbid(self, action: &'static str) -> RuleBuilder<'a> {
        self.into_rule("forbid", Effect::Single(action))
    }

    /// Start a `permit` rule for a single action class.
    #[must_use]
    pub fn permit(self, action: &'static str) -> RuleBuilder<'a> {
        self.into_rule("permit", Effect::Single(action))
    }

    /// Start a `forbid` rule covering multiple action classes.
    #[must_use]
    pub fn forbid_in(self, actions: &'static [&'static str]) -> RuleBuilder<'a> {
        self.into_rule("forbid", Effect::Set(actions))
    }

    /// Start a `permit` rule covering multiple action classes.
    #[must_use]
    pub fn permit_in(self, actions: &'static [&'static str]) -> RuleBuilder<'a> {
        self.into_rule("permit", Effect::Set(actions))
    }

    fn into_rule(self, effect: &'static str, action: Effect) -> RuleBuilder<'a> {
        RuleBuilder {
            ctx: self.ctx,
            name: self.name,
            effect,
            action,
            resource: None,
            when: None,
        }
    }
}

enum Effect {
    Single(&'static str),
    Set(&'static [&'static str]),
}

/// A Cedar rule under construction — created by [`PolicyBuilder`].
///
/// Call [`RuleBuilder::when`] to add a `when` clause, then [`RuleBuilder::add`]
/// to write the rule to `policies/dev.cedar`.
pub struct RuleBuilder<'a> {
    ctx: &'a ScenarioSetup,
    name: Option<&'static str>,
    effect: &'static str,
    action: Effect,
    resource: Option<String>,
    when: Option<String>,
}

impl RuleBuilder<'_> {
    /// Scope the rule to a specific resource entity UID (host + path, e.g. `"127.0.0.1:8080/paste"`).
    /// Rendered as `Firma::Resource::"<uid>"` in the rule head.
    #[must_use]
    pub fn resource_uid(mut self, uid: impl Into<String>) -> Self {
        self.resource = Some(uid.into());
        self
    }

    /// Add a `when` clause to the rule. The closure receives a [`WhenBuilder`]
    /// which accumulates conditions.
    ///
    /// ```ignore
    /// .when(|w| w.resource_like("paste.rs*"))
    /// .when(|w| w.context("budget_remaining").greater_than(0).and().context("risk_score").less_than(30))
    /// ```
    #[must_use]
    pub fn when<F>(mut self, f: F) -> Self
    where
        F: FnOnce(WhenBuilder) -> WhenBuilder,
    {
        let wb = WhenBuilder::new();
        self.when = Some(f(wb).build());
        self
    }

    /// Format the Cedar rule and write it to `policies/dev.cedar`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or written.
    pub fn add(self) -> Result<(), anyhow::Error> {
        let config_dir = self.ctx.config_dir.clone();
        let rule = self.render();
        config::append_policy_rule(&config_dir, "dev", &rule)
    }

    fn render(self) -> String {
        let mut s = String::new();
        if let Some(name) = self.name {
            s.push_str("// ");
            s.push_str(name);
            s.push('\n');
        }
        s.push_str(self.effect);
        s.push_str("(\n    principal,\n    ");
        let resource_head = self.resource.as_deref().map_or_else(
            || "resource".to_string(),
            |uid| format!("resource == Firma::Resource::\"{uid}\""),
        );
        match self.action {
            Effect::Single(a) => {
                s.push_str("action == Firma::Action::\"");
                s.push_str(a);
                s.push_str("\",\n    ");
                s.push_str(&resource_head);
                s.push_str("\n)");
            }
            Effect::Set(actions) => {
                s.push_str("action in [");
                for (i, a) in actions.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str("Firma::Action::\"");
                    s.push_str(a);
                    s.push('"');
                }
                s.push_str("],\n    ");
                s.push_str(&resource_head);
                s.push_str("\n)");
            }
        }
        if let Some(when_clause) = self.when {
            s.push_str("\nwhen { ");
            s.push_str(&when_clause);
            s.push_str(" }");
        }
        s.push(';');
        s
    }
}

/// Accumulates `when` clause conditions via a fluent API.
///
/// Start with [`WhenBuilder::resource_like`] or [`WhenBuilder::context`],
/// chain with [`.and()`](WhenBuilder::and), and pass the result back
/// to [`RuleBuilder::when`].
///
/// ```ignore
/// WhenBuilder::new()
///     .context("budget_remaining").greater_than(0)
///     .and()
///     .resource_like("paste.rs*")
/// ```
pub struct WhenBuilder {
    parts: Vec<String>,
}

impl WhenBuilder {
    fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// `resource.id like "<pattern>"`
    #[must_use]
    pub fn resource_like(mut self, pattern: impl std::fmt::Display) -> Self {
        self.parts.push(format!("resource.id like \"{pattern}\""));
        self
    }

    /// Start a context attribute comparison, e.g. `context.budget_remaining`.
    /// Call a method on the returned [`ContextMatcher`] to complete the
    /// comparison and get back a [`WhenBuilder`].
    ///
    /// ```ignore
    /// w.context("budget_remaining").greater_than(0)
    /// ```
    #[must_use]
    pub fn context(self, name: &str) -> ContextMatcher {
        ContextMatcher {
            parts: self.parts,
            name: name.to_string(),
        }
    }

    /// Chain another condition with `&&`.
    #[must_use]
    pub fn and(mut self) -> Self {
        self.parts.push("&&".to_string());
        self
    }

    fn build(self) -> String {
        self.parts.join(" ")
    }
}

/// In-progress context attribute comparison — created by
/// [`WhenBuilder::context`].
pub struct ContextMatcher {
    parts: Vec<String>,
    name: String,
}

impl ContextMatcher {
    /// `context.<name> > <value>`
    #[must_use]
    pub fn greater_than(mut self, value: impl std::fmt::Display) -> WhenBuilder {
        self.parts.push(format!("context.{} > {value}", self.name));
        WhenBuilder { parts: self.parts }
    }

    /// `context.<name> < <value>`
    #[must_use]
    pub fn less_than(mut self, value: impl std::fmt::Display) -> WhenBuilder {
        self.parts.push(format!("context.{} < {value}", self.name));
        WhenBuilder { parts: self.parts }
    }

    /// `context.<name> == <value>`
    #[must_use]
    pub fn equals(mut self, value: impl std::fmt::Display) -> WhenBuilder {
        self.parts.push(format!("context.{} == {value}", self.name));
        WhenBuilder { parts: self.parts }
    }
}

// ── Output / result types ─────────────────────────────────────────────────────

pub struct AgentOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

pub struct ScenarioResult {
    pub scenario_name: String,
    pub baseline_passed: bool,
    pub enforcement_passed: bool,
    pub enforcement_error: Option<String>,
    pub enforcement_output: PhaseOutput,
    pub firma_audit: FirmaAudit,
}

// ── run_scenario ──────────────────────────────────────────────────────────────

/// Run a full two-phase scenario for `agent`.
///
/// Phase 1 (baseline): agent runs directly — no firma proxy; HTTP requests
/// are captured and passed to [`EnforcementScenario::assert_baseline`].
/// Phase 2 (enforcement): agent runs through `firma run`; mock routes active;
/// HTTP requests and sidecar audit log captured for
/// [`EnforcementScenario::assert_enforcement`].
#[allow(clippy::too_many_lines)]
pub async fn run_scenario(
    scenario: &dyn EnforcementScenario,
    agent: &Agent,
) -> Result<ScenarioResult, anyhow::Error> {
    // Bind the capture server on all interfaces so agents inside bwrap sandboxes
    // can reach it via the host's outbound IP (loopback is isolated in bwrap).
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

    // Read baseline HTTP captures before clearing for enforcement.
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

    // Transfer mock specs into the capture server; clear baseline captures
    // so enforcement captures are isolated.
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
            elapsed: Duration::from_secs(0),
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
