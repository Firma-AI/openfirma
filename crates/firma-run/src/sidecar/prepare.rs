//! Filesystem and process preparation for a local Sidecar launch.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use firma_config_loader::AgentProfile;
use firma_core::SecretMatcher;
use firma_identifiers::{AgentId, SandboxId};
use firma_runtime_state::RunEntryLayout;
use firma_secret_provider::gateway::client::GATEWAY_ADDR_ENV;
use firma_secret_provider::spec::http::HttpIntegrationSpec;
use firma_sidecar::authority_credentials::{SidecarCredential, SidecarCredentialsConfig};

use crate::config::SidecarEndpoint;
use crate::error::RunError;

const LOOPBACK_EPHEMERAL: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

fn validated_config(
    path: &Path,
    state: &firma_runtime_state::RuntimeLayout,
) -> Result<toml::Value, RunError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| RunError::Internal(format!("read {}: {error}", path.display())))?;
    let document: toml::Value = toml::from_str(&text)
        .map_err(|error| RunError::Internal(format!("parse synthesized config: {error}")))?;
    let section = document
        .get("sidecar")
        .ok_or_else(|| RunError::Internal("synthesized config has no [sidecar] table".into()))?;
    let schema = section.clone().try_into().map_err(|error| {
        RunError::ConfigValidation(format!("invalid synthesized Sidecar config: {error}"))
    })?;
    // Templates are drafts until orchestration injects the ready endpoint.
    firma_sidecar::config::SidecarConfig::resolve(schema, state).map_err(|error| {
        RunError::ConfigValidation(format!("invalid synthesized Sidecar config: {error}"))
    })?;
    Ok(document)
}

/// A fully materialized local Sidecar launch, without process ownership.
///
/// The preparation inputs and planned metadata correspond exactly to the
/// contained command. A lifecycle owner may inspect it, take it once, then
/// retain this value while the child runs and metadata is published.
#[doc(hidden)]
pub struct PreparedSidecarLaunch {
    command: Option<Command>,
    pub expected_endpoint: SidecarEndpoint,
    pub marker_dir: PathBuf,
    pub config_path: PathBuf,
    pub pid_path: PathBuf,
    pub metadata_path: PathBuf,
    pub audit_socket_path: PathBuf,
    sandbox_id: SandboxId,
    agent_id: AgentId,
    session_id: String,
    /// Configured Authority URL published after the launch becomes ready.
    pub planned_authority_url: String,
}

impl PreparedSidecarLaunch {
    /// Inspect the command without transferring lifecycle ownership.
    #[must_use]
    pub fn command(&self) -> Option<&Command> {
        self.command.as_ref()
    }

    /// Transfer the prepared command to a lifecycle owner exactly once.
    pub fn take_command(&mut self) -> Result<Command, RunError> {
        self.command
            .take()
            .ok_or_else(|| RunError::Internal("prepared Sidecar command was already taken".into()))
    }
}

/// Preparation-only inputs for a local Sidecar launch.
#[doc(hidden)]
pub struct PrepareRequest<'a> {
    pub state: firma_runtime_state::RuntimeLayout,
    pub sandbox_id: &'a SandboxId,
    pub agent_id: &'a AgentId,
    pub execution_profile: AgentProfile,
    pub session_id: &'a str,
    pub marker_dir: PathBuf,
    pub template: crate::sidecar::config::ResolvedTemplate,
    pub firma_exe: PathBuf,
    pub authority_url: Option<&'a str>,
    pub authority_ca_cert: Option<PathBuf>,
    pub authority_pub_key: Option<PathBuf>,
    pub authority_credentials: Option<SidecarCredentialsConfig>,
    pub capability_seed_path: Option<PathBuf>,
    pub use_http_proxy_interceptor: bool,
    pub audit_fallback_path: Option<PathBuf>,
    pub audit_signing_key_path: Option<PathBuf>,
    pub secret_gateway_addr: Option<&'a str>,
    pub http_secret_providers: &'a [HttpIntegrationSpec<SecretMatcher>],
    /// The resolved credential: a runtime credential is handed to this
    /// process alone, under the variable `authority_credentials` names.
    pub credential: Option<&'a SidecarCredential>,
}

/// The runtime credential as the one variable the Sidecar's configuration
/// names, for that process alone.
fn runtime_credential_env<'a>(
    credentials: Option<&'a SidecarCredentialsConfig>,
    credential: Option<&'a SidecarCredential>,
) -> Result<Option<(&'a str, &'a str)>, RunError> {
    let Some(name) = credentials.and_then(SidecarCredentialsConfig::runtime_credential_env_name)
    else {
        return Ok(None);
    };
    let bearer = credential
        .and_then(SidecarCredential::runtime_bearer)
        .ok_or_else(|| {
            RunError::Internal(format!(
                "{name} is configured but no runtime credential was resolved"
            ))
        })?;
    Ok(Some((name, bearer)))
}

/// Materialize a Sidecar command and all of its launch inputs.
pub fn prepare(req: PrepareRequest<'_>) -> Result<PreparedSidecarLaunch, RunError> {
    let marker_dir = std::path::absolute(&req.marker_dir).map_err(|error| {
        RunError::Internal(format!(
            "resolve marker directory {}: {error}",
            req.marker_dir.display()
        ))
    })?;
    firma_fs::create_private_dir_all(&marker_dir)
        .map_err(|error| RunError::Internal(format!("mkdir {}: {error}", marker_dir.display())))?;

    let marker_layout = RunEntryLayout::from_root(&marker_dir);
    let socket_path = marker_layout.sidecar_socket();
    let config_path = marker_layout.sidecar_config();
    let pid_path = marker_layout.sidecar_pid();
    let metadata_path = marker_layout.sidecar_metadata();
    let audit_socket_path = firma_sidecar::run_audit::socket_path_in(&marker_dir);
    let listen_addr = req.use_http_proxy_interceptor.then_some(LOOPBACK_EPHEMERAL);
    let expected_endpoint = listen_addr.map_or_else(
        || SidecarEndpoint::Unix {
            path: socket_path.clone(),
        },
        |addr| SidecarEndpoint::Tcp { addr },
    );

    crate::sidecar::config::synthesize(crate::sidecar::config::SynthesizeRequest {
        agent_id: req.agent_id,
        execution_profile: req.execution_profile,
        session_id: req.session_id,
        template: req.template,
        socket_path: &socket_path,
        listen_addr,
        out_path: &config_path,
        authority_url: req.authority_url,
        authority_ca_cert: req.authority_ca_cert.as_deref(),
        authority_pub_key: req.authority_pub_key.as_deref(),
        authority_credentials: req.authority_credentials.as_ref(),
        capability_seed_path: req.capability_seed_path.as_deref(),
        audit_fallback_path: req.audit_fallback_path.as_deref(),
        audit_signing_key_path: req.audit_signing_key_path.as_deref(),
        http_secret_providers: req.http_secret_providers,
    })?;

    let synthesized = validated_config(&config_path, &req.state)?;
    let sidecar = synthesized
        .get("sidecar")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| RunError::Internal("synthesized config has no [sidecar] table".into()))?;
    let authority_url = sidecar
        .get("authority")
        .and_then(toml::Value::as_table)
        .and_then(|authority| authority.get("url"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string();

    let mut command = Command::new(&req.firma_exe);
    command
        .args(["sidecar", "--config"])
        .arg(&config_path)
        .arg("--enforcement-state")
        .arg(firma_runtime_state::enforcement_state::run_path(
            &marker_dir,
        ))
        .env_remove("FIRMA_LOG_FILE")
        .env("FIRMA_SIDECAR_HEALTH_BIND_ADDR", "127.0.0.1:0")
        .env("FIRMA_RUN_SANDBOX_ID", req.sandbox_id.to_string())
        .env("FIRMA_RUN_PID", std::process::id().to_string())
        .env("FIRMA_RUN_AUDIT_SOCK", &audit_socket_path)
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some((name, bearer)) =
        runtime_credential_env(req.authority_credentials.as_ref(), req.credential)?
    {
        command.env(name, bearer);
    }
    if let Some(ref addr) = req.secret_gateway_addr {
        command.env(GATEWAY_ADDR_ENV, addr);
    } else {
        command.env_remove(GATEWAY_ADDR_ENV);
    }

    Ok(PreparedSidecarLaunch {
        command: Some(command),
        expected_endpoint,
        marker_dir,
        config_path,
        pid_path,
        metadata_path,
        audit_socket_path,
        sandbox_id: *req.sandbox_id,
        agent_id: *req.agent_id,
        session_id: req.session_id.to_string(),
        planned_authority_url: authority_url,
    })
}

/// Publish the existing Sidecar marker schema after a prepared launch starts.
pub fn publish_metadata(
    prepared: &PreparedSidecarLaunch,
    endpoint: &SidecarEndpoint,
    pid: firma_runtime_state::UserProcessId,
) -> Result<(), RunError> {
    firma_runtime_state::sidecar_markers::publish(
        &prepared.marker_dir,
        &firma_runtime_state::sidecar_markers::MetadataFile {
            sandbox_id: prepared.sandbox_id,
            agent_id: prepared.agent_id.to_string(),
            session_id: prepared.session_id.clone(),
            authority_url: prepared.planned_authority_url.clone(),
            // The running Sidecar publishes its enforced version separately.
            policy_bundle_version: String::new(),
            pid,
            started_at: chrono::Utc::now().to_rfc3339(),
            listen: endpoint_text(endpoint),
        },
    )
    .map_err(|error| RunError::Internal(format!("publish sidecar marker: {error}")))
}

fn endpoint_text(endpoint: &SidecarEndpoint) -> String {
    match endpoint {
        SidecarEndpoint::Tcp { addr } => addr.to_string(),
        SidecarEndpoint::Unix { path } => path.display().to_string(),
    }
}
