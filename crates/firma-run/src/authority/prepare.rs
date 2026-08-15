//! Filesystem and process preparation for a local Authority launch.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use firma_authority::{AuthorityConfig, AuthorityTlsConfig};
use firma_identifiers::{AgentId, SandboxId};

use crate::error::RunError;

const LOOPBACK_EPHEMERAL: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
const AUTOSTART_LOCAL_DEVELOPER_POLICY: &str = r"// Local autostart profile for `firma run`.
//
// Governs token *issuance* only. Runtime enforcement is handled by the
// sidecar's Cedar policy bundle (dev.cedar). All registered action classes
// are permitted here so the sidecar can classify and enforce without the
// Authority becoming the bottleneck for local dev.
permit(principal, action, resource);
";

/// A fully materialized local Authority launch, without process ownership.
///
/// Preparation has already performed all validation and filesystem bootstrap;
/// the command can be spawned exactly once by a lifecycle owner.
pub struct PreparedAuthorityLaunch {
    command: Option<Command>,
    pub expected_endpoint: SocketAddr,
    pub pub_key_path: PathBuf,
    pub pid_path: PathBuf,
    pub metadata_path: PathBuf,
    pub sandbox_id: SandboxId,
    pub agent_id: AgentId,
    pub session_id: String,
    pub profile_name: String,
}

impl PreparedAuthorityLaunch {
    /// Transfer the prepared command to its lifecycle owner exactly once.
    pub fn take_command(&mut self) -> Result<Command, RunError> {
        self.command.take().ok_or_else(|| {
            RunError::Internal("prepared Authority command was already taken".into())
        })
    }
}

/// Publish the effective Authority process identity and endpoint after readiness.
pub fn publish_metadata(
    prepared: &PreparedAuthorityLaunch,
    listen_addr: SocketAddr,
    pid: firma_runtime_state::UserProcessId,
) -> Result<(), RunError> {
    firma_runtime_state::pidfile::write(&prepared.pid_path, pid)
        .map_err(|error| RunError::Internal(format!("write authority.pid: {error}")))?;
    crate::authority::metadata::write(
        &prepared.metadata_path,
        &crate::authority::metadata::Metadata {
            sandbox_id: prepared.sandbox_id,
            agent_id: prepared.agent_id,
            session_id: prepared.session_id.clone(),
            profile: prepared.profile_name.clone(),
            listen_addr: listen_addr.to_string(),
            pid,
            started_at: chrono::Utc::now().to_rfc3339(),
        },
    )
}

/// Inputs needed to validate and materialize an Authority launch.
pub struct PrepareRequest<'a> {
    pub sandbox_id: &'a SandboxId,
    pub agent_id: &'a AgentId,
    pub session_id: &'a str,
    pub marker_dir: PathBuf,
    pub profile_name: &'a str,
    pub firma_exe: PathBuf,
    pub user_config_path: Option<PathBuf>,
}

/// Validate and materialize everything needed to launch a local Authority.
pub fn prepare(req: &PrepareRequest<'_>) -> Result<PreparedAuthorityLaunch, RunError> {
    firma_authority::cedar_for(req.profile_name).map_err(|_| {
        RunError::AuthorityUnknownProfile {
            name: req.profile_name.to_string(),
        }
    })?;

    firma_fs::create_private_dir_all(&req.marker_dir)
        .map_err(|error| RunError::Internal(error.to_string()))?;
    let authority_toml = req.marker_dir.join("authority.toml");
    let pid_path = req.marker_dir.join("authority.pid");
    let metadata_path = req.marker_dir.join("metadata.toml");

    let authority_config = if let Some(ref user_config) = req.user_config_path {
        persisted_authority_config(user_config)?
    } else {
        ephemeral_authority_config(req)?
    };
    let pub_key_path = authority_config.key_file.with_extension("pub");
    let inner = toml::to_string_pretty(&authority_config).map_err(|error| {
        RunError::Internal(format!("invalid synthetic authority config: {error}"))
    })?;
    std::fs::write(&authority_toml, format!("[authority]\n{inner}")).map_err(|error| {
        RunError::Internal(format!("write {}: {error}", authority_toml.display()))
    })?;

    let mut command = Command::new(&req.firma_exe);
    let child_environment = std::env::vars_os()
        .filter(|(key, _)| !key.to_string_lossy().starts_with("FIRMA_AUTHORITY_"));
    command
        .args(["authority", "--config"])
        .arg(&authority_toml)
        .env_clear()
        .envs(child_environment)
        .env_remove("FIRMA_LOG_FILE")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    Ok(PreparedAuthorityLaunch {
        command: Some(command),
        expected_endpoint: LOOPBACK_EPHEMERAL,
        pub_key_path,
        pid_path,
        metadata_path,
        sandbox_id: *req.sandbox_id,
        agent_id: *req.agent_id,
        session_id: req.session_id.to_string(),
        profile_name: req.profile_name.to_string(),
    })
}

fn persisted_authority_config(user_config: &Path) -> Result<AuthorityConfig, RunError> {
    let config_dir = user_config.parent().unwrap_or_else(|| Path::new("."));
    let body = firma_config_loader::load_section(user_config, "authority").map_err(|error| {
        RunError::Internal(format!(
            "load [authority] from {}: {error}",
            user_config.display()
        ))
    })?;
    let mut config = toml::from_str::<AuthorityConfig>(&body)
        .map_err(|error| RunError::Internal(format!("parse authority config: {error}")))?;
    config.rebase_defaults(config_dir);
    config.tls = AuthorityTlsConfig::default();
    config.listen_addr = LOOPBACK_EPHEMERAL.to_string();
    ensure_authority_key(&config.key_file)?;
    Ok(config)
}

fn ensure_authority_key(key_path: &Path) -> Result<(), RunError> {
    if key_path.is_file() {
        return Ok(());
    }
    if let Some(parent) = key_path.parent() {
        firma_fs::create_private_dir_all(parent)
            .map_err(|error| RunError::Internal(error.to_string()))?;
    }
    firma_authority::write_keypair(key_path)
        .map(|_| ())
        .map_err(|error| {
            RunError::Internal(format!(
                "generate authority key at {}: {error}",
                key_path.display()
            ))
        })
}

fn ephemeral_authority_config(req: &PrepareRequest<'_>) -> Result<AuthorityConfig, RunError> {
    let policy_dir = req.marker_dir.join("policy_dir");
    let keys_dir = req.marker_dir.join("keys");
    let cedar_path = policy_dir.join(format!("{}.cedar", req.profile_name));
    let key_path = keys_dir.join("authority.key");
    let revocation_file = req.marker_dir.join("revocations.txt");
    firma_fs::create_private_dir_all(&policy_dir)
        .map_err(|error| RunError::Internal(error.to_string()))?;
    firma_fs::create_private_dir_all(&keys_dir)
        .map_err(|error| RunError::Internal(error.to_string()))?;
    let cedar = if req.profile_name == firma_authority::DEFAULT_PROFILE {
        AUTOSTART_LOCAL_DEVELOPER_POLICY
    } else {
        firma_authority::cedar_for(req.profile_name).map_err(|_| {
            RunError::AuthorityUnknownProfile {
                name: req.profile_name.to_string(),
            }
        })?
    };
    std::fs::write(&cedar_path, cedar)
        .map_err(|error| RunError::Internal(format!("write {}: {error}", cedar_path.display())))?;
    std::fs::write(&revocation_file, b"").map_err(|error| {
        RunError::Internal(format!("write {}: {error}", revocation_file.display()))
    })?;
    firma_authority::write_keypair(&key_path).map_err(|error| {
        RunError::Internal(format!(
            "generate authority key for {}: {error}",
            key_path.display()
        ))
    })?;
    Ok(AuthorityConfig {
        listen_addr: LOOPBACK_EPHEMERAL.to_string(),
        policy_dir: policy_dir.clone(),
        issuance_policy_dir: policy_dir,
        schema_path: None,
        revocation_file,
        max_ttl_seconds: 3600,
        key_file: key_path,
        log_level: "info".to_string(),
        bundle_ttl_seconds: 30,
        tls: AuthorityTlsConfig::default(),
    })
}
