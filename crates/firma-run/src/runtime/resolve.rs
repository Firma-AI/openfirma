//! What a run resolves before it creates a sandbox: its configuration,
//! identity, profile and local inputs.

use std::env;
use std::path::{Path, PathBuf};

use firma_connection_store::StoreError;
use firma_identifiers::AgentId;
use firma_runtime_state::RuntimeLayout;

use serde::Serialize;

use super::{RunInput, managed};
use crate::capability::read_capability_token;
use crate::config::{ResolvedProfile, resolve_profile_with_layout};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::routing::ResolvedAuthority;

/// Where a run's identity and Authority come from.
enum RunSource {
    /// A project `firma.toml`, resolved and read for the Agent id.
    Project {
        config: Option<firma_config_loader::ResolvedConfig>,
        agent_id: AgentId,
    },
    /// The Control Plane, through [`super::execute_managed_run`].
    Managed(Box<managed::Managed>),
}

/// Everything a run resolved before its sandbox exists.
pub(super) struct ResolvedRun {
    pub runtime_layout: RuntimeLayout,
    pub profile: ResolvedProfile,
    pub identity: RunIdentity,
    pub managed_authority: Option<ResolvedAuthority>,
    pub user_config_path: Option<PathBuf>,
    pub user_config_dir: Option<PathBuf>,
    pub allow_non_structural: bool,
    pub capability_token: Option<String>,
    pub working_dir: PathBuf,
    pub host_connection_dir: Option<PathBuf>,
    pub firma_exe: PathBuf,
}

/// Resolves what a run needs before it creates a sandbox.
pub(super) fn resolve_run(
    args: &RunInput,
    managed: Option<managed::Managed>,
) -> Result<ResolvedRun, RunError> {
    if args.command.is_empty() {
        return Err(RunError::MissingCommand);
    }

    crate::identity::reject_reserved_sandbox_id_environment()?;

    // A managed run has no project configuration and its session is the
    // execution: nothing is discovered or required from the environment.
    let source = if let Some(managed) = managed {
        crate::identity::reject_reserved_session_id_environment()?;
        RunSource::Managed(Box::new(managed))
    } else {
        ensure_required_session_identity()?;
        let config_override = args.user_config_path.as_deref().or(args.config.as_deref());
        let config = firma_config_loader::ConfigResolver::default()
            .resolve_config(config_override)
            .map_err(|error| RunError::ConfigParse {
                path: error.path.clone(),
                reason: error.to_string(),
            })?;
        let agent_id = config
            .as_ref()
            .map(firma_config_loader::ResolvedConfig::config_file)
            .map_or_else(
                || {
                    Err(RunError::MissingAgentId {
                        path: PathBuf::from("firma.toml"),
                    })
                },
                crate::identity::read_configured_agent_id,
            )?;
        RunSource::Project { config, agent_id }
    };
    let resolved_user_config = match &source {
        RunSource::Project { config, .. } => config.as_ref(),
        RunSource::Managed(_) => None,
    };
    let user_config_path = resolved_user_config
        .map(firma_config_loader::ResolvedConfig::config_file)
        .map(Path::to_path_buf);
    let user_config_dir = resolved_user_config.map(firma_config_loader::ResolvedConfig::config_dir);

    let runtime_layout = RuntimeLayout::resolve(None)
        .map_err(|error| RunError::Internal(format!("resolve runtime layout: {error}")))?;
    let profile = resolve_profile_with_layout(args, &runtime_layout)?;
    let (identity, managed_authority) = match source {
        RunSource::Managed(managed) => (managed.identity, Some(managed.authority)),
        RunSource::Project { agent_id, .. } => {
            (RunIdentity::new(agent_id, profile.id.clone()), None)
        }
    };
    if args.print_effective_config {
        print_effective_config(&identity, &profile)?;
    }

    let allow_non_structural =
        profile.allow_non_structural || crate::config::env_truthy("FIRMA_RUN_ALLOW_NON_STRUCTURAL");

    log_run_start(&identity, &profile);

    let capability_token = read_capability_token(&profile.capability.source)?;
    let working_dir = resolve_working_dir()?;
    let host_connection_dir = match firma_connection_store::default_dir() {
        Ok(dir) => Some(dir),
        Err(StoreError::NoConfigDirectory | StoreError::RelativeDirectory { .. }) => None,
        Err(error) => {
            return Err(RunError::Internal(format!(
                "resolve host login directory: {error}"
            )));
        }
    };
    let firma_exe = env::current_exe()
        .map_err(|error| RunError::Internal(format!("resolve current_exe: {error}")))?;

    Ok(ResolvedRun {
        runtime_layout,
        profile,
        identity,
        managed_authority,
        user_config_path,
        user_config_dir,
        allow_non_structural,
        capability_token,
        working_dir,
        host_connection_dir,
        firma_exe,
    })
}

fn log_run_start(identity: &RunIdentity, profile: &ResolvedProfile) {
    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        session_id = %identity.session_id,
        agent_id = %identity.agent_id,
        profile = %identity.execution_profile,
        backend = %profile.backend,
        "starting firma run"
    );
}

fn resolve_working_dir() -> Result<PathBuf, RunError> {
    env::current_dir()
        .map_err(|error| RunError::Internal(format!("failed to read current directory: {error}")))
}

fn ensure_required_session_identity() -> Result<(), RunError> {
    let require = env::var("FIRMA_RUN_REQUIRE_SESSION_ID").is_ok_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    });
    if !require {
        return Ok(());
    }
    let has_session = env::var("FIRMA_RUN_SESSION_ID").is_ok_and(|v| !v.trim().is_empty());
    if has_session {
        return Ok(());
    }
    Err(RunError::ConfigValidation(
        "FIRMA_RUN_REQUIRE_SESSION_ID is enabled but FIRMA_RUN_SESSION_ID is not set; set a stable session id so capability issuance/seed selection can match runtime attribution".to_string(),
    ))
}

fn print_effective_config(
    identity: &RunIdentity,
    profile: &ResolvedProfile,
) -> Result<(), RunError> {
    #[derive(Serialize)]
    struct Snapshot<'a> {
        agent_id: &'a firma_identifiers::AgentId,
        execution_profile: &'a str,
        profile: &'a ResolvedProfile,
        working_dir: PathBuf,
    }

    let snapshot = Snapshot {
        agent_id: &identity.agent_id,
        execution_profile: &identity.execution_profile,
        profile,
        working_dir: env::current_dir().map_err(|error| {
            RunError::Internal(format!(
                "failed to resolve working dir for snapshot: {error}"
            ))
        })?,
    };

    let json = serde_json::to_string_pretty(&snapshot)
        .map_err(|error| RunError::Internal(format!("snapshot serialization failed: {error}")))?;
    println!("{json}");
    Ok(())
}
