//! `firma run --agent`: the launch of a run the Control Plane
//! activated, on the same path a project run takes.

use firma_config_loader::AgentProfile;
use firma_identifiers::{AgentId, RunId, SidecarId, WorkspaceId};
use firma_sidecar::authority_credentials::{CredentialSource, SidecarCredentialsConfig};
use secrecy::ExposeSecret as _;

use super::{LaunchHooks, RunCompletion, RunInput};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::routing::ResolvedAuthority;

/// A run the Control Plane reserved and activated: the Agent, the run
/// it runs as, and what the Sidecar needs to authenticate to the Authority.
pub struct ManagedRunInput {
    /// The Agent being run.
    pub agent_id: AgentId,
    /// The `OpenFirma` profile the Control Plane configured for it.
    pub profile: AgentProfile,
    /// The reserved run; the run's session id.
    pub run_id: RunId,
    /// The Sidecar identity activation issued for this run alone.
    pub sidecar_id: SidecarId,
    /// The Workspace the Agent belongs to.
    pub workspace_id: WorkspaceId,
    /// Where the Sidecar and the capability mint reach the Authority's gRPC
    /// services: `https` to another host, verified against the platform's
    /// trusted roots, or `http` to a loopback host.
    pub authority_grpc_uri: url::Url,
    /// The Workspace's Ed25519 capability verifying key, raw 32 bytes.
    pub capability_public_key: [u8; 32],
    /// The runtime credential activation issued; the Sidecar alone receives
    /// it, through its own environment.
    pub credential: secrecy::SecretString,
    /// The workload command.
    pub command: Vec<String>,
}

/// The variable a managed run's Sidecar reads its credential from: the
/// synthesized configuration's `runtime_credential_env`, set on the Sidecar
/// process alone.
const RUNTIME_CREDENTIAL_ENV: &str = "FIRMA_RUNTIME_CREDENTIAL";

/// Checks the managed profile's effective backend before reserving a run.
/// No sandbox or run marker is created.
///
/// # Errors
///
/// Returns profile, host-support, or network opt-in errors.
pub fn preflight_managed_run(profile: AgentProfile) -> Result<(), RunError> {
    let args = managed_args(profile, Vec::new());
    let profile = crate::config::resolve_profile(&args)?;
    let backend = crate::backend::build_backend(profile.backend);
    backend.preflight(&profile)?;
    if !backend.structural_network(&profile.network)
        && !profile.allow_non_structural
        && !crate::config::env_truthy("FIRMA_RUN_ALLOW_NON_STRUCTURAL")
    {
        return Err(RunError::NonStructuralBackendRequiresOptIn {
            backend: profile.backend.to_string(),
        });
    }
    Ok(())
}

fn managed_args(profile: AgentProfile, command: Vec<String>) -> RunInput {
    RunInput {
        profile: profile.as_str().to_owned(),
        config: None,
        backend: None,
        sidecar_cli: crate::sidecar::SidecarCli::Local,
        capability_file: None,
        identity_mode: None,
        preserve_host_user: false,
        print_effective_config: false,
        no_autostart: false,
        sidecar_startup_timeout_secs: 0,
        command,
        authority_cli: crate::authority::AuthorityCli::Unset,
        authority_profile: String::new(),
        user_config_path: None,
        allow_non_structural: false,
    }
}

/// Runs `input.command` as the run the Control Plane activated.
///
/// Everything [`execute_run`](super::execute_run) does with a project `firma.toml`, except that
/// the Agent identity, the profile, the Authority and the credential come
/// from the Control Plane, and nothing under `.firma/` is read or written.
///
/// The [`RunCompletion`] keeps the command's result apart from cleanup, so
/// the caller can report how the run ended even when cleanup failed.
pub fn execute_managed_run(input: ManagedRunInput, hooks: &LaunchHooks<'_>) -> RunCompletion {
    let ManagedRunInput {
        agent_id,
        profile,
        run_id,
        sidecar_id,
        workspace_id,
        authority_grpc_uri,
        capability_public_key,
        credential,
        command,
    } = input;
    let args = managed_args(profile, command);
    let credentials_config = SidecarCredentialsConfig {
        workspace_id: workspace_id.to_string(),
        sidecar_id: sidecar_id.to_string(),
        source: CredentialSource::Runtime {
            env: RUNTIME_CREDENTIAL_ENV.to_string(),
            run_id,
        },
    };
    // One carrier for the credential: the mint presents it, and the Sidecar
    // launch takes it from the same value.
    let credentials = match credentials_config.runtime_credential(credential.expose_secret()) {
        Ok(credentials) => credentials,
        Err(error) => {
            return RunCompletion::not_started(RunError::Internal(format!(
                "runtime credential: {error}"
            )));
        }
    };
    let managed = Managed {
        identity: RunIdentity::managed(agent_id, profile.as_str(), run_id),
        authority: ResolvedAuthority {
            url: authority_grpc_uri.origin().ascii_serialization(),
            ca_cert_path: None,
            trust: firma_sidecar::config::AuthorityTrust::PlatformStore,
            connect_addr: None,
            // Named once `prepare_run_components` has written the key.
            pub_key_path: None,
            credentials: Some(credentials),
            credentials_config: Some(credentials_config),
            owned: None,
            capability_public_key: Some(capability_public_key),
        },
    };
    super::execute(&args, hooks, Some(managed))
}

/// What a managed run fixes before the shared launch path: its identity and
/// the Authority it was resolved to.
pub struct Managed {
    pub identity: RunIdentity,
    pub authority: ResolvedAuthority,
}
