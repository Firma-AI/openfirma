//! Per-session live capability issuance for `firma run`.
//!
//! Calls the Authority's `IssueCapability` RPC once per invocation, verifies
//! the returned token locally, and writes the resulting [`CapabilitySeed`] to
//! `$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`. The sidecar then
//! loads it via `[capability_seed]`.

// M-CANONICAL-DOCS: all public items carry doc comments.
// M-ERRORS-CANONICAL-STRUCTS: errors are forwarded through RunError.
// M-PANIC-IS-STOP: no unwrap/expect/panic outside tests.

use std::path::{Path, PathBuf};
use std::time::Duration;

use firma_core::token::paseto::PasetoV4Verifier;
use firma_core::{CapabilitySeed, TokenVerifier};
use firma_protobuf::v1::IssueCapabilityRequest;
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_sidecar::authority_client::channel::build_channel;
use firma_sidecar::authority_credentials::ResolvedSidecarCredentials;

use crate::error::RunError;

/// Inputs for a single capability mint.
#[derive(Debug, Clone)]
pub struct IssueParams {
    /// Authority gRPC URL.
    pub authority_url: String,
    /// Path to the Authority's Ed25519 public key (for local verification).
    pub authority_pub_key_path: PathBuf,
    /// Optional PEM CA cert path for an `https://` Authority.
    pub authority_ca_cert_path: Option<PathBuf>,
    /// Optional Sidecar credentials for the Authority request.
    pub credentials: Option<ResolvedSidecarCredentials>,
    /// Agent identity to bind into the request.
    pub agent_id: String,
    /// Session identity to bind into the request.
    pub session_id: String,
    /// Action classes requested.
    pub requested_actions: Vec<String>,
    /// Resource scope requested.
    pub resource_scope: String,
    /// Requested TTL in seconds.
    pub ttl_seconds: i32,
}

/// Default action set requested when none is configured.
pub const DEFAULT_REQUESTED_ACTIONS: &[&str] = &["communication.external.send"];

/// Default resource scope.
pub const DEFAULT_RESOURCE_SCOPE: &str = "*";

/// Default capability TTL in seconds (15 minutes).
///
/// Chosen to be long enough to cover typical agent sessions while
/// short enough to limit token exposure if a seed file is leaked.
pub const DEFAULT_TTL_SECONDS: i32 = 900;

/// Mint a capability and write the seed file. Returns the written path.
///
/// Runs the async RPC inside a scoped current-thread tokio runtime so the
/// synchronous `firma run` call path is unchanged.
///
/// # Errors
///
/// - [`RunError::AuthorityUnreachable`] on channel/transport/connect failure.
/// - [`RunError::CapabilityDenied`] when the Authority returns `granted=false`.
/// - [`RunError::Capability`] on verification, encoding, or file-write failure.
pub fn mint_and_write(params: &IssueParams, out_path: &Path) -> Result<PathBuf, RunError> {
    let seed = mint(params)?;
    write_seed(&seed, out_path)?;
    Ok(out_path.to_path_buf())
}

fn mint(params: &IssueParams) -> Result<CapabilitySeed, RunError> {
    let pub_key = std::fs::read(&params.authority_pub_key_path).map_err(|e| {
        RunError::Capability(format!(
            "read authority public key '{}': {e}",
            params.authority_pub_key_path.display()
        ))
    })?;
    let verifier = PasetoV4Verifier::try_new(&pub_key)
        .map_err(|e| RunError::Capability(format!("invalid authority public key: {e}")))?;

    let ca_pem = match &params.authority_ca_cert_path {
        Some(p) => Some(std::fs::read(p).map_err(|e| {
            RunError::Capability(format!("read authority CA cert '{}': {e}", p.display()))
        })?),
        None => None,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| RunError::Internal(format!("build tokio runtime: {e}")))?;

    // `build_channel` calls `Endpoint::connect_lazy`, whose connector wiring
    // requires an active Tokio reactor; build it inside `block_on` so the call
    // site does not need to already be running on a runtime. `firma run`
    // invokes this from a synchronous code path, so this must self-host.
    let response = runtime.block_on(async {
        let channel = build_channel(
            &params.authority_url,
            Duration::from_secs(10),
            ca_pem.as_deref(),
            None,
            None,
        )
        .map_err(|e| RunError::AuthorityUnreachable {
            url: params.authority_url.clone(),
            reason: e.to_string(),
        })?;
        let mut client = AuthorityServiceClient::new(channel);
        client
            .issue_capability(IssueCapabilityRequest {
                agent_id: params.agent_id.clone(),
                session_id: params.session_id.clone(),
                requested_actions: params.requested_actions.clone(),
                resource_scope: params.resource_scope.clone(),
                requested_ttl_seconds: params.ttl_seconds,
                credentials: params
                    .credentials
                    .as_ref()
                    .map(ResolvedSidecarCredentials::to_proto),
            })
            .await
            .map(tonic::Response::into_inner)
            .map_err(|status| RunError::AuthorityUnreachable {
                url: params.authority_url.clone(),
                reason: format!("IssueCapability RPC failed: {status}"),
            })
    })?;

    if !response.granted {
        return Err(RunError::CapabilityDenied {
            agent_id: params.agent_id.clone(),
            reason: response.deny_reason,
            message: response.deny_message,
        });
    }

    let token = response
        .token
        .ok_or_else(|| RunError::Capability("granted=true but no token returned".to_string()))?;

    // `signature` carries the raw PASETO token string as UTF-8 bytes.
    let raw_token = String::from_utf8(token.signature)
        .map_err(|e| RunError::Capability(format!("token is not valid UTF-8: {e}")))?;

    let claims = verifier.verify(&raw_token).map_err(|e| {
        RunError::Capability(format!("issued token failed local verification: {e}"))
    })?;

    Ok(CapabilitySeed::from_claims(&claims, raw_token))
}

fn write_seed(seed: &CapabilitySeed, out_path: &Path) -> Result<(), RunError> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RunError::Capability(format!("mkdir {}: {e}", parent.display())))?;
    }
    let text = toml::to_string_pretty(seed)
        .map_err(|e| RunError::Capability(format!("serialize capability seed: {e}")))?;
    let tmp = out_path.with_extension("toml.tmp");
    std::fs::write(&tmp, &text)
        .map_err(|e| RunError::Capability(format!("write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, out_path)
        .map_err(|e| RunError::Capability(format!("rename into {}: {e}", out_path.display())))?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test module"
)]
mod tests {
    use super::*;
    use firma_core::{CapabilityClaims, TokenId};

    fn sample_seed() -> CapabilitySeed {
        let now = chrono::Utc::now();
        let claims = CapabilityClaims {
            token_id: TokenId::new(),
            agent_id: "codex".parse().unwrap(),
            session_id: "sess1".parse().unwrap(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::minutes(15),
            context_hash: "deadbeef".to_string(),
            budget_ceiling: None,
        };
        CapabilitySeed::from_claims(&claims, "v4.public.tok".to_string())
    }

    #[test]
    fn write_seed_is_atomic_and_parses_back() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("sandbox.toml");
        let seed = sample_seed();
        write_seed(&seed, &out).unwrap();
        assert!(out.exists());
        let parsed: CapabilitySeed =
            toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(parsed, seed);
        // tmp file is consumed by the rename.
        assert!(!out.with_extension("toml.tmp").exists());
    }
}
