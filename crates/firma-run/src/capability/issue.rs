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
use firma_core::{ActionClass, AgentId, CapabilitySeed, TokenVerifier};
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_protobuf::v1::{IssueCapabilityRequest, IssueCapabilityResponse, IssueDecision};
use firma_sidecar::authority_client::channel::build_channel;
use firma_sidecar::authority_credentials::ResolvedSidecarCredentials;
use firma_sidecar::config::AuthorityEndpoint;

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
    pub agent_id: AgentId,
    /// Session identity to bind into the request.
    pub session_id: String,
    /// Action classes requested.
    pub requested_actions: Vec<String>,
    /// Resource scope requested.
    pub resource_scope: String,
    /// Requested TTL in seconds.
    pub ttl_seconds: i32,
}

/// Default action set requested when none is configured: every action class.
///
/// A run requests all action classes by default and lets the Authority narrow
/// the grant to whatever its issuance policy authorizes (`requested ∩
/// Cedar-permitted`). This keeps the Authority the single source of truth for
/// what a session may do, so a run never fails closed merely because its
/// configured request omitted an action class the mapping rules later emit.
///
/// Setting `[run.profiles.<name>.capability] requested_actions` in `firma.toml`
/// narrows this request further — an opt-in extra-restriction knob for running
/// with fewer permissions than the policy would otherwise allow.
pub(crate) const DEFAULT_REQUESTED_ACTIONS: &[ActionClass] = ActionClass::ALL;

/// Default resource scope.
pub(crate) const DEFAULT_RESOURCE_SCOPE: &str = "*";

/// Default capability TTL in seconds (15 minutes).
///
/// Chosen to be long enough to cover typical agent sessions while
/// short enough to limit token exposure if a seed file is leaked.
pub(crate) const DEFAULT_TTL_SECONDS: i32 = 900;

/// Upper bound on a single `IssueCapability` request once connected. Prevents a
/// stalled Authority from hanging the mint (and, for the background refresher,
/// from stalling sandbox teardown while its Drop joins the mint thread).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// `FirmaTeam` exports Ed25519 public keys in their raw 32-byte representation.
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Mint a capability and write the seed file. Returns the written path.
///
/// Runs the async RPC inside a scoped current-thread tokio runtime so the
/// synchronous `firma run` call path is unchanged.
///
/// # Errors
///
/// - [`RunError::AuthorityUnreachable`] on channel/transport/connect failure.
/// - [`RunError::AgentNotRegistered`] when the Authority does not recognize the UUID.
/// - [`RunError::AgentProfileMismatch`] when the registration rejects the local profile.
/// - [`RunError::CapabilityDenied`] for other Authority denials.
/// - [`RunError::CapabilityPendingApproval`] when issuance requires human approval.
/// - [`RunError::Capability`] on verification, encoding, or file-write failure.
pub fn mint_and_write(params: &IssueParams, out_path: &Path) -> Result<PathBuf, RunError> {
    let seed = mint(params)?;
    write_seed(&seed, out_path)?;
    Ok(out_path.to_path_buf())
}

/// Mint a capability seed and write it atomically, returning the verified
/// [`CapabilitySeed`] (so callers can read the fresh `expiry` for scheduling).
///
/// # Errors
///
/// Same failure modes as [`mint_and_write`].
pub(crate) fn mint_and_write_seed(
    params: &IssueParams,
    out_path: &Path,
) -> Result<CapabilitySeed, RunError> {
    let seed = mint(params)?;
    write_seed(&seed, out_path)?;
    Ok(seed)
}

fn mint(params: &IssueParams) -> Result<CapabilitySeed, RunError> {
    let pub_key = std::fs::read(&params.authority_pub_key_path).map_err(|e| {
        RunError::Capability(format!(
            "read authority public key '{}': {e}",
            params.authority_pub_key_path.display()
        ))
    })?;
    let public_key_length = pub_key.len();
    if public_key_length != ED25519_PUBLIC_KEY_LENGTH {
        let public_key_path = params.authority_pub_key_path.display();
        return Err(RunError::Capability(format!(
            "authority public key '{public_key_path}' must contain exactly \
             {ED25519_PUBLIC_KEY_LENGTH} raw Ed25519 bytes; found \
             {public_key_length} bytes"
        )));
    }
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
        let endpoint = AuthorityEndpoint::new(&params.authority_url, None).map_err(|e| {
            RunError::AuthorityUnreachable {
                url: params.authority_url.clone(),
                reason: e.to_string(),
            }
        })?;
        let channel = build_channel(
            &endpoint,
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
        // Bound the request so a connected-but-stalled Authority cannot hang the
        // caller indefinitely. This matters for the background refresher, whose
        // Drop must join the mint thread before the seed-file guard deletes the
        // file (see `capability::refresh`); an unbounded RPC would stall sandbox
        // teardown.
        let rpc = client.issue_capability(IssueCapabilityRequest {
            agent_id: params.agent_id.to_string(),
            session_id: params.session_id.clone(),
            requested_actions: params.requested_actions.clone(),
            resource_scope: params.resource_scope.clone(),
            requested_ttl_seconds: params.ttl_seconds,
            credentials: params
                .credentials
                .as_ref()
                .map(ResolvedSidecarCredentials::to_proto),
        });
        tokio::time::timeout(REQUEST_TIMEOUT, rpc)
            .await
            .map_err(|_elapsed| RunError::AuthorityUnreachable {
                url: params.authority_url.clone(),
                reason: format!(
                    "IssueCapability RPC timed out after {}s",
                    REQUEST_TIMEOUT.as_secs()
                ),
            })?
            .map(tonic::Response::into_inner)
            .map_err(|status| RunError::AuthorityUnreachable {
                url: params.authority_url.clone(),
                reason: format!("IssueCapability RPC failed: {status}"),
            })
    })?;

    capability_seed_from_response(response, params, &verifier)
}

fn capability_seed_from_response(
    response: IssueCapabilityResponse,
    params: &IssueParams,
    verifier: &PasetoV4Verifier,
) -> Result<CapabilitySeed, RunError> {
    let decision = IssueDecision::try_from(response.decision).map_err(|_| {
        RunError::Capability(format!(
            "authority returned unknown issuance decision {}",
            response.decision
        ))
    })?;

    match decision {
        IssueDecision::Allow if !response.granted => {
            return Err(RunError::Capability(
                "authority returned ALLOW with granted=false".to_string(),
            ));
        }
        IssueDecision::Allow => {}
        IssueDecision::Deny if response.granted => {
            return Err(RunError::Capability(
                "authority returned DENY with granted=true".to_string(),
            ));
        }
        IssueDecision::Deny => {
            return Err(match response.deny_reason.as_str() {
                "AGENT_NOT_REGISTERED" => RunError::AgentNotRegistered {
                    agent_id: params.agent_id.to_string(),
                    message: response.deny_message,
                },
                "AGENT_PROFILE_MISMATCH" => RunError::AgentProfileMismatch {
                    agent_id: params.agent_id.to_string(),
                    message: response.deny_message,
                },
                _ => RunError::CapabilityDenied {
                    agent_id: params.agent_id.to_string(),
                    reason: response.deny_reason,
                    message: response.deny_message,
                },
            });
        }
        IssueDecision::PendingApproval => {
            if response.granted {
                return Err(RunError::Capability(
                    "authority returned PENDING_APPROVAL with granted=true".to_string(),
                ));
            }
            let approval_id = response.approval_id.ok_or_else(|| {
                RunError::Capability(
                    "authority returned PENDING_APPROVAL without approval_id".to_string(),
                )
            })?;
            let approval_url = response.approval_url.ok_or_else(|| {
                RunError::Capability(
                    "authority returned PENDING_APPROVAL without approval_url".to_string(),
                )
            })?;
            if response.approval_expiry.is_none() {
                return Err(RunError::Capability(
                    "authority returned PENDING_APPROVAL without approval_expiry".to_string(),
                ));
            }
            return Err(RunError::CapabilityPendingApproval {
                agent_id: params.agent_id.to_string(),
                approval_id,
                approval_url,
            });
        }
        IssueDecision::Unspecified => {
            return Err(RunError::Capability(
                "authority returned unspecified issuance decision".to_string(),
            ));
        }
    }

    let token = response
        .token
        .ok_or_else(|| RunError::Capability("ALLOW response contained no token".to_string()))?;

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
mod tests {
    use super::*;
    use firma_core::{CapabilityClaims, TokenId};

    fn sample_seed() -> CapabilitySeed {
        let now = chrono::Utc::now();
        let claims = CapabilityClaims {
            token_id: TokenId::generate(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            session_id: "sess1".parse().unwrap(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::minutes(15),
            context_hash: "deadbeef".to_string(),
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
