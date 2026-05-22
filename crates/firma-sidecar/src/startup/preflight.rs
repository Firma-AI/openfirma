//! Pre-flight capability token provisioning.
//!
//! Contacts the Authority via `IssueCapability` before the enforcement
//! pipeline starts accepting requests, and returns a live `CapabilityMap`
//! paired with a `PasetoV4Verifier`.  When `[preflight]` is absent from
//! the sidecar config the sidecar falls back to the stub verifier (always
//! deny) and an empty map — useful for unit-testing but not for demos.

use anyhow::{Context, Result};
use firma_core::TokenVerifier;
use firma_core::token::paseto::PasetoV4Verifier;
use firma_proto::authority_service_client::AuthorityServiceClient;
use firma_proto::firma::v1::IssueCapabilityRequest;

use crate::authority_client::channel::build_channel;
use crate::config::PreflightConfig;
use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};

/// Output of a successful pre-flight.
pub struct PreflightResult {
    /// Populated capability map with the issued token.
    pub capability_map: CapabilityMap,
    /// Real PASETO v4 verifier constructed from the authority public key.
    pub token_verifier: Box<dyn TokenVerifier + Send + Sync>,
}

/// Call `IssueCapability` on the Authority and return a populated
/// `CapabilityMap` and matching `PasetoV4Verifier`.
///
/// # Errors
///
/// Returns an error if the public key file cannot be read, the gRPC call
/// fails, the Authority denies the capability request, or the issued token
/// cannot be verified with the provided key.
pub async fn run_preflight(
    config: &PreflightConfig,
    authority_url: &str,
    ca_cert_pem: Option<&[u8]>,
) -> Result<PreflightResult> {
    // Load authority public key (32-byte Ed25519 public key).
    let key_path = config
        .authority_pub_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("preflight.authority_pub_key_path is not configured"))?;
    let pub_key_bytes = std::fs::read(key_path).with_context(|| {
        format!(
            "failed to read authority public key from '{}'",
            key_path.display()
        )
    })?;

    let verifier =
        PasetoV4Verifier::try_new(&pub_key_bytes).context("invalid authority public key")?;

    // Connect to authority gRPC endpoint.
    let channel = build_channel(
        authority_url,
        std::time::Duration::from_secs(10),
        ca_cert_pem,
    )
    .context("failed to build authority gRPC channel")?;
    let mut client = AuthorityServiceClient::new(channel);

    tracing::info!(
        agent_id = %config.agent_id,
        actions = ?config.requested_actions,
        "requesting capability token from Authority"
    );

    // Call IssueCapability.
    let response = client
        .issue_capability(IssueCapabilityRequest {
            agent_id: config.agent_id.clone(),
            session_id: config.session_id.clone(),
            requested_actions: config.requested_actions.clone(),
            resource_scope: config.resource_scope.clone(),
            requested_ttl_seconds: config.ttl_seconds,
        })
        .await
        .context("IssueCapability RPC failed")?
        .into_inner();

    if !response.granted {
        anyhow::bail!(
            "Authority denied capability for agent '{}': {} — {}",
            config.agent_id,
            response.deny_reason,
            response.deny_message
        );
    }

    let token = response
        .token
        .context("Authority returned granted=true but no token")?;

    // The `signature` field carries the raw PASETO token string as UTF-8 bytes.
    let raw_token =
        String::from_utf8(token.signature).context("capability token is not valid UTF-8")?;

    // Verify the token locally to confirm key/token consistency.
    let claims = verifier
        .verify(&raw_token)
        .context("issued token failed local verification")?;

    tracing::info!(
        agent_id = %claims.agent_id,
        token_id = %claims.token_id,
        actions = ?claims.action_set,
        "capability token issued and verified"
    );

    let entry = CapabilityEntry { raw_token, claims };
    let capability_map = CapabilityMap::new(vec![entry]);

    Ok(PreflightResult {
        capability_map,
        token_verifier: Box::new(verifier),
    })
}
