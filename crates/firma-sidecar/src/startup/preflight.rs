//! Pre-flight capability token provisioning.
//!
//! Contacts the Authority via `IssueCapability` before the enforcement
//! pipeline starts accepting requests, and returns a live `CapabilityMap`
//! paired with a `PasetoV4Verifier`.  When `[preflight]` is absent from
//! the sidecar config the sidecar falls back to the stub verifier (always
//! deny) and an empty map — useful for unit-testing but not for demos.

use std::path::Path;

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

/// Resolve the authority public-key path used for pre-flight verification.
///
/// Prefers the explicit `[sidecar.preflight].authority_pub_key_path`; when it
/// is absent, falls back to `fallback` — the `[sidecar.authority].public_key_path`.
/// `firma config` does not scaffold the preflight key path (it is normally
/// injected at runtime by `firma run`), so standalone `firma sidecar --config`
/// reuses the authority key instead of failing.
///
/// # Errors
///
/// Returns an error when neither source provides a path.
fn resolve_authority_pub_key_path<'a>(
    config: &'a PreflightConfig,
    fallback: Option<&'a Path>,
) -> Result<&'a Path> {
    config
        .authority_pub_key_path
        .as_deref()
        .or(fallback)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "preflight.authority_pub_key_path is not configured and no \
                 [sidecar.authority].public_key_path fallback is available"
            )
        })
}

/// Call `IssueCapability` on the Authority and return a populated
/// `CapabilityMap` and matching `PasetoV4Verifier`.
///
/// `authority_pub_key_fallback` supplies the `[sidecar.authority].public_key_path`
/// used when `[sidecar.preflight].authority_pub_key_path` is unset.
///
/// # Errors
///
/// Returns an error if no authority public key path can be resolved, the public
/// key file cannot be read, the gRPC call fails, the Authority denies the
/// capability request, or the issued token cannot be verified with the key.
pub async fn run_preflight(
    config: &PreflightConfig,
    authority_url: &str,
    authority_pub_key_fallback: Option<&Path>,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<PreflightResult> {
    // Load authority public key (32-byte Ed25519 public key).
    let key_path = resolve_authority_pub_key_path(config, authority_pub_key_fallback)?;
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
        client_cert_pem,
        client_key_pem,
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test code: unwrap is an acceptable failure"
)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::resolve_authority_pub_key_path;
    use crate::config::PreflightConfig;

    fn preflight_config(authority_pub_key_path: Option<PathBuf>) -> PreflightConfig {
        PreflightConfig {
            agent_id: "test-agent".to_string(),
            session_id: "preflight-session".to_string(),
            requested_actions: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            authority_pub_key_path,
            ttl_seconds: 900,
        }
    }

    #[test]
    fn prefers_explicit_preflight_path_over_fallback() {
        let config = preflight_config(Some(PathBuf::from("/preflight/key.pub")));
        let resolved =
            resolve_authority_pub_key_path(&config, Some(Path::new("/authority/key.pub"))).unwrap();
        assert_eq!(resolved, Path::new("/preflight/key.pub"));
    }

    #[test]
    fn falls_back_to_authority_public_key_when_preflight_path_absent() {
        // `firma config` omits preflight.authority_pub_key_path;
        // standalone sidecar must reuse [sidecar.authority].public_key_path.
        let config = preflight_config(None);
        let resolved =
            resolve_authority_pub_key_path(&config, Some(Path::new("/authority/key.pub"))).unwrap();
        assert_eq!(resolved, Path::new("/authority/key.pub"));
    }

    #[test]
    fn errors_when_neither_preflight_nor_authority_key_present() {
        let config = preflight_config(None);
        let err = resolve_authority_pub_key_path(&config, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("authority_pub_key_path") && msg.contains("public_key_path"),
            "error should name both sources: {msg}"
        );
    }
}
