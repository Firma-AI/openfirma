//! Pure capability-issuance helper shared by the gRPC service and the
//! `firma-authority issue` CLI subcommand.
//!
//! Encapsulates: Cedar policy evaluation, TTL clamping, context-hash
//! computation, claim assembly, and PASETO signing. Stays free of any
//! transport (`tonic`) or process-IO dependency so it is straightforward
//! to call from a CLI in-process and to unit-test.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use firma_core::token::paseto::PasetoV4Signer;
use firma_core::{AgentId, CapabilityClaims, SessionId, TokenId, TokenSigner as _};
use thiserror::Error;

use crate::cedar_loader::CedarPolicyStore;
use crate::service::{CedarDecision, clamp_ttl, compute_context_hash, evaluate_cedar_policy};

/// Inputs the issuer needs to evaluate and sign a token.
pub struct IssuanceRequest<'a> {
    pub agent_id: &'a AgentId,
    pub session_id: &'a SessionId,
    pub requested_actions: &'a [String],
    pub resource_scope: &'a str,
    /// Requested TTL in seconds. `0` (or negative) means "use the configured maximum".
    pub requested_ttl_seconds: i32,
}

/// Successful issuance output.
#[derive(Debug)]
pub struct IssuanceResult {
    pub raw_token: String,
    pub claims: CapabilityClaims,
}

/// Failure modes for the issuance pipeline.
#[derive(Debug, Error)]
pub enum IssuanceError {
    /// Cedar evaluation refused to issue. Carries the structured reason
    /// and message so the gRPC handler can populate the matching proto
    /// fields without losing information.
    #[error("cedar denied issuance ({reason}): {message}")]
    Denied { reason: String, message: String },
    /// PASETO signing failed.
    #[error("token signing failed: {0}")]
    Sign(String),
}

/// Evaluate the request against the loaded Cedar bundle and, on
/// allow, mint a signed PASETO v4 token.
///
/// # Errors
///
/// Returns [`IssuanceError::Denied`] when Cedar denies, or
/// [`IssuanceError::Sign`] when PASETO signing fails.
pub async fn issue_capability(
    policy_store: &Arc<CedarPolicyStore>,
    signer: &Arc<PasetoV4Signer>,
    max_ttl_seconds: i32,
    req: &IssuanceRequest<'_>,
) -> Result<IssuanceResult, IssuanceError> {
    let policy_set = policy_store.policy_set().await;
    let schema = policy_store.schema().await;
    let decision = evaluate_cedar_policy(
        &policy_set,
        &schema,
        req.agent_id,
        req.session_id,
        req.requested_actions,
        req.resource_scope,
    );

    match decision {
        CedarDecision::Allow => {}
        CedarDecision::Deny { reason, message } => {
            return Err(IssuanceError::Denied { reason, message });
        }
    }

    let ttl = clamp_ttl(req.requested_ttl_seconds, max_ttl_seconds);
    let now: DateTime<Utc> = Utc::now();
    let expiry = now + Duration::seconds(i64::from(ttl));
    let token_id = TokenId::new();
    let bundle_version = policy_store.bundle().version.clone();
    let context_hash = compute_context_hash(
        req.agent_id.as_ref(),
        req.requested_actions,
        req.resource_scope,
        &bundle_version,
    );

    let claims = CapabilityClaims {
        token_id,
        agent_id: req.agent_id.clone(),
        session_id: req.session_id.clone(),
        action_set: req.requested_actions.to_vec(),
        resource_scope: req.resource_scope.to_string(),
        issued_at: now,
        expiry,
        context_hash,
        budget_ceiling: None,
    };

    let raw_token = signer
        .sign(&claims)
        .map_err(|e| IssuanceError::Sign(format!("{e}")))?;

    Ok(IssuanceResult { raw_token, claims })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;

    fn fixture_policy_store() -> Arc<CedarPolicyStore> {
        let dir = tempfile::tempdir().unwrap().keep();
        std::fs::write(
            dir.join("default.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        let schema_src = include_str!("../schema.cedarschema");
        std::fs::write(dir.join("schema.cedarschema"), schema_src).unwrap();
        Arc::new(CedarPolicyStore::load(&dir, None, 30).unwrap())
    }

    #[tokio::test]
    async fn issues_token_when_cedar_allows() {
        let store = fixture_policy_store();
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let signer = Arc::new(PasetoV4Signer::try_new(kp.secret.as_bytes()).unwrap());
        let agent: AgentId = "agent_1".parse().unwrap();
        let session: SessionId = "sess_1".parse().unwrap();
        let actions = vec!["communication.external.send".to_string()];
        let req = IssuanceRequest {
            agent_id: &agent,
            session_id: &session,
            requested_actions: &actions,
            resource_scope: "wttr.in*",
            requested_ttl_seconds: 300,
        };
        let out = issue_capability(&store, &signer, 600, &req).await.unwrap();
        assert!(!out.raw_token.is_empty());
        assert_eq!(out.claims.action_set, actions);
        assert_eq!(out.claims.resource_scope, "wttr.in*");
    }

    #[tokio::test]
    async fn returns_denied_when_cedar_denies() {
        // No policies loaded → Cedar denies with NO_POLICIES.
        let dir = tempfile::tempdir().unwrap().keep();
        // Empty policy file (no `permit`).
        std::fs::write(dir.join("default.cedar"), "").unwrap();
        let schema_src = include_str!("../schema.cedarschema");
        std::fs::write(dir.join("schema.cedarschema"), schema_src).unwrap();
        let store = Arc::new(CedarPolicyStore::load(&dir, None, 30).unwrap());

        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let signer = Arc::new(PasetoV4Signer::try_new(kp.secret.as_bytes()).unwrap());
        let agent: AgentId = "agent_1".parse().unwrap();
        let session: SessionId = "sess_1".parse().unwrap();
        let actions = vec!["communication.external.send".to_string()];
        let req = IssuanceRequest {
            agent_id: &agent,
            session_id: &session,
            requested_actions: &actions,
            resource_scope: "wttr.in*",
            requested_ttl_seconds: 300,
        };
        let err = issue_capability(&store, &signer, 600, &req)
            .await
            .unwrap_err();
        match err {
            IssuanceError::Denied { reason, .. } => {
                assert_eq!(reason, "NO_POLICIES");
            }
            IssuanceError::Sign(e) => panic!("expected Denied, got Sign({e})"),
        }
    }
}
