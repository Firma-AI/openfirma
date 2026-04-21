use std::pin::Pin;
use std::sync::Arc;

use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request, Schema};
use chrono::{Duration, Utc};
use firma_core::agent::AgentId;
use firma_core::session::SessionId;
use firma_core::FirmaEntityUid;
use firma_core::policy::PolicyBundle;
use firma_core::token::paseto::PasetoV4Signer;
use firma_core::token::{CapabilityClaims, TokenId, TokenSigner};
use firma_proto::RevocationEvent;
use firma_proto::firma::v1::authority_service_server::AuthorityService;
use firma_proto::firma::v1::{
    CapabilityToken, IssueCapabilityRequest, IssueCapabilityResponse, PolicyBundleUpdate,
    TokenFormat, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request as TonicRequest, Response, Status};

use crate::cedar_loader::{CedarPolicyStore, CedarPolicyStoreWatcher};
use crate::revocation::{RevocationStore, RevocationStoreWatcher};

/// gRPC implementation of the `AuthorityService` defined in `authority.proto`.
pub struct AuthorityServiceImpl {
    policy_store: Arc<CedarPolicyStore>,
    policy_watcher: Arc<CedarPolicyStoreWatcher>,
    revocation_store: Arc<RevocationStore>,
    revocation_watcher: Arc<RevocationStoreWatcher>,
    signer: Arc<PasetoV4Signer>,
    max_ttl_seconds: i32,
}

impl AuthorityServiceImpl {
    #[must_use]
    pub fn new(
        policy_store: Arc<CedarPolicyStore>,
        policy_watcher: Arc<CedarPolicyStoreWatcher>,
        revocation_store: Arc<RevocationStore>,
        revocation_watcher: Arc<RevocationStoreWatcher>,
        signer: Arc<PasetoV4Signer>,
        max_ttl_seconds: i32,
    ) -> Self {
        Self {
            policy_store,
            policy_watcher,
            revocation_store,
            revocation_watcher,
            signer,
            max_ttl_seconds,
        }
    }
}

#[tonic::async_trait]
impl AuthorityService for AuthorityServiceImpl {
    /// FR-3: Evaluate Cedar policies and issue a signed capability token.
    async fn issue_capability(
        &self,
        request: TonicRequest<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            agent_id = %req.agent_id,
            session_id = %req.session_id,
            actions = ?req.requested_actions,
            resource = %req.resource_scope,
            "capability issuance requested"
        );

        let agent_id: AgentId = req
            .agent_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {e}")))?;
        let session_id: SessionId = req
            .session_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid session_id: {e}")))?;

        // Build Cedar evaluation context
        let policy_set = self.policy_store.policy_set().await;
        let schema = self.policy_store.schema().await;
        let decision = evaluate_cedar_policy(
            &policy_set,
            schema.as_deref(),
            &agent_id,
            &session_id,
            &req.requested_actions,
            &req.resource_scope,
        );

        match decision {
            CedarDecision::Allow => {
                // FR-4: Clamp TTL
                let ttl = clamp_ttl(req.requested_ttl_seconds, self.max_ttl_seconds);
                let now = Utc::now();
                let expires_at = now + Duration::seconds(i64::from(ttl));
                let token_id = TokenId::new();

                // Build context hash: SHA-256 of (agent_id | sorted_actions | resource | bundle_version).
                // This binds the token to both the identity being granted and the policy state at issuance.
                let bundle_version = self.policy_store.bundle().version.clone();
                let context_hash = compute_context_hash(
                    agent_id.as_ref(),
                    &req.requested_actions,
                    &req.resource_scope,
                    &bundle_version,
                );

                let claims = CapabilityClaims {
                    token_id,
                    agent_id: agent_id.clone(),
                    session_id: session_id.clone(),
                    action_set: req.requested_actions.clone(),
                    resource_scope: req.resource_scope.clone(),
                    issued_at: now,
                    expiry: expires_at,
                    context_hash: context_hash.clone(),
                };

                // Sign the token
                let signed_token = self.signer.sign(&claims).map_err(|e| {
                    tracing::error!(error = %e, "token signing failed");
                    Status::internal("token signing failed")
                })?;

                let issued_at_ts = to_proto_timestamp(now);
                let expiry_ts = to_proto_timestamp(expires_at);

                let token = CapabilityToken {
                    token_id: token_id.to_string(),
                    agent_id: req.agent_id.clone(),
                    session_id: req.session_id.clone(),
                    action_set: req.requested_actions,
                    resource_scope: req.resource_scope,
                    issued_at: Some(issued_at_ts),
                    expiry: Some(expiry_ts),
                    context_hash,
                    signature: signed_token.into_bytes(),
                    format: TokenFormat::PasetoV4.into(),
                };

                tracing::info!(
                    agent_id = %token.agent_id,
                    token_id = %token.token_id,
                    ttl = ttl,
                    "capability granted"
                );

                Ok(Response::new(IssueCapabilityResponse {
                    granted: true,
                    token: Some(token),
                    deny_reason: String::new(),
                    deny_message: String::new(),
                }))
            }
            CedarDecision::Deny { reason, message } => {
                tracing::info!(
                    agent_id = %req.agent_id,
                    deny_reason = %reason,
                    "capability denied"
                );

                Ok(Response::new(IssueCapabilityResponse {
                    granted: false,
                    token: None,
                    deny_reason: reason,
                    deny_message: message,
                }))
            }
        }
    }

    type WatchPolicyBundleStream =
        Pin<Box<dyn Stream<Item = Result<PolicyBundleUpdate, Status>> + Send>>;

    /// FR-5: Stream policy bundles to connected sidecars.
    async fn watch_policy_bundle(
        &self,
        request: TonicRequest<WatchPolicyBundleRequest>,
    ) -> Result<Response<Self::WatchPolicyBundleStream>, Status> {
        let req = request.into_inner();
        let current_version = req.current_version;

        tracing::info!(
            client_version = %current_version,
            "sidecar connected to policy bundle stream"
        );

        let mut rx = self.policy_watcher.subscribe();

        let stream = async_stream::try_stream! {
            // Send current bundle immediately (unless client already has it)
            let initial = rx.borrow_and_update().clone();
            if current_version.is_empty() || current_version != initial.version {
                yield bundle_to_update(&initial);
            }

            // Stream updates as they arrive
            while rx.changed().await.is_ok() {
                let bundle = rx.borrow_and_update().clone();
                yield bundle_to_update(&bundle);
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type WatchRevocationsStream =
        Pin<Box<dyn Stream<Item = Result<RevocationEvent, Status>> + Send>>;

    /// FR-6: Stream revocation events to connected sidecars.
    async fn watch_revocations(
        &self,
        request: TonicRequest<WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let req = request.into_inner();

        let since = match req.since {
            Some(ts) => {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos.try_into().unwrap_or(0))
                    .unwrap_or_else(Utc::now)
            }
            None => Utc::now() - Duration::days(365),
        };

        tracing::info!(?since, "sidecar connected to revocation stream");

        // Replay events after `since` timestamp
        let replay_events = self.revocation_store.events_since(since).await;
        let broadcast_rx = self.revocation_watcher.subscribe();

        let stream = async_stream::try_stream! {
            // First, replay historical events
            for entry in replay_events {
                yield entry_to_proto(&entry);
            }

            // Then stream new events as they arrive
            let mut broadcast_stream = BroadcastStream::new(broadcast_rx);
            while let Some(result) = broadcast_stream.next().await {
                match result {
                    Ok(entry) => yield entry_to_proto(&entry),
                    Err(BroadcastStreamRecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "sidecar missed revocation events due to slow consumption");
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

// --- Cedar evaluation helpers ---

enum CedarDecision {
    Allow,
    Deny { reason: String, message: String },
}

impl CedarDecision {
    fn no_policies() -> Self {
        Self::Deny {
            reason: "NO_POLICIES".to_string(),
            message: "no Cedar policies loaded".to_string(),
        }
    }
    fn no_action() -> Self {
        Self::Deny {
            reason: "NO_ACTIONS".to_string(),
            message: "no actions requested".to_string(),
        }
    }

    fn invalid_request(msg: impl Into<String>) -> Self {
        Self::Deny {
            reason: "INVALID_REQUEST".to_string(),
            message: msg.into(),
        }
    }

    fn context_build(action: &str, reason: &str) -> Self {
        Self::Deny {
            reason: "CONTEXT_BUILD_FAILED".to_string(),
            message: format!("failed to build Cedar context for '{action}': {reason}"),
        }
    }

    fn policy_deny(action: &str, diagnostics: &cedar_policy::Diagnostics) -> Self {
        let reasons: Vec<String> = diagnostics
            .reason()
            .map(std::string::ToString::to_string)
            .collect();
        let errors: Vec<String> = diagnostics
            .errors()
            .map(std::string::ToString::to_string)
            .collect();

        let message = if !errors.is_empty() {
            format!("policy errors for '{action}': {}", errors.join("; "))
        } else if !reasons.is_empty() {
            format!("denied '{action}' by policies: {}", reasons.join(", "))
        } else {
            format!("denied '{action}' by default (no matching permit policy)")
        };

        Self::Deny {
            reason: "POLICY_DENIED".to_string(),
            message,
        }
    }
}

/// Evaluate Cedar policies for a capability issuance request.
///
/// Uses Cedar's unspecified principal/action/resource when the schema is
/// not loaded, falling back to a simple "any policy allows" evaluation.
/// Evaluate Cedar policies for a capability issuance request.
///
/// Evaluates every requested action independently — all must be allowed for
/// the request to succeed (fail-closed across the full action set).
///
/// Context at issuance time carries `session_id`, `timestamp_ms`, and
/// `risk_score` (V1 placeholder = 0). `params` is empty (`"{}"`) because no
/// specific intent exists yet at issuance.
fn evaluate_cedar_policy(
    policy_set: &PolicySet,
    schema: Option<&Schema>,
    agent_id: &AgentId,
    session_id: &SessionId,
    actions: &[String],
    resource: &str,
) -> CedarDecision {
    if policy_set.policies().next().is_none() {
        return CedarDecision::no_policies();
    }

    if actions.is_empty() {
        return CedarDecision::no_action();
    }

    let principal: cedar_policy::EntityUid =
        match FirmaEntityUid::Agent(agent_id.clone()).try_into() {
            Ok(uid) => uid,
            Err(e) => {
                return CedarDecision::invalid_request(format!("invalid agent_id: {e}"));
            }
        };
    let resource_entity: cedar_policy::EntityUid =
        match FirmaEntityUid::Resource(resource.to_string()).try_into() {
            Ok(uid) => uid,
            Err(e) => {
                return CedarDecision::invalid_request(format!("invalid resource: {e}"));
            }
        };
    let authorizer = Authorizer::new();
    let timestamp_ms = Utc::now().timestamp_millis();

    for action in actions {
        let action_entity: cedar_policy::EntityUid =
            match FirmaEntityUid::Action(action.clone()).try_into() {
                Ok(uid) => uid,
                Err(e) => {
                    return CedarDecision::invalid_request(format!("invalid action: {e}"));
                }
            };
        let context_json = json!({
            "session_id": session_id,
            "timestamp_ms": timestamp_ms,
            "params": "{}",
            "risk_score": 0i64,
        });
        let schema_with_action = schema.map(|s| (s, &action_entity));
        let cedar_context = match Context::from_json_value(context_json, schema_with_action) {
            Ok(c) => c,
            Err(err) => {
                return CedarDecision::context_build(action, &err.to_string());
            }
        };

        let request = match Request::new(
            Some(principal.clone()),
            Some(action_entity),
            Some(resource_entity.clone()),
            cedar_context,
            schema,
        ) {
            Ok(r) => r,
            Err(e) => {
                return CedarDecision::invalid_request(e.to_string());
            }
        };

        let response = authorizer.is_authorized(&request, policy_set, &Entities::empty());

        if response.decision() == cedar_policy::Decision::Deny {
            return CedarDecision::policy_deny(action, response.diagnostics());
        }
    }

    CedarDecision::Allow
}

// --- Proto conversion helpers ---

fn to_proto_timestamp(dt: chrono::DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos().try_into().unwrap_or(0),
    }
}

fn bundle_to_update(bundle: &PolicyBundle) -> PolicyBundleUpdate {
    PolicyBundleUpdate {
        bundle: Some(firma_proto::PolicyBundle {
            version: bundle.version.clone(),
            policies: bundle.policies.clone(),
            entity_schema: bundle.entity_schema.clone(),
            ttl_seconds: bundle.ttl_seconds,
        }),
        updated_at: Some(to_proto_timestamp(Utc::now())),
    }
}

fn entry_to_proto(entry: &crate::revocation::RevocationEntry) -> RevocationEvent {
    RevocationEvent {
        token_id: entry.token_id.to_string(),
        reason: entry.reason.clone(),
        timestamp: Some(to_proto_timestamp(entry.timestamp)),
    }
}

/// Compute the context hash for a capability token.
///
/// SHA-256 of `agent_id | sorted_actions | resource | bundle_version`.
/// Binds the issued token to both the principal's identity and the policy
/// state that governed the evaluation.
fn compute_context_hash(
    agent_id: &str,
    actions: &[String],
    resource: &str,
    bundle_version: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(b"|");
    // Sort actions for a deterministic hash regardless of request order.
    let mut sorted = actions.to_vec();
    sorted.sort_unstable();
    for action in &sorted {
        hasher.update(action.as_bytes());
        hasher.update(b",");
    }
    hasher.update(b"|");
    hasher.update(resource.as_bytes());
    hasher.update(b"|");
    hasher.update(bundle_version.as_bytes());
    hex::encode(hasher.finalize())
}

/// FR-4: Clamp requested TTL to the configured maximum.
fn clamp_ttl(requested: i32, max: i32) -> i32 {
    if requested <= 0 {
        max
    } else {
        requested.min(max)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn agent(id: &str) -> AgentId {
        id.parse().unwrap()
    }

    fn session(id: &str) -> SessionId {
        id.parse().unwrap()
    }

    #[test]
    fn test_clamp_ttl_within_max() {
        assert_eq!(clamp_ttl(600, 3600), 600);
    }

    #[test]
    fn test_clamp_ttl_exceeds_max() {
        assert_eq!(clamp_ttl(7200, 3600), 3600);
    }

    #[test]
    fn test_clamp_ttl_zero_uses_max() {
        assert_eq!(clamp_ttl(0, 3600), 3600);
    }

    #[test]
    fn test_clamp_ttl_negative_uses_max() {
        assert_eq!(clamp_ttl(-1, 3600), 3600);
    }

    fn permit_all() -> PolicySet {
        "permit(principal, action, resource);"
            .parse()
            .unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn forbid_all() -> PolicySet {
        "forbid(principal, action, resource);"
            .parse()
            .unwrap_or_else(|e| panic!("{e:?}"))
    }

    const FIRMA_SCHEMA: &str = include_str!("../../firma-authority/policies/schema.cedarschema");

    fn firma_schema() -> Schema {
        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA)
            .unwrap_or_else(|e| panic!("schema parse failed: {e}"));
        schema
    }

    #[test]
    fn test_evaluate_no_policies_denies() {
        let result = evaluate_cedar_policy(
            &PolicySet::new(),
            None,
            &agent("agent_1"),
            &session("sess_1"),
            &["http.get".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_no_actions_denies() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            None,
            &agent("agent_1"),
            &session("sess_1"),
            &[],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { reason, .. } if reason == "NO_ACTIONS"));
    }

    #[test]
    fn test_evaluate_permit_all_allows() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            None,
            &agent("agent_1"),
            &session("sess_1"),
            &["http.get".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow));
    }

    #[test]
    fn test_evaluate_forbid_all_denies() {
        let result = evaluate_cedar_policy(
            &forbid_all(),
            None,
            &agent("agent_1"),
            &session("sess_1"),
            &["http.get".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_multi_action_all_allowed() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            None,
            &agent("agent_1"),
            &session("sess_1"),
            &["llm.inference".to_string(), "http.get".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow));
    }

    #[test]
    fn test_evaluate_multi_action_one_denied() {
        // forbid-all → every action in the set is denied; first one short-circuits
        let result = evaluate_cedar_policy(
            &forbid_all(),
            None,
            &agent("agent_1"),
            &session("sess_1"),
            &["llm.inference".to_string(), "http.get".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_with_schema_valid_action() {
        let schema = firma_schema();
        let result = evaluate_cedar_policy(
            &permit_all(),
            Some(&schema),
            &agent("agent_1"),
            &session("sess_1"),
            &["llm.inference".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow));
    }

    #[test]
    fn test_evaluate_with_schema_unknown_action_denies() {
        // "unknown.action" not declared in schema → Cedar rejects the request
        let schema = firma_schema();
        let result = evaluate_cedar_policy(
            &permit_all(),
            Some(&schema),
            &agent("agent_1"),
            &session("sess_1"),
            &["unknown.action".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_with_schema_all_15_actions_allowed() {
        let schema = firma_schema();
        let actions: Vec<String> = [
            "http.get",
            "http.post",
            "http.put",
            "http.delete",
            "http.patch",
            "network.connect",
            "db.query",
            "db.mutate",
            "file.read",
            "file.write",
            "file.delete",
            "code.execute",
            "system.execute",
            "messaging.send",
            "llm.inference",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let result = evaluate_cedar_policy(
            &permit_all(),
            Some(&schema),
            &agent("agent_1"),
            &session("sess_1"),
            &actions,
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow));
    }

    #[test]
    fn test_to_proto_timestamp_roundtrip() {
        let now = Utc::now();
        let ts = to_proto_timestamp(now);
        assert_eq!(ts.seconds, now.timestamp());
    }

    #[test]
    fn context_hash_deterministic() {
        let h1 = compute_context_hash(
            "agent_1",
            &["http.get".to_string(), "llm.inference".to_string()],
            "api.example.com",
            "bundle_v1",
        );
        let h2 = compute_context_hash(
            "agent_1",
            &["http.get".to_string(), "llm.inference".to_string()],
            "api.example.com",
            "bundle_v1",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn context_hash_action_order_independent() {
        // Actions sorted before hashing — different order must produce same hash.
        let h1 = compute_context_hash(
            "agent_1",
            &["http.get".to_string(), "llm.inference".to_string()],
            "api.example.com",
            "v1",
        );
        let h2 = compute_context_hash(
            "agent_1",
            &["llm.inference".to_string(), "http.get".to_string()],
            "api.example.com",
            "v1",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn context_hash_changes_with_agent() {
        let h1 = compute_context_hash(
            "agent_a",
            &["http.get".to_string()],
            "resource",
            "bundle_v1",
        );
        let h2 = compute_context_hash(
            "agent_b",
            &["http.get".to_string()],
            "resource",
            "bundle_v1",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn context_hash_changes_with_bundle_version() {
        let h1 = compute_context_hash(
            "agent_1",
            &["http.get".to_string()],
            "resource",
            "bundle_v1",
        );
        let h2 = compute_context_hash(
            "agent_1",
            &["http.get".to_string()],
            "resource",
            "bundle_v2",
        );
        assert_ne!(h1, h2);
    }
}
