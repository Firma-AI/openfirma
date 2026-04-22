use std::pin::Pin;
use std::sync::Arc;

use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema};
use chrono::{Duration, Utc};
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

        // Build Cedar evaluation context
        let policy_set = self.policy_store.policy_set().await;
        let schema = self.policy_store.schema().await;
        let decision = evaluate_cedar_policy(
            &policy_set,
            schema.as_deref(),
            &req.agent_id,
            &req.session_id,
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
                    &req.agent_id,
                    &req.requested_actions,
                    &req.resource_scope,
                    &bundle_version,
                );

                let agent_id = req
                    .agent_id
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {e}")))?;
                let session_id = req
                    .session_id
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid session_id: {e}")))?;

                let claims = CapabilityClaims {
                    token_id,
                    agent_id,
                    session_id,
                    action_set: req.requested_actions.clone(),
                    resource_scope: req.resource_scope.clone(),
                    issued_at: now,
                    expiry: expires_at,
                    context_hash: context_hash.clone(),
                    budget_ceiling: None,
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
                    budget_ceiling: None,
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
/// specific intent exists yet at issuance. The runtime-signal fields
/// (`budget_remaining`, `session_duration_s`, `action_count`) are populated
/// with schema-compatible placeholders (`i64::MAX`, `0`, `0`) — the Authority
/// has no session history at pre-flight, but all 7 fields are required by
/// the canonical `EnforcementContext` schema.
fn evaluate_cedar_policy(
    policy_set: &PolicySet,
    schema: Option<&Schema>,
    agent_id: &str,
    session_id: &str,
    actions: &[String],
    resource: &str,
) -> CedarDecision {
    if policy_set.policies().next().is_none() {
        return CedarDecision::Deny {
            reason: "NO_POLICIES".to_string(),
            message: "no Cedar policies loaded".to_string(),
        };
    }

    if actions.is_empty() {
        return CedarDecision::Deny {
            reason: "NO_ACTIONS".to_string(),
            message: "no actions requested".to_string(),
        };
    }

    let authorizer = Authorizer::new();
    let timestamp_ms = Utc::now().timestamp_millis();

    for action in actions {
        let action_uid = parse_action_uid(action);
        let context_json = json!({
            "session_id": session_id,
            "timestamp_ms": timestamp_ms,
            "params": "{}",
            "risk_score": 0i64,
            "budget_remaining": i64::MAX,
            "session_duration_s": 0i64,
            "action_count": 0i64,
        });
        let schema_with_action = schema.map(|s| (s, &action_uid));
        let cedar_context = match Context::from_json_value(context_json, schema_with_action) {
            Ok(c) => c,
            Err(e) => {
                return CedarDecision::Deny {
                    reason: "CONTEXT_BUILD_FAILED".to_string(),
                    message: format!("failed to build Cedar context for '{action}': {e}"),
                };
            }
        };

        let request = match Request::new(
            Some(parse_entity_uid(agent_id)),
            Some(action_uid),
            Some(parse_resource_uid(resource)),
            cedar_context,
            schema,
        ) {
            Ok(r) => r,
            Err(e) => {
                return CedarDecision::Deny {
                    reason: "CONTEXT_BUILD_FAILED".to_string(),
                    message: format!("failed to build Cedar request for '{action}': {e}"),
                };
            }
        };

        let response = authorizer.is_authorized(&request, policy_set, &Entities::empty());

        if let cedar_policy::Decision::Deny = response.decision() {
            let diagnostics = response.diagnostics();
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

            return CedarDecision::Deny {
                reason: "POLICY_DENIED".to_string(),
                message,
            };
        }
    }

    CedarDecision::Allow
}

/// Parse an agent ID into a Cedar `EntityUid`.
/// Uses the namespace `Firma::Agent`.
fn parse_entity_uid(agent_id: &str) -> EntityUid {
    let uid_str = format!("Firma::Agent::\"{agent_id}\"");
    uid_str
        .parse::<EntityUid>()
        .or_else(|_| "Firma::Agent::\"unknown\"".parse::<EntityUid>())
        .unwrap_or_else(|e| unknown_entity_uid("Agent", &e))
}

/// Parse an action class string into a Cedar `EntityUid`.
/// Uses the namespace `Firma::Action`.
fn parse_action_uid(action: &str) -> EntityUid {
    let uid_str = format!("Firma::Action::\"{action}\"");
    uid_str
        .parse::<EntityUid>()
        .or_else(|_| "Firma::Action::\"unknown\"".parse::<EntityUid>())
        .unwrap_or_else(|e| unknown_entity_uid("Action", &e))
}

/// Parse a resource scope into a Cedar `EntityUid`.
/// Uses the namespace `Firma::Resource`.
fn parse_resource_uid(resource: &str) -> EntityUid {
    let uid_str = format!("Firma::Resource::\"{resource}\"");
    uid_str
        .parse::<EntityUid>()
        .or_else(|_| "Firma::Resource::\"unknown\"".parse::<EntityUid>())
        .unwrap_or_else(|e| unknown_entity_uid("Resource", &e))
}

/// Fallback: construct a minimal unknown entity UID.
/// This should never be reached since the hardcoded fallback parses always succeed.
fn unknown_entity_uid(kind: &str, err: &cedar_policy::ParseErrors) -> EntityUid {
    tracing::error!(kind, %err, "failed to parse fallback entity UID");
    // Return a best-effort UID — parse_entity_uid("unknown") with a type that always works
    format!("Firma::{kind}::\"unknown\"")
        .parse::<EntityUid>()
        .unwrap_or_else(|_| {
            // Absolute last resort — this is unreachable in practice
            tracing::error!("critical: cannot parse any entity UID");
            std::process::exit(1);
        })
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
            "agent_1",
            "sess_1",
            &["filesystem.read".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_no_actions_denies() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            None,
            "agent_1",
            "sess_1",
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
            "agent_1",
            "sess_1",
            &["filesystem.read".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow));
    }

    #[test]
    fn test_evaluate_forbid_all_denies() {
        let result = evaluate_cedar_policy(
            &forbid_all(),
            None,
            "agent_1",
            "sess_1",
            &["filesystem.read".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_multi_action_all_allowed() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            None,
            "agent_1",
            "sess_1",
            &[
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
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
            "agent_1",
            "sess_1",
            &[
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
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
            "agent_1",
            "sess_1",
            &["communication.external.send".to_string()],
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
            "agent_1",
            "sess_1",
            &["unknown.action".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_with_schema_all_15_actions_allowed() {
        let schema = firma_schema();
        let actions: Vec<String> = [
            "account.permission.change",
            "browser.purchase",
            "communication.external.send",
            "communication.internal.send",
            "credential.read",
            "credential.write",
            "filesystem.delete",
            "filesystem.read",
            "filesystem.write",
            "memory.cross_namespace.read",
            "memory.cross_namespace.write",
            "payment.purchase",
            "payment.transfer",
            "system.execute",
            "system.install",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let result = evaluate_cedar_policy(
            &permit_all(),
            Some(&schema),
            "agent_1",
            "sess_1",
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
            &[
                "filesystem.read".to_string(),
                "communication.external.send".to_string(),
            ],
            "api.example.com",
            "bundle_v1",
        );
        let h2 = compute_context_hash(
            "agent_1",
            &[
                "filesystem.read".to_string(),
                "communication.external.send".to_string(),
            ],
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
            &[
                "filesystem.read".to_string(),
                "communication.external.send".to_string(),
            ],
            "api.example.com",
            "v1",
        );
        let h2 = compute_context_hash(
            "agent_1",
            &[
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
            "api.example.com",
            "v1",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn context_hash_changes_with_agent() {
        let h1 = compute_context_hash(
            "agent_a",
            &["filesystem.read".to_string()],
            "resource",
            "bundle_v1",
        );
        let h2 = compute_context_hash(
            "agent_b",
            &["filesystem.read".to_string()],
            "resource",
            "bundle_v1",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn context_hash_changes_with_bundle_version() {
        let h1 = compute_context_hash(
            "agent_1",
            &["filesystem.read".to_string()],
            "resource",
            "bundle_v1",
        );
        let h2 = compute_context_hash(
            "agent_1",
            &["filesystem.read".to_string()],
            "resource",
            "bundle_v2",
        );
        assert_ne!(h1, h2);
    }
}
