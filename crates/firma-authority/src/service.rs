use std::pin::Pin;
use std::sync::Arc;

use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request};
use chrono::{Duration, Utc};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request as TonicRequest, Response, Status};
use uuid::Uuid;

use firma_core::{CapabilityClaims, PasetoV4Signer, PolicyBundle, TokenSigner};
use firma_proto::firma::v1::authority_service_server::AuthorityService;
use firma_proto::firma::v1::{
    CapabilityToken, IssueCapabilityRequest, IssueCapabilityResponse, PolicyBundleUpdate,
    TokenFormat, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use firma_proto::RevocationEvent;

use crate::cedar_loader::CedarPolicyStore;
use crate::revocation::RevocationStore;

/// gRPC implementation of the `AuthorityService` defined in `authority.proto`.
pub struct AuthorityServiceImpl {
    policy_store: Arc<CedarPolicyStore>,
    revocation_store: Arc<RevocationStore>,
    signer: Arc<PasetoV4Signer>,
    max_ttl_seconds: i32,
}

impl AuthorityServiceImpl {
    pub fn new(
        policy_store: Arc<CedarPolicyStore>,
        revocation_store: Arc<RevocationStore>,
        signer: Arc<PasetoV4Signer>,
        max_ttl_seconds: i32,
    ) -> Self {
        Self {
            policy_store,
            revocation_store,
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
        let policy_set = self.policy_store.get_policy_set().await;
        let decision = evaluate_cedar_policy(
            &policy_set,
            &req.agent_id,
            &req.requested_actions,
            &req.resource_scope,
        );

        match decision {
            CedarDecision::Allow => {
                // FR-4: Clamp TTL
                let ttl = clamp_ttl(req.requested_ttl_seconds, self.max_ttl_seconds);
                let now = Utc::now();
                let expires_at = now + Duration::seconds(i64::from(ttl));
                let token_id = format!("tok_{}", Uuid::new_v4());

                // Build context hash from the current policy bundle version
                let context_hash = self.policy_store.get_bundle().await.version.clone();

                let claims = CapabilityClaims {
                    token_id: token_id.clone(),
                    agent_id: req.agent_id.clone(),
                    session_id: req.session_id.clone(),
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
                    token_id,
                    agent_id: req.agent_id.clone(),
                    action_set: req.requested_actions,
                    resource_scope: req.resource_scope,
                    issued_at: Some(issued_at_ts),
                    expiry: Some(expiry_ts),
                    context_hash,
                    signature: signed_token.into_bytes(),
                    format: TokenFormat::PasetoV4.into(),
                };

                tracing::info!(
                    agent_id = %req.agent_id,
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

        let mut rx = self.policy_store.subscribe();

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
        let broadcast_rx = self.revocation_store.subscribe();

        let stream = async_stream::try_stream! {
            // First, replay historical events
            for entry in replay_events {
                yield entry_to_proto(&entry);
            }

            // Then stream new events as they arrive
            let mut broadcast_stream = BroadcastStream::new(broadcast_rx);
            while let Some(Ok(entry)) = broadcast_stream.next().await {
                yield entry_to_proto(&entry);
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
fn evaluate_cedar_policy(
    policy_set: &PolicySet,
    agent_id: &str,
    actions: &[String],
    resource: &str,
) -> CedarDecision {
    // If no policies are loaded, deny by default (fail-closed)
    if policy_set.policies().next().is_none() {
        return CedarDecision::Deny {
            reason: "NO_POLICIES".to_string(),
            message: "no Cedar policies loaded".to_string(),
        };
    }

    let authorizer = Authorizer::new();

    // Build Cedar request with unspecified entity UIDs (schema-less evaluation)
    // This allows policies to use `permit(principal, action, resource)` patterns
    // without requiring entity types to be defined in a schema.
    let request = match Request::new(
        Some(parse_entity_uid(agent_id)),
        Some(parse_action_uid(actions)),
        Some(parse_resource_uid(resource)),
        Context::empty(),
        None, // no schema validation on request
    ) {
        Ok(r) => r,
        Err(e) => {
            return CedarDecision::Deny {
                reason: "CONTEXT_BUILD_FAILED".to_string(),
                message: format!("failed to build Cedar request: {e}"),
            };
        }
    };

    let entities = Entities::empty();
    let response = authorizer.is_authorized(&request, policy_set, &entities);

    match response.decision() {
        cedar_policy::Decision::Allow => CedarDecision::Allow,
        cedar_policy::Decision::Deny => {
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
                format!("policy errors: {}", errors.join("; "))
            } else if !reasons.is_empty() {
                format!("denied by policies: {}", reasons.join(", "))
            } else {
                "denied by default (no matching permit policy)".to_string()
            };

            CedarDecision::Deny {
                reason: "POLICY_DENIED".to_string(),
                message,
            }
        }
    }
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

/// Parse the first action into a Cedar `EntityUid`.
/// Uses the namespace `Firma::Action`.
fn parse_action_uid(actions: &[String]) -> EntityUid {
    let action = actions.first().map_or("unknown", String::as_str);
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
        token_id: entry.token_id.clone(),
        reason: entry.reason.clone(),
        timestamp: Some(to_proto_timestamp(entry.timestamp)),
    }
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

    #[test]
    fn test_evaluate_no_policies_denies() {
        let empty = PolicySet::new();
        let result = evaluate_cedar_policy(
            &empty,
            "agent_1",
            &["http:GET".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_permit_all_allows() {
        let ps: PolicySet = "permit(principal, action, resource);"
            .parse()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let result =
            evaluate_cedar_policy(&ps, "agent_1", &["http:GET".to_string()], "api.example.com");
        assert!(matches!(result, CedarDecision::Allow));
    }

    #[test]
    fn test_evaluate_forbid_all_denies() {
        let ps: PolicySet = "forbid(principal, action, resource);"
            .parse()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let result =
            evaluate_cedar_policy(&ps, "agent_1", &["http:GET".to_string()], "api.example.com");
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn test_to_proto_timestamp_roundtrip() {
        let now = Utc::now();
        let ts = to_proto_timestamp(now);
        assert_eq!(ts.seconds, now.timestamp());
    }
}
