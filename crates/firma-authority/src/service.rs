use std::pin::Pin;
use std::sync::Arc;

use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request, Schema};
use chrono::{Duration, Utc};
use firma_core::AgentId;
use firma_core::FirmaEntityUid;
use firma_core::policy::PolicyBundle;
use firma_core::session::SessionId;
use firma_core::token::CapabilityClaims;
use firma_core::token::paseto::PasetoV4Signer;
use firma_protobuf::v1::RevocationEvent;
use firma_protobuf::v1::authority_service_server::AuthorityService;
use firma_protobuf::v1::{
    CapabilityToken, IssueCapabilityRequest, IssueCapabilityResponse, IssueDecision,
    PolicyBundleUpdate, TokenFormat, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::{Stream, StreamExt};
use tonic::{Code, Request as TonicRequest, Response, Status};
use x509_parser::prelude::*;

use crate::cedar_loader::{CedarPolicyStore, CedarPolicyStoreWatcher};
use crate::revocation::{RevocationStore, RevocationStoreWatcher};

/// gRPC implementation of the `AuthorityService` defined in `authority.proto`.
pub struct AuthorityServiceImpl {
    /// Keeps issuance policy hot-reload task alive; also used to evaluate
    /// issuance requests via `Deref<Target = CedarPolicyStore>`.
    issuance_policy_watcher: CedarPolicyStoreWatcher,
    /// Keeps enforcement policy hot-reload task alive; also used to subscribe bundle updates.
    policy_watcher: CedarPolicyStoreWatcher,
    /// Keeps revocation hot-reload task alive; also used to subscribe revocation events
    /// and read in-memory revocation state via `Deref<Target = RevocationStore>`.
    revocation_watcher: RevocationStoreWatcher,
    signer: Arc<PasetoV4Signer>,
    max_ttl_seconds: i32,
}

impl AuthorityServiceImpl {
    /// # Errors
    ///
    /// Returns an error if any file watcher cannot be initialised.
    pub(crate) fn try_new(
        issuance_policy_store: CedarPolicyStore,
        policy_store: CedarPolicyStore,
        revocation_store: RevocationStore,
        signer: Arc<PasetoV4Signer>,
        max_ttl_seconds: i32,
    ) -> anyhow::Result<Self> {
        let issuance_policy_watcher = issuance_policy_store.watch()?;
        let policy_watcher = policy_store.watch()?;
        let revocation_watcher = revocation_store.watch()?;
        Ok(Self {
            issuance_policy_watcher,
            policy_watcher,
            revocation_watcher,
            signer,
            max_ttl_seconds,
        })
    }
}

#[tonic::async_trait]
impl AuthorityService for AuthorityServiceImpl {
    /// FR-3: Evaluate Cedar policies and issue a signed capability token.
    async fn issue_capability(
        &self,
        request: TonicRequest<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        let client_identity = peer_identity_from_request(&request);
        let remote_addr = request.remote_addr();
        let req = request.into_inner();

        tracing::info!(
            agent_id = %req.agent_id,
            session_id = %req.session_id,
            actions = ?req.requested_actions,
            resource = %req.resource_scope,
            client_identity = %client_identity.as_deref().unwrap_or("<unknown>"),
            remote_addr = %remote_addr.map_or_else(|| "<unknown>".to_string(), |a| a.to_string()),
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

        let issuance_req = crate::issuance::IssuanceRequest {
            agent_id: &agent_id,
            session_id: &session_id,
            requested_actions: &req.requested_actions,
            resource_scope: &req.resource_scope,
            requested_ttl_seconds: req.requested_ttl_seconds,
        };

        match crate::issuance::issue_capability(
            &self.issuance_policy_watcher,
            &self.signer,
            self.max_ttl_seconds,
            &issuance_req,
        )
        .await
        {
            Ok(out) => {
                let token = build_proto_token(
                    &out.claims,
                    out.raw_token.into_bytes(),
                    &self.policy_watcher.bundle().version,
                );
                tracing::info!(
                    agent_id = %token.agent_id,
                    token_id = %token.token_id,
                    client_identity = %client_identity.as_deref().unwrap_or("<unknown>"),
                    "capability granted"
                );
                Ok(Response::new(IssueCapabilityResponse {
                    granted: true,
                    token: Some(token),
                    deny_reason: String::new(),
                    deny_message: String::new(),
                    decision: IssueDecision::Allow.into(),
                    approval_id: None,
                    approval_url: None,
                    approval_expiry: None,
                }))
            }
            Err(crate::issuance::IssuanceError::Denied { reason, message }) => {
                tracing::info!(
                    agent_id = %req.agent_id,
                    deny_reason = %reason,
                    client_identity = %client_identity.as_deref().unwrap_or("<unknown>"),
                    "capability denied"
                );
                Ok(Response::new(IssueCapabilityResponse {
                    granted: false,
                    token: None,
                    deny_reason: reason,
                    deny_message: message,
                    decision: IssueDecision::Deny.into(),
                    approval_id: None,
                    approval_url: None,
                    approval_expiry: None,
                }))
            }
            Err(crate::issuance::IssuanceError::Sign(e)) => {
                tracing::error!(error = %e, "token signing failed");
                Err(Status::internal("token signing failed"))
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
        let client_identity = peer_identity_from_request(&request);
        let req = request.into_inner();
        let current_version = req.current_version;

        tracing::info!(
            client_version = %current_version,
            client_identity = %client_identity.as_deref().unwrap_or("<unknown>"),
            "sidecar connected to policy bundle stream"
        );

        let mut rx = self.policy_watcher.subscribe();

        let stream = async_stream::try_stream! {
            // Send current bundle immediately (unless client already has it)
            let initial = rx.borrow_and_update().clone();
            if current_version.is_empty() || current_version != initial.version {
                yield bundle_to_update(&initial);
            }

            // Periodic refresh keeps the sidecar bundle fresh between policy changes.
            // Interval = half of bundle TTL, floored at 5 s.
            let refresh_secs = (u64::from(initial.ttl_seconds) / 2).max(5);
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_secs(refresh_secs)
            );
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // skip the immediate first tick

            loop {
                tokio::select! {
                    result = rx.changed() => {
                        if result.is_err() { break; }
                        let bundle = rx.borrow_and_update().clone();
                        yield bundle_to_update(&bundle);
                        // reset ticker so refresh fires relative to this send
                        ticker.reset();
                    }
                    _ = ticker.tick() => {
                        let bundle = rx.borrow().clone();
                        yield bundle_to_update(&bundle);
                    }
                }
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
        let client_identity = peer_identity_from_request(&request);
        let req = request.into_inner();

        let since = match req.since {
            Some(ts) => ts
                .nanos
                .try_into()
                .ok()
                .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
                .ok_or_else(|| {
                    Status::new(Code::InvalidArgument, "invalid timestamp for `since`")
                })?,
            None => Utc::now() - Duration::days(365),
        };

        tracing::info!(
            ?since,
            client_identity = %client_identity.as_deref().unwrap_or("<unknown>"),
            "sidecar connected to revocation stream"
        );

        // Replay events after `since` timestamp
        let replay_events = self.revocation_watcher.events_since(since).await;
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

/// Extract peer identity from mTLS request certificates.
///
/// Resolution order:
/// 1. First DNS SAN
/// 2. Subject CN
fn peer_identity_from_request<T>(request: &TonicRequest<T>) -> Option<String> {
    let certs = request.peer_certs()?;
    let end_entity = certs.first()?;
    let (_, parsed) = X509Certificate::from_der(end_entity.as_ref()).ok()?;

    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    return Some((*dns).to_string());
                }
            }
        }
    }

    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

// --- Cedar evaluation helpers ---

pub(crate) enum CedarDecision {
    /// At least one requested action is authorized. Carries the granted subset
    /// (`requested ∩ Cedar-permitted`), which becomes the token `action_set`.
    Allow {
        granted: Vec<String>,
    },
    Deny {
        reason: String,
        message: String,
    },
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

    /// Every requested action was denied by policy; the intersection is empty
    /// so there is nothing to grant. Fail closed rather than mint an empty token.
    fn no_authorized_actions() -> Self {
        Self::Deny {
            reason: "NO_AUTHORIZED_ACTIONS".to_string(),
            message: "no requested action classes are authorized by policy".to_string(),
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
}

/// Human-readable reason a single action was denied, used when logging the
/// actions dropped while narrowing an issuance request to its authorized subset.
fn policy_deny_message(action: &str, diagnostics: &cedar_policy::Diagnostics) -> String {
    let reasons: Vec<String> = diagnostics
        .reason()
        .map(std::string::ToString::to_string)
        .collect();
    let errors: Vec<String> = diagnostics
        .errors()
        .map(std::string::ToString::to_string)
        .collect();

    if !errors.is_empty() {
        format!("policy errors for '{action}': {}", errors.join("; "))
    } else if !reasons.is_empty() {
        format!("denied '{action}' by policies: {}", reasons.join(", "))
    } else {
        format!("denied '{action}' by default (no matching permit policy)")
    }
}

/// Evaluate Cedar policies for a capability issuance request.
///
/// Uses Cedar's unspecified principal/action/resource when the schema is
/// not loaded, falling back to a simple "any policy allows" evaluation.
/// Evaluate Cedar policies for a capability issuance request.
///
/// Evaluates every requested action independently and grants the authorized
/// subset (`requested ∩ Cedar-permitted`). Policy-denied actions are dropped,
/// not fatal: this lets a run request the full action-class set and receive a
/// token narrowed to whatever the policy authorizes. If the intersection is
/// empty the whole issuance fails closed. Structural/malformed requests (invalid
/// action UID, context-build failure) still hard-fail the entire request.
///
/// Context at issuance time carries `session_id`, `timestamp_ms`, and
/// `risk_score` (V1 placeholder = 0). `params` is empty (`"{}"`) because no
/// specific intent exists yet at issuance. Runtime-signal fields are populated
/// with schema-compatible placeholders — the Authority has no session history
/// at pre-flight, but all fields required by `EnforcementContext` must be present.
pub(crate) fn evaluate_cedar_policy(
    policy_set: &PolicySet,
    schema: &Schema,
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

    let principal: cedar_policy::EntityUid = match FirmaEntityUid::Agent(*agent_id).try_into() {
        Ok(uid) => uid,
        Err(e) => {
            return CedarDecision::invalid_request(format!("invalid agent_id: {e}"));
        }
    };
    // Build the resource as a full entity so issuance-time policies can read
    // `resource.host` / `resource.path` / `resource.id` — evaluated identically
    // to Sidecar enforcement. A bare UID with an empty store makes every
    // `resource.<attr>` access error and skips the guarded condition.
    let resource_entity = match FirmaEntityUid::resource_entity(resource) {
        Ok(entity) => entity,
        Err(e) => {
            return CedarDecision::invalid_request(format!("invalid resource: {e}"));
        }
    };
    let resource_uid = resource_entity.uid();
    let entities = match Entities::from_entities([resource_entity], None) {
        Ok(entities) => entities,
        Err(e) => {
            return CedarDecision::invalid_request(format!("invalid resource entity store: {e}"));
        }
    };
    let authorizer = Authorizer::new();
    let timestamp_ms = Utc::now().timestamp_millis();

    let mut granted: Vec<String> = Vec::with_capacity(actions.len());
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
            "session_duration_s": 0i64,
            "action_count": 0i64,
            "raw_transport": "https",
            "deny_count": 0i64,
            "prior_action_classes": [],
            "last_resource": "",
            "transfer_amount": 0i64,
            "daily_cumulative_amount": 0i64,
            "transfers_last_10m": 0i64,
            "same_payee_count_30m": 0i64,
            "session_transfer_count": 0i64,
        });
        let cedar_context =
            match Context::from_json_value(context_json, Some((schema, &action_entity))) {
                Ok(c) => c,
                Err(err) => {
                    return CedarDecision::context_build(action, &err.to_string());
                }
            };

        let request = match Request::new(
            Some(principal.clone()),
            Some(action_entity),
            Some(resource_uid.clone()),
            cedar_context,
            Some(schema),
        ) {
            Ok(r) => r,
            Err(e) => {
                return CedarDecision::invalid_request(e.to_string());
            }
        };

        let response = authorizer.is_authorized(&request, policy_set, &entities);

        if response.decision() == cedar_policy::Decision::Deny {
            tracing::debug!(
                action = %action,
                reason = %policy_deny_message(action, response.diagnostics()),
                "dropping unauthorized action while narrowing issuance"
            );
            continue;
        }
        granted.push(action.clone());
    }

    if granted.is_empty() {
        return CedarDecision::no_authorized_actions();
    }

    CedarDecision::Allow { granted }
}

// --- Proto conversion helpers ---

fn to_proto_timestamp(dt: chrono::DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos().try_into().unwrap_or(0),
    }
}

/// Build the proto `CapabilityToken` from the issuance result. Centralised so
/// both the gRPC handler here and any future caller (e.g. an HTTP shim) share
/// a single mapping from `CapabilityClaims` → wire format.
fn build_proto_token(
    claims: &CapabilityClaims,
    signature: Vec<u8>,
    policy_bundle_version: &str,
) -> CapabilityToken {
    CapabilityToken {
        token_id: claims.token_id.to_string(),
        agent_id: claims.agent_id.to_string(),
        session_id: claims.session_id.to_string(),
        action_set: claims.action_set.clone(),
        resource_scope: claims.resource_scope.clone(),
        issued_at: Some(to_proto_timestamp(claims.issued_at)),
        expiry: Some(to_proto_timestamp(claims.expiry)),
        context_hash: claims.context_hash.clone(),
        signature,
        format: TokenFormat::PasetoV4.into(),
        policy_bundle_version: Some(policy_bundle_version.to_string()),
        approver_id: None,
        approval_id: None,
    }
}

fn bundle_to_update(bundle: &PolicyBundle) -> PolicyBundleUpdate {
    PolicyBundleUpdate {
        bundle: Some(firma_protobuf::v1::PolicyBundle {
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
pub(crate) fn compute_context_hash(
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
pub(crate) fn clamp_ttl(requested: i32, max: i32) -> i32 {
    if requested <= 0 {
        max
    } else {
        requested.min(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str) -> AgentId {
        id.parse().unwrap()
    }

    fn session(id: &str) -> SessionId {
        id.parse().unwrap()
    }

    #[test]
    fn clamp_ttl_within_max() {
        assert_eq!(clamp_ttl(600, 3600), 600);
    }

    #[test]
    fn clamp_ttl_exceeds_max() {
        assert_eq!(clamp_ttl(7200, 3600), 3600);
    }

    #[test]
    fn clamp_ttl_zero_uses_max() {
        assert_eq!(clamp_ttl(0, 3600), 3600);
    }

    #[test]
    fn clamp_ttl_negative_uses_max() {
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

    /// Permits exactly one action class, so any other requested action
    /// default-denies (no matching permit) and is dropped while narrowing.
    fn permit_only(action: &str) -> PolicySet {
        format!("permit(principal, action == Firma::Action::\"{action}\", resource);")
            .parse()
            .unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn firma_schema() -> Schema {
        let (schema, _) = Schema::from_cedarschema_str(firma_core::cedar::FIRMA_SCHEMA)
            .unwrap_or_else(|e| panic!("schema parse failed: {e}"));
        schema
    }

    #[test]
    fn evaluate_no_policies_denies() {
        let result = evaluate_cedar_policy(
            &PolicySet::new(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["filesystem.read".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn evaluate_no_actions_denies() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &[],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { reason, .. } if reason == "NO_ACTIONS"));
    }

    #[test]
    fn evaluate_permit_all_allows() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["filesystem.read".to_string()],
            "api.example.com",
        );
        assert!(
            matches!(result, CedarDecision::Allow { granted } if granted == ["filesystem.read"])
        );
    }

    #[test]
    fn evaluate_forbid_all_denies() {
        // forbid-all → nothing authorized → empty intersection → fail closed.
        let result = evaluate_cedar_policy(
            &forbid_all(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["filesystem.read".to_string()],
            "api.example.com",
        );
        assert!(
            matches!(result, CedarDecision::Deny { reason, .. } if reason == "NO_AUTHORIZED_ACTIONS")
        );
    }

    fn host_forbid() -> PolicySet {
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource) \
         when { resource has host && resource.host == \"169.254.169.254\" };"
            .parse()
            .unwrap_or_else(|e| panic!("{e:?}"))
    }

    #[test]
    fn evaluate_host_forbid_denies_metadata_endpoint() {
        // Issuance-time host rule: the resource.host attribute must be populated
        // in the entity store so the metadata-endpoint forbid fires here exactly
        // as it does on the Sidecar hot path.
        let result = evaluate_cedar_policy(
            &host_forbid(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["communication.external.send".to_string()],
            "169.254.169.254",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn evaluate_host_forbid_allows_other_host() {
        // Control for the deny above: the same bundle permits a non-metadata
        // host, proving the deny is driven by resource.host (evaluated, not
        // erroring the whole request).
        let result = evaluate_cedar_policy(
            &host_forbid(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["communication.external.send".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow { .. }));
    }

    #[test]
    fn evaluate_multi_action_all_allowed() {
        let result = evaluate_cedar_policy(
            &permit_all(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &[
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
            "api.example.com",
        );
        assert!(matches!(
            result,
            CedarDecision::Allow { granted }
                if granted == ["communication.external.send", "filesystem.read"]
        ));
    }

    #[test]
    fn evaluate_multi_action_narrows_to_authorized_subset() {
        // Policy permits only filesystem.read; the unauthorized action is
        // dropped and the grant is narrowed rather than the whole request denied.
        let result = evaluate_cedar_policy(
            &permit_only("filesystem.read"),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &[
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
            "api.example.com",
        );
        assert!(
            matches!(result, CedarDecision::Allow { granted } if granted == ["filesystem.read"])
        );
    }

    #[test]
    fn evaluate_multi_action_all_denied_fails_closed() {
        // forbid-all → every action dropped → empty intersection → deny.
        let result = evaluate_cedar_policy(
            &forbid_all(),
            &firma_schema(),
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &[
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
            "api.example.com",
        );
        assert!(
            matches!(result, CedarDecision::Deny { reason, .. } if reason == "NO_AUTHORIZED_ACTIONS")
        );
    }

    #[test]
    fn evaluate_with_schema_valid_action() {
        let schema = firma_schema();
        let result = evaluate_cedar_policy(
            &permit_all(),
            &schema,
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["communication.external.send".to_string()],
            "api.example.com",
        );
        assert!(matches!(
            result,
            CedarDecision::Allow { granted } if granted == ["communication.external.send"]
        ));
    }

    #[test]
    fn evaluate_with_schema_unknown_action_denies() {
        // "unknown.action" not declared in schema → Cedar rejects the request
        let schema = firma_schema();
        let result = evaluate_cedar_policy(
            &permit_all(),
            &schema,
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["unknown.action".to_string()],
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Deny { .. }));
    }

    #[test]
    fn evaluate_structural_failure_aborts_partial_grant() {
        // First action is authorized and would narrow into `granted`; the second
        // is structurally invalid (not declared in schema). A structural failure
        // must hard-fail the whole request rather than return the partial grant.
        let schema = firma_schema();
        let result = evaluate_cedar_policy(
            &permit_all(),
            &schema,
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &["filesystem.read".to_string(), "unknown.action".to_string()],
            "api.example.com",
        );
        assert!(
            matches!(result, CedarDecision::Deny { .. }),
            "structural failure after an authorized action must abort, not grant the subset"
        );
    }

    #[test]
    fn evaluate_with_schema_all_15_actions_allowed() {
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
            &schema,
            &agent("agt_01j0000000e008000000000001"),
            &session("sess_1"),
            &actions,
            "api.example.com",
        );
        assert!(matches!(result, CedarDecision::Allow { granted } if granted == actions));
    }

    #[test]
    fn to_proto_timestamp_roundtrip() {
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
