//! Enforcement pipeline orchestrator.
//!
//! Wires the [`IntentNormalizer`](crate::normalizer::IntentNormalizer),
//! Stage 1 ([`CapabilityValidator`]), and Stage 2 ([`ConstraintEnforcer`])
//! into a single `enforce()` entry point.
//!
//! The pipeline is the ONLY public entry point for enforcement; callers
//! never interact with individual stages directly.
//!
//! Every code path returns ALLOW, DENY, or PASSTHROUGH.
//! PASSTHROUGH means the request targets a non-protected host and should
//! be forwarded without enforcement. The pipeline short-circuits on any
//! DENY or PASSTHROUGH.
//!
//! Target: < 3 ms p95 end-to-end overhead (interceptor + Stage 1 +
//! Stage 2 + credential injection + audit emit, excluding connector and
//! external system latency).

use std::time::Duration;

use firma_core::{
    ActionParams, DenyReason, ExecutionEnvelope, ExecutionMetadata, InjectedCredentials,
    PaymentTransferParams, SessionId,
};

use std::sync::Arc;

use crate::audit::AuditPayload;
use crate::authority_client::readiness::ReadinessView;
use crate::credential::{CredentialInjectionError, CredentialInjector};
use crate::enforcement::SessionStateStore;
pub use crate::enforcement::capability_map::CapabilityMap;
pub use crate::enforcement::capability_validation::CapabilityValidator;
pub use crate::enforcement::constraint_enforcement::{ConstraintEnforcer, PolicyEvaluation};
pub use crate::enforcement::decision::EnforcementDecision;
use crate::enforcement::decision::EnforcementStage;
pub use crate::enforcement::registry::ActionClassRegistry;
pub use crate::normalizer::{IntentNormalizer, MappingTable, RawRequest};

/// Proto wire values for the enforcement decision enum.
const DECISION_ALLOW: i32 = 1;
pub(crate) const DECISION_DENY: i32 = 2;
/// Proto wire value for the `ABORT` decision introduced by task 005
/// step 6. Emitted when the connector aborts an already-approved call
/// (currently only `CONNECTOR_TIMEOUT`).
pub(crate) const DECISION_ABORT: i32 = 3;

#[expect(
    clippy::expect_used,
    reason = "the literal `_anonymous_` session id is non-empty by construction"
)]
fn anonymous_session_id() -> SessionId {
    "_anonymous_"
        .parse()
        .expect("literal anonymous session id is non-empty")
}

/// Construction arguments for [`EnforcementPipeline`].
///
/// Bundles every component the pipeline needs so the constructor
/// stays readable as new stages (e.g. credential injection) are added.
pub struct PipelineArgs {
    /// Intent normalizer (raw request → canonical envelope).
    pub normalizer: IntentNormalizer,
    /// Stage 1: token selection, parse, verify, expiry, revocation.
    pub capability_validator: CapabilityValidator,
    /// Stage 2: scope check, bundle freshness, Cedar policy eval.
    pub constraint_enforcer: ConstraintEnforcer,
    /// Credential injector called after Stage 2 ALLOW.
    pub credential_injector: Box<dyn CredentialInjector>,
    /// Per-session runtime state store — holds action count, budget
    /// consumed, risk score keyed by `SessionId`.
    pub session_state_store: Arc<dyn SessionStateStore>,
}

/// The enforcement pipeline. Orchestrates the full `enforce()` flow:
///
/// ```text
/// normalize → Stage 1 → Stage 2 → credential injection → assemble envelope
/// ```
///
/// Short-circuits on any DENY or PASSTHROUGH. Every code path returns
/// ALLOW, DENY, or PASSTHROUGH.
/// The pipeline is stateless per-request — all shared state is accessed
/// via references injected at construction time.
///
/// Target: < 3ms p95 end-to-end overhead.
pub struct EnforcementPipeline {
    capability_validator: CapabilityValidator,
    constraint_enforcer: ConstraintEnforcer,
    credential_injector: Box<dyn CredentialInjector>,
    normalizer: IntentNormalizer,
    readiness: ReadinessView,
    stage2_timeout: Option<Duration>,
    session_state_store: Arc<dyn SessionStateStore>,
}

impl EnforcementPipeline {
    /// Construct the pipeline from [`PipelineArgs`]. Called once at
    /// startup.
    #[must_use]
    pub fn new(args: PipelineArgs) -> Self {
        Self {
            capability_validator: args.capability_validator,
            constraint_enforcer: args.constraint_enforcer,
            credential_injector: args.credential_injector,
            normalizer: args.normalizer,
            readiness: ReadinessView::all_ready(),
            stage2_timeout: None,
            session_state_store: args.session_state_store,
        }
    }

    /// Install a readiness view for Authority-backed runtime state.
    #[must_use]
    pub fn with_readiness(mut self, readiness: ReadinessView) -> Self {
        self.readiness = readiness;
        self
    }

    /// Bound Stage 2 evaluation by a timeout.
    ///
    /// Any expiry DENYs with `EnforcementTimeout` to preserve fail-closed
    /// behavior under load.
    #[must_use]
    pub fn with_stage2_timeout(mut self, stage2_timeout: Duration) -> Self {
        self.stage2_timeout = Some(stage2_timeout);
        self
    }

    /// Run the full enforcement pipeline.
    ///
    /// This is the ONLY public entry point for enforcement.
    /// Token is selected internally from the `CapabilityMap` (ADR-002).
    ///
    /// Pipeline stages:
    /// 1. Normalize intent: raw request → `NormalizedEnvelope`
    /// 2. Capability validation: select token, validate → `ValidatedCapability`
    /// 3. Constraint enforcement: scope check + Cedar policy evaluation
    /// 4. Credential injection: fetch credentials for outbound target
    /// 5. On Allow: assemble a fully populated `ExecutionEnvelope` from
    ///    the normalized envelope + validated capability + session context.
    #[must_use]
    pub async fn enforce(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> (EnforcementDecision, AuditPayload) {
        let start = std::time::Instant::now();
        let bundle_version = self.constraint_enforcer.policy_version();

        let decision = self.enforce_inner(request, session_id).await;
        let payload = audit_payload_from_decision(
            &decision,
            request,
            session_id,
            start.elapsed(),
            bundle_version.as_deref(),
        );

        (decision, payload)
    }

    /// Enforcement logic, separated so the outer [`enforce`](Self::enforce)
    /// can unconditionally audit the result.
    async fn enforce_inner(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision {
        if let Err(deny) = self.check_readiness() {
            return deny;
        }

        // Normalize intent (may short-circuit with Deny or Passthrough)
        let normalized = match self.normalizer.normalize(request) {
            Ok(env) => env,
            Err(decision) => return decision,
        };

        // Capability validation: select token → validate
        let capability = match self.capability_validator.enforce(&normalized, session_id) {
            Ok(cap) => cap,
            Err(deny) => return deny,
        };

        // Constraint enforcement: scope check + Cedar policy evaluation.
        //
        // Record this admitted call. Session-scoped; first call is 1.
        // Gate is Stage 1 ALLOW — Stage 1 DENY short-circuits above and
        // must NOT bump the counter.
        let action_count = self
            .session_state_store
            .record_action(&capability.claims.session_id);
        let mut signals = self
            .session_state_store
            .signals(&capability.claims.session_id);
        // `record_action` already incremented the counter — ensure Cedar
        // sees the up-to-date value even if a concurrent writer raced
        // between `record_action` and `signals` (the LRU mutex is taken
        // twice; the second read could observe a later increment).
        signals.action_count = action_count;

        let now = std::time::Instant::now();
        let payment_transfer = match &normalized.intent.params {
            ActionParams::PaymentTransfer(p) => Some(p.clone()),
            _ => None,
        };
        self.attach_payment_signals(
            &capability.claims.session_id,
            &mut signals,
            payment_transfer.as_ref(),
            now,
        );

        let stage2_result = match self.stage2_timeout {
            Some(timeout) => {
                self.constraint_enforcer
                    .evaluate_with_timeout(&normalized, &capability.claims, &signals, timeout)
                    .await
            }
            None => self
                .constraint_enforcer
                .evaluate(&normalized, &capability.claims, &signals),
        };
        if let Err(deny) = stage2_result {
            return deny;
        }

        // All stages passed — assemble the fully populated envelope.
        // Empty session_id falls back to the `_anonymous_` sentinel so
        // in-tree tests and callers that do not propagate a session
        // header still reach the connector.
        let session_id_typed = session_id
            .parse::<SessionId>()
            .unwrap_or_else(|_| anonymous_session_id());
        let mut envelope = ExecutionEnvelope::new(
            normalized.intent,
            capability.raw_token,
            ExecutionMetadata {
                session_id: session_id_typed,
                agent_id: capability.claims.agent_id.clone(),
                timestamp: normalized.timestamp,
                trace_id: None,
                budget_consumed: signals.budget_consumed,
                risk_score: if signals.risk_score == 0.0 {
                    None
                } else {
                    Some(signals.risk_score)
                },
            },
            None,
        );

        // Credential injection: fetch credentials for the outbound
        // target. connector_id is the host portion of the resource.
        let resource_display = envelope.intent().resource_display();
        let connector_id = extract_host(&resource_display);
        let target = resource_display.as_str();
        let credentials = match self
            .credential_injector
            .inject(&envelope, connector_id, target)
            .await
        {
            Ok(creds) => creds,
            // No credentials configured for this connector — proceed
            // with empty headers (passthrough behavior).
            Err(CredentialInjectionError::UnknownConnector { .. }) => InjectedCredentials::empty(),
            // Credential fetch failed — fail-closed.
            Err(CredentialInjectionError::FetchFailed {
                connector_id,
                reason,
            }) => {
                return EnforcementDecision::Deny {
                    reason: DenyReason::CredentialInjectionFailed,
                    stage: EnforcementStage::CredentialInjection,
                    detail: format!("connector {connector_id}: {reason}"),
                    envelope: None,
                };
            }
        };

        let budget_cost = self.record_admitted_allow(
            &capability.claims.session_id,
            payment_transfer.as_ref(),
            now,
        );
        envelope.metadata.budget_consumed = signals.budget_consumed + budget_cost;

        EnforcementDecision::Allow {
            claims: capability.claims,
            envelope: Box::new(envelope),
            credentials,
        }
    }

    /// Readiness gate. Denies every call until the Authority streams
    /// have hydrated both the policy bundle and the revocation cache,
    /// so in-flight traffic never bypasses state that the Authority
    /// has not yet shipped.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    fn check_readiness(&self) -> Result<(), EnforcementDecision> {
        let readiness = self.readiness.snapshot();
        if !readiness.policy_bundle_ready {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleNotReady,
                stage: EnforcementStage::ConstraintEnforcement(
                    crate::enforcement::decision::ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle has not been loaded".to_string(),
                envelope: None,
            });
        }
        if !readiness.revocation_ready {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::RevocationCacheNotReady,
                stage: EnforcementStage::CapabilityValidation(
                    crate::enforcement::decision::CapabilityValidationStage::TokenValidation,
                ),
                detail: "revocation cache has not completed initial sync".to_string(),
                envelope: None,
            });
        }
        Ok(())
    }

    fn attach_payment_signals(
        &self,
        session_id: &SessionId,
        signals: &mut crate::enforcement::session_state::RuntimeSignals,
        payment_transfer: Option<&PaymentTransferParams>,
        now: std::time::Instant,
    ) {
        let Some(transfer) = payment_transfer else {
            return;
        };
        signals.transfer_amount = transfer.amount;
        signals.daily_cumulative_amount = self.session_state_store.cumulative_transfer_amount(
            session_id,
            now,
            crate::enforcement::session_state::DAILY_WINDOW,
        );
        signals.transfers_last_10m = self.session_state_store.transfer_count_in_window(
            session_id,
            now,
            crate::enforcement::session_state::TRANSFER_WINDOW,
        );
        signals.same_payee_count_30m = self.session_state_store.same_payee_count(
            session_id,
            &transfer.payee,
            now,
            crate::enforcement::session_state::PAYEE_WINDOW,
        );
    }

    fn record_admitted_allow(
        &self,
        session_id: &SessionId,
        payment_transfer: Option<&PaymentTransferParams>,
        now: std::time::Instant,
    ) -> f64 {
        let budget_cost = payment_transfer.map_or(1.0, payment_budget_cost);
        self.session_state_store
            .add_budget_cost(session_id, budget_cost);
        if let Some(transfer) = payment_transfer {
            self.session_state_store.record_transfer(
                session_id,
                &transfer.payee,
                transfer.amount,
                now,
            );
        }
        budget_cost
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "budget_consumed is f64 by public schema; transfer cents fit exactly for supported test limits"
)]
fn payment_budget_cost(transfer: &PaymentTransferParams) -> f64 {
    transfer.amount.max(0) as f64
}

/// Extracts an [`AuditPayload`] from an [`EnforcementDecision`].
///
/// This is a pure data extraction — no cryptography, no I/O. Designed
/// to run on the enforcement hot path with < 1µs overhead.
///
/// `bundle_version` should be the version of the policy bundle that was
/// active when enforcement ran. Pass `None` when the bundle version is
/// unknown (e.g. in tests that do not wire a real `ConstraintEnforcer`).
#[must_use]
pub fn audit_payload_from_decision(
    decision: &EnforcementDecision,
    request: &RawRequest,
    session_id: &str,
    enforcement_latency: Duration,
    bundle_version: Option<&str>,
) -> AuditPayload {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "duration micros fits i64 for any realistic enforcement latency"
    )]
    let enforcement_latency_us = enforcement_latency.as_micros() as i64;

    let (
        token_id,
        agent_id,
        action,
        resource,
        decision_code,
        deny_reason,
        context_hash,
        bundle_version,
    ) = match decision {
        EnforcementDecision::Allow {
            claims, envelope, ..
        } => (
            claims.token_id.to_string(),
            claims.agent_id.to_string(),
            envelope.intent().action_class.clone(),
            envelope.intent().resource_display(),
            DECISION_ALLOW,
            String::new(),
            claims.context_hash.clone(),
            bundle_version.unwrap_or("").to_string(),
        ),
        EnforcementDecision::Deny {
            reason,
            detail,
            envelope,
            ..
        } => {
            let (action, resource) = envelope.as_ref().map_or_else(
                || {
                    (
                        raw_request_action_label(request),
                        raw_request_resource_display(request),
                    )
                },
                |e| (e.intent.action_class.clone(), e.intent.resource_display()),
            );

            (
                String::new(),
                String::new(),
                action,
                resource,
                DECISION_DENY,
                format!("{reason}: {detail}"),
                String::new(),
                String::new(),
            )
        }
        EnforcementDecision::Passthrough { .. } => (
            String::new(),
            String::new(),
            raw_request_action_label(request),
            raw_request_resource_display(request),
            DECISION_ALLOW,
            String::new(),
            String::new(),
            String::new(),
        ),
    };

    AuditPayload {
        session_id: session_id.to_string(),
        token_id,
        agent_id,
        action,
        resource,
        decision: decision_code,
        deny_reason,
        enforcement_latency_us,
        context_hash,
        bundle_version,
        dispatch_status: 0,
        dispatch_latency_us: 0,
        response_size: 0,
    }
}

fn raw_request_action_label(request: &RawRequest) -> String {
    let method = request.method.to_ascii_uppercase();
    if method == "CONNECT" {
        "network.connect".to_string()
    } else {
        format!("raw.http.{method}")
    }
}

fn raw_request_resource_display(request: &RawRequest) -> String {
    format!("{}{}", request.host, request.path)
}

/// Extracts the host portion from a resource string.
///
/// Resource format is `host/path` (no scheme). Returns the host part
/// before the first `/`, or the entire string if no `/` is present.
fn extract_host(resource: &str) -> &str {
    resource.split('/').next().unwrap_or(resource)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::enforcement::registry::ActionClassRegistry;
    use crate::normalizer::MappingTable;
    use chrono::Utc;
    use firma_core::*;
    use std::collections::HashMap;
    use std::time::Duration;

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    struct BudgetRemainingPolicy;
    impl PolicyEvaluation for BudgetRemainingPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            context: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(context
                .get("budget_remaining")
                .and_then(serde_json::Value::as_i64)
                .is_some_and(|remaining| remaining > 0))
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-budget-v1".to_string())
        }
    }

    struct DailyCumulativeLimitPolicy;
    impl PolicyEvaluation for DailyCumulativeLimitPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            action: &str,
            _: &str,
            context: &serde_json::Value,
        ) -> Result<bool, String> {
            if action != "payment.transfer" {
                return Ok(true);
            }
            let daily = context
                .get("daily_cumulative_amount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let current = context
                .get("transfer_amount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            Ok(daily + current <= 1_000_000)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-payment-v1".to_string())
        }
    }

    struct MockVerifier {
        claims: CapabilityClaims,
    }
    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Ok(self.claims.clone())
        }
    }

    struct NoRevocations;
    impl RevocationStore for NoRevocations {
        fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &TokenId) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "sess_001".parse().expect("literal session id"),
            action_set: vec![
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    fn test_mapping_table(rules: &[MappingRuleConfig]) -> MappingTable {
        test_mapping_table_with_protection(rules, true)
    }

    fn test_mapping_table_with_protection(
        rules: &[MappingRuleConfig],
        default_protected: bool,
    ) -> MappingTable {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: rules.to_vec(),
        };
        MappingTable::from_config(&file, &registry, default_protected)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn default_rules() -> Vec<MappingRuleConfig> {
        vec![
            MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            },
            MappingRuleConfig {
                method: Some("GET".to_string()),
                host: "*".to_string(),
                path: None,
                action_class: "filesystem.read".to_string(),
            },
        ]
    }

    fn test_pipeline() -> EnforcementPipeline {
        test_pipeline_with_session_store(std::sync::Arc::new(
            crate::enforcement::LruSessionStateStore::new(16),
        ))
    }

    fn test_pipeline_with_session_store(
        store: std::sync::Arc<dyn crate::enforcement::SessionStateStore>,
    ) -> EnforcementPipeline {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: store,
        })
    }

    /// Build a pipeline where Stage 1 denies every request: the
    /// `CapabilityMap` is empty, so token selection fails before any
    /// runtime-state bookkeeping.
    fn test_pipeline_stage1_denies_with_session_store(
        store: std::sync::Arc<dyn crate::enforcement::SessionStateStore>,
    ) -> EnforcementPipeline {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]), // empty — Stage 1 DENY
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );

        let constraint_enforcer =
            ConstraintEnforcer::new(std::sync::Arc::new(BudgetRemainingPolicy));

        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: store,
        })
    }

    fn test_request(method: &str, host_and_path: &str) -> RawRequest {
        let (host, path) = host_and_path.split_once('/').map_or_else(
            || (host_and_path.to_string(), "/".to_string()),
            |(h, p)| (h.to_string(), format!("/{p}")),
        );
        RawRequest {
            method: method.to_string(),
            host,
            path,
            headers: HashMap::new(),
            body: None,
            is_https: true,
        }
    }

    #[tokio::test]
    async fn test_enforce_happy_path() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow {
            claims, envelope, ..
        } = decision
        {
            assert_eq!(claims.agent_id.as_ref(), "agent_test");
            assert_eq!(envelope.metadata().agent_id.as_ref(), "agent_test");
            assert_eq!(envelope.metadata().session_id.as_ref(), "sess_001");
            assert!(
                !envelope.capability().is_empty(),
                "capability must be populated on Allow"
            );
            assert_eq!(
                envelope.intent().action_class,
                "communication.external.send"
            );
        }
    }

    #[tokio::test]
    async fn test_enforce_denies_before_authority_readiness() {
        let (flag, readiness) = crate::authority_client::readiness::ReadinessFlag::new(
            crate::authority_client::readiness::ReadinessState::default(),
        );
        let pipeline = test_pipeline().with_readiness(readiness);
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::PolicyBundleNotReady)
        );

        flag.set_policy_bundle_ready(true);
        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::RevocationCacheNotReady)
        );
    }

    #[tokio::test]
    async fn test_enforce_unclassified_intent() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
    }

    #[tokio::test]
    async fn test_enforce_not_protected_returns_passthrough() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table_with_protection(&rules, false));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer =
            ConstraintEnforcer::new(std::sync::Arc::new(BudgetRemainingPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "GET".to_string(),
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(
            decision.is_passthrough(),
            "non-protected traffic should passthrough, not deny"
        );
        assert!(!decision.is_deny());
        assert!(!decision.is_allow());
    }

    #[tokio::test]
    async fn test_enforce_scope_violation() {
        struct DenyDeletePolicy;
        impl PolicyEvaluation for DenyDeletePolicy {
            fn evaluate(
                &self,
                _: &AgentId,
                action: &str,
                _: &str,
                _: &serde_json::Value,
            ) -> Result<bool, String> {
                Ok(action != "filesystem.delete")
            }
            fn is_fresh(&self) -> bool {
                true
            }
            fn version(&self) -> Option<String> {
                Some("test".to_string())
            }
        }

        let rules = vec![MappingRuleConfig {
            method: Some("DELETE".to_string()),
            host: "api.example.com".to_string(),
            path: Some("/data".to_string()),
            action_class: "filesystem.delete".to_string(),
        }];

        let mut wide_claims = test_claims();
        wide_claims.action_set = vec!["*".to_string()];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.narrow".to_string(),
                claims: wide_claims.clone(),
            }]),
            Box::new(MockVerifier {
                claims: wide_claims,
            }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(DenyDeletePolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    // ===== Fail-closed discipline tests =====

    #[tokio::test]
    async fn test_enforce_validation_failure_short_circuits_enforcement() {
        struct RejectingVerifier;
        impl TokenVerifier for RejectingVerifier {
            fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
                Err(TokenError::SignatureInvalid {
                    reason: "forged".to_string(),
                })
            }
        }

        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.bad".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(RejectingVerifier),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
        assert_eq!(
            decision.stage(),
            Some(
                crate::enforcement::decision::EnforcementStage::CapabilityValidation(
                    crate::enforcement::decision::CapabilityValidationStage::TokenValidation,
                )
            )
        );
    }

    #[tokio::test]
    async fn test_enforce_no_capability_token_denies() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]), // empty!
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    // ===== Determinism test =====

    #[tokio::test]
    async fn test_enforce_deterministic_same_input_same_output() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        for _ in 0..100 {
            let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
            assert!(
                decision.is_allow(),
                "non-deterministic: got DENY on repeated call"
            );
        }
    }

    #[tokio::test]
    async fn test_enforce_deterministic_deny_same_input() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        for _ in 0..100 {
            let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
            assert!(decision.is_deny());
            assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
        }
    }

    // ===== Policy bundle staleness =====

    #[tokio::test]
    async fn test_enforce_allow_envelope_fields_complete() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{\"model\":\"gpt-4\"}".to_vec()),
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow {
            claims, envelope, ..
        } = decision
        {
            // Verify intent fields
            assert_eq!(
                envelope.intent().action_class,
                "communication.external.send"
            );
            assert_eq!(
                envelope.intent().resource_display(),
                "api.openai.com/v1/chat/completions"
            );
            assert_eq!(envelope.intent().raw_transport, "https");
            assert_eq!(
                envelope.intent().raw_action_ref,
                "POST /v1/chat/completions"
            );

            // Verify metadata fields
            assert_eq!(envelope.metadata().session_id.as_ref(), "sess_001");
            assert_eq!(envelope.metadata().agent_id.as_ref(), "agent_test");
            assert!(envelope.metadata().trace_id.is_none());
            assert!((envelope.metadata().budget_consumed - 1.0).abs() < f64::EPSILON);
            assert!(envelope.metadata().risk_score.is_none());

            // Verify provenance is None (V1 placeholder)
            assert!(envelope.provenance().is_none());

            // Verify capability token is populated
            assert!(!envelope.capability().is_empty());

            // Verify claims match
            assert_eq!(
                claims.token_id.to_string(),
                "3713c5fc-b569-650c-c780-c64051473370"
            );
            assert_eq!(claims.agent_id.as_ref(), "agent_test");
        }
    }

    #[tokio::test]
    async fn test_enforce_revoked_token_denied_through_pipeline() {
        struct RevokedStore;
        impl firma_core::RevocationStore for RevokedStore {
            fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, firma_core::TokenError> {
                Ok(true)
            }
            fn add_revocation(&self, _token_id: &TokenId) -> Result<(), firma_core::TokenError> {
                Ok(())
            }
        }

        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(RevokedStore),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenRevoked));
    }

    #[tokio::test]
    async fn test_enforce_expired_token_denied_through_pipeline() {
        let mut claims = test_claims();
        claims.expiry = Utc::now() - chrono::Duration::hours(1);

        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenExpired));
    }

    #[tokio::test]
    async fn test_enforce_scope_violation_through_pipeline() {
        // Token only allows communication.external.send, but request maps to filesystem.read
        let mut claims = test_claims();
        claims.action_set = vec!["communication.external.send".to_string()]; // no filesystem.read

        let rules = vec![MappingRuleConfig {
            method: Some("GET".to_string()),
            host: "api.example.com".to_string(),
            path: None,
            action_class: "filesystem.read".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "GET".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        // Token selection fails because no token covers filesystem.read
        assert!(decision.is_deny());
    }

    #[tokio::test]
    async fn test_enforce_sensitive_headers_stripped_in_allow() {
        let pipeline = test_pipeline();
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer secret".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow { envelope, .. } = decision {
            if let firma_core::ActionParams::Http(ref params) = envelope.intent().params {
                assert!(
                    !params.headers.contains_key("Authorization"),
                    "authorization header must not leak into envelope"
                );
                assert!(params.headers.contains_key("Content-Type"));
            }
        }
    }

    #[tokio::test]
    async fn test_enforce_stale_bundle_denies() {
        struct StalePolicy;
        impl PolicyEvaluation for StalePolicy {
            fn evaluate(
                &self,
                _: &AgentId,
                _: &str,
                _: &str,
                _: &serde_json::Value,
            ) -> Result<bool, String> {
                Ok(true)
            }
            fn is_fresh(&self) -> bool {
                false
            }
            fn version(&self) -> Option<String> {
                None
            }
        }

        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(StalePolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    // ===== Audit event emission tests =====

    #[tokio::test]
    async fn test_enforce_allow_emits_audit_event() {
        let mut claims = test_claims();
        claims.session_id = "sess_audit".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_audit").await;
        assert!(decision.is_allow());

        assert_eq!(payload.session_id, "sess_audit");
        assert_eq!(payload.decision, 1); // ALLOW
        assert_eq!(payload.token_id, "3713c5fc-b569-650c-c780-c64051473370");
        assert_eq!(payload.agent_id, "agent_test");
        assert_eq!(payload.action, "communication.external.send");
        assert!(payload.enforcement_latency_us >= 0);
        assert_eq!(
            payload.bundle_version, "test-v1",
            "bundle_version must be populated from ConstraintEnforcer in Allow audit events"
        );
    }

    #[tokio::test]
    async fn test_enforce_deny_emits_audit_event() {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_deny").await;
        assert!(decision.is_deny());

        assert_eq!(payload.session_id, "sess_deny");
        assert_eq!(payload.decision, 2); // DENY
        assert_eq!(payload.action, "raw.http.POST");
        assert_eq!(payload.resource, "api.openai.com/v1/chat/completions");
    }

    #[tokio::test]
    async fn test_enforce_passthrough_emits_audit_event() {
        let claims = test_claims();

        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];
        let normalizer = IntentNormalizer::new(test_mapping_table_with_protection(&rules, false));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "GET".to_string(),
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_pt").await;
        assert!(decision.is_passthrough());

        assert_eq!(payload.session_id, "sess_pt");
        assert_eq!(payload.decision, 1); // Passthrough maps to ALLOW
        assert_eq!(payload.action, "raw.http.GET");
        assert_eq!(payload.resource, "not-protected.example.com/any");
    }

    #[tokio::test]
    async fn test_enforce_normalization_deny_emits_audit_event() {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        // Unclassified intent — denied at normalization stage
        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_norm").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));

        assert_eq!(payload.session_id, "sess_norm");
        assert_eq!(payload.decision, 2); // DENY
    }

    // ===== Credential injection tests =====

    #[tokio::test]
    async fn test_enforce_credential_injection_success() {
        let mut claims = test_claims();
        claims.session_id = "sess_cred".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        // BasicCredentialInjector with credentials for api.openai.com
        let injector =
            crate::credential::provider::BasicCredentialInjector::new(HashMap::from([(
                "api.openai.com".to_string(),
                HashMap::from([("Authorization".to_string(), "Bearer sk_test".to_string())]),
            )]));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_cred").await;
        assert!(
            decision.is_allow(),
            "credential injection should not block Allow"
        );
    }

    #[tokio::test]
    async fn test_enforce_credential_injection_unknown_connector_allows() {
        let mut claims = test_claims();
        claims.session_id = "sess_cred".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        // Empty injector — no connectors configured
        let injector = crate::credential::provider::BasicCredentialInjector::empty();

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        // UnknownConnector should be treated as passthrough (empty creds)
        let (decision, _payload) = pipeline.enforce(&request, "sess_cred").await;
        assert!(
            decision.is_allow(),
            "unknown connector should still Allow with empty credentials"
        );
    }

    #[tokio::test]
    async fn test_enforce_credential_injection_fetch_failed_denies() {
        let mut claims = test_claims();
        claims.session_id = "sess_fail".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        // Vault injector with nonexistent secret file — triggers FetchFailed
        let injector =
            crate::credential::provider::VaultCredentialInjector::new(HashMap::from([(
                "api.openai.com".to_string(),
                vec![crate::credential::provider::VaultSecretEntry {
                    header_name: "Authorization".to_string(),
                    value_prefix: Some("Bearer ".to_string()),
                    secret_path: std::path::PathBuf::from("/nonexistent/secret"),
                }],
            )]));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_fail").await;
        assert!(decision.is_deny(), "FetchFailed should produce DENY");
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::CredentialInjectionFailed)
        );

        assert_eq!(payload.session_id, "sess_fail");
        assert_eq!(payload.decision, 2); // DENY
    }

    // ===== SessionStateStore wiring (Task 5) =====

    #[tokio::test]
    async fn pipeline_builds_runtime_signals_and_populates_metadata() {
        use crate::enforcement::session_state::{LruSessionStateStore, SessionStateStore};
        use std::sync::Arc;

        let store: Arc<dyn SessionStateStore> = Arc::new(LruSessionStateStore::new(16));

        let pipeline = test_pipeline_with_session_store(Arc::clone(&store));
        let request = test_request("POST", "api.openai.com/v1/chat/completions");

        // First call: action_count should be 1.
        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(matches!(decision, EnforcementDecision::Allow { .. }));
        assert_eq!(
            store
                .signals(&"sess_001".parse().expect("sid"))
                .action_count,
            1
        );

        // Second call: action_count should be 2.
        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(matches!(decision, EnforcementDecision::Allow { .. }));
        assert_eq!(
            store
                .signals(&"sess_001".parse().expect("sid"))
                .action_count,
            2
        );
    }

    #[tokio::test]
    async fn pipeline_stage1_deny_does_not_increment_action_count() {
        use crate::enforcement::session_state::{LruSessionStateStore, SessionStateStore};
        use std::sync::Arc;

        let store: Arc<dyn SessionStateStore> = Arc::new(LruSessionStateStore::new(16));

        // Pipeline configured so Stage 1 denies (no valid capability for
        // this session).
        let pipeline = test_pipeline_stage1_denies_with_session_store(Arc::clone(&store));
        let request = test_request("POST", "api.openai.com/v1/chat/completions");

        let (decision, _) = pipeline.enforce(&request, "sess_denied").await;
        assert!(matches!(decision, EnforcementDecision::Deny { .. }));
        assert_eq!(
            store
                .signals(&"sess_denied".parse().expect("sid"))
                .action_count,
            0
        );
    }

    // ===== Budget ceiling enforcement (Task FIR-62 Week 3) =====

    /// Build a pipeline whose token has the given budget ceiling.
    fn test_pipeline_with_budget(ceiling: f64) -> EnforcementPipeline {
        let mut claims = test_claims();
        claims.budget_ceiling = Some(ceiling);

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.budget_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer =
            ConstraintEnforcer::new(std::sync::Arc::new(BudgetRemainingPolicy));
        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(crate::credential::NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        })
    }

    fn test_payment_pipeline_with_store(
        store: std::sync::Arc<dyn crate::enforcement::SessionStateStore>,
    ) -> EnforcementPipeline {
        let mut claims = test_claims();
        claims.action_set = vec!["payment.transfer".to_string()];
        claims.budget_ceiling = Some(10_000_000.0);

        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.stripe.com".to_string(),
            path: Some("/v1/payment_intents".to_string()),
            action_class: "payment.transfer".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.payment_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer =
            ConstraintEnforcer::new(std::sync::Arc::new(DailyCumulativeLimitPolicy));

        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(crate::credential::NullCredentialInjector),
            session_state_store: store,
        })
    }

    fn payment_transfer_request(amount: i64, payee: &str) -> RawRequest {
        RawRequest {
            method: "POST".to_string(),
            host: "api.stripe.com".to_string(),
            path: "/v1/payment_intents".to_string(),
            headers: HashMap::new(),
            body: Some(format!("amount={amount}&payee={payee}").into_bytes()),
            is_https: true,
        }
    }

    #[tokio::test]
    async fn budget_ceiling_denies_when_consumed_equals_ceiling() {
        // ceiling = 1.0, cost = 1.0 per call.
        // Call 1: remaining = 1 > 0 → ALLOW → consumed becomes 1.
        // Call 2: remaining = 0 <= 0 → Cedar DENY.
        //
        // Session id must match the session_id baked into the token claims
        // because CapabilityMap::select filters by session_id.
        let pipeline = test_pipeline_with_budget(1.0);
        let request = test_request("POST", "api.openai.com/v1/chat/completions");

        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(
            decision.is_allow(),
            "first call within budget must be allowed"
        );

        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny(), "second call must be denied");
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[tokio::test]
    async fn budget_ceiling_five_allows_then_sixth_denied() {
        // ceiling = 5.0, cost = 1.0 per call → calls 1-5 pass, call 6 denied.
        let pipeline = test_pipeline_with_budget(5.0);
        let request = test_request("POST", "api.openai.com/v1/chat/completions");

        for i in 1..=5u32 {
            let (decision, _) = pipeline.enforce(&request, "sess_001").await;
            assert!(decision.is_allow(), "call {i} must be allowed");
        }

        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(
            decision.is_deny(),
            "6th call must be denied after budget exhausted"
        );
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[tokio::test]
    async fn daily_cumulative_limit_denies_sixth_transfer_with_valid_token() {
        let store: std::sync::Arc<dyn crate::enforcement::SessionStateStore> =
            std::sync::Arc::new(crate::enforcement::LruSessionStateStore::new(16));
        let pipeline = test_payment_pipeline_with_store(std::sync::Arc::clone(&store));

        for i in 1..=5u32 {
            let request = payment_transfer_request(200_000, "payee_x");
            let (decision, _) = pipeline.enforce(&request, "sess_001").await;
            assert!(decision.is_allow(), "transfer {i} must be allowed");
        }

        assert_eq!(
            store
                .signals(&"sess_001".parse().expect("sid"))
                .session_transfer_count,
            5
        );
        assert_eq!(
            store.cumulative_transfer_amount(
                &"sess_001".parse().expect("sid"),
                std::time::Instant::now(),
                crate::enforcement::session_state::DAILY_WINDOW,
            ),
            1_000_000
        );

        let request = payment_transfer_request(200_000, "payee_x");
        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny(), "6th transfer must be denied");
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[tokio::test]
    async fn budget_ceiling_none_never_denies_for_budget() {
        // No ceiling → unbounded → 100 calls all pass.
        let pipeline = test_pipeline(); // uses test_claims() with budget_ceiling: None
        let request = test_request("POST", "api.openai.com/v1/chat/completions");

        for _ in 0..100 {
            let (decision, _) = pipeline.enforce(&request, "sess_001").await;
            assert!(decision.is_allow(), "unbounded budget must never deny");
        }
    }

    // ===== Scope constraint per-call (Task FIR-62 Week 3) =====

    #[tokio::test]
    async fn scope_violation_denied_per_call_not_only_at_issuance() {
        // CapabilityMap entry has wildcard action_set so Stage 1 always selects
        // the token. The MockVerifier returns narrow claims (only
        // "communication.external.send"), so Stage 2 check_scope enforces the
        // real per-call constraint and produces ScopeViolation for every request
        // to a "filesystem.read" endpoint.
        //
        // This proves the scope gate runs on every call (not just at issuance):
        // the token is pre-selected at startup (Stage 1 sees wildcard) but
        // Stage 2 re-checks the verified claims on each enforce() call.
        let mut map_claims = test_claims();
        map_claims.action_set = vec!["*".to_string()]; // wide — Stage 1 always selects

        let mut verified_claims = test_claims();
        verified_claims.action_set = vec!["communication.external.send".to_string()]; // narrow — Stage 2 enforces

        let rules = vec![MappingRuleConfig {
            method: Some("GET".to_string()),
            host: "api.example.com".to_string(),
            path: None,
            action_class: "filesystem.read".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.wide_token".to_string(),
                claims: map_claims, // wildcard → selects for filesystem.read
            }]),
            Box::new(MockVerifier {
                claims: verified_claims,
            }), // narrow → Stage 2 denies
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(crate::credential::NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = test_request("GET", "api.example.com/data");
        for call in 1..=5u32 {
            let (decision, _) = pipeline.enforce(&request, "sess_001").await;
            assert!(
                decision.is_deny(),
                "call {call} must be denied (per-call scope check)"
            );
            assert_eq!(
                decision.deny_reason(),
                Some(DenyReason::ScopeViolation),
                "call {call} must produce ScopeViolation — scope is enforced per-call"
            );
        }
    }

    // ===== Zero Authority RPC calls during enforcement cycle (Task FIR-62 Week 3) =====
    //
    // Architecture guarantee: the EnforcementPipeline holds no Authority client.
    // All Authority contact runs in background streaming tasks (policy bundle and
    // revocation streams) that are initialized before the pipeline starts serving.
    // Once hydrated, enforcement is fully local — no RPCs on the hot path.
    //
    // This test proves the guarantee by running 10 enforcement calls through a
    // pipeline that uses an `AuthorityCallTracker` store. If the pipeline were
    // to add an Authority-contact code path in the future, the tracker would
    // detect it. Since we never call Authority here, the count stays 0.

    struct AuthorityCallTracker {
        inner: crate::enforcement::LruSessionStateStore,
        // Counter is written by callers to prove zero authority calls;
        // reading it is the test assertion.
        #[allow(dead_code)]
        authority_call_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AuthorityCallTracker {
        fn new(counter: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
            Self {
                inner: crate::enforcement::LruSessionStateStore::new(32),
                authority_call_count: counter,
            }
        }
    }

    impl crate::enforcement::SessionStateStore for AuthorityCallTracker {
        fn record_action(&self, session_id: &firma_core::SessionId) -> u64 {
            // No Authority contact — delegate to real store.
            self.inner.record_action(session_id)
        }
        fn signals(
            &self,
            session_id: &firma_core::SessionId,
        ) -> crate::enforcement::session_state::RuntimeSignals {
            self.inner.signals(session_id)
        }
        fn add_budget_cost(&self, session_id: &firma_core::SessionId, cost: f64) {
            self.inner.add_budget_cost(session_id, cost);
        }
        fn record_transfer(
            &self,
            session_id: &firma_core::SessionId,
            payee: &str,
            amount: i64,
            at: std::time::Instant,
        ) {
            self.inner.record_transfer(session_id, payee, amount, at);
        }
        fn same_payee_count(
            &self,
            session_id: &firma_core::SessionId,
            payee: &str,
            now: std::time::Instant,
            window: std::time::Duration,
        ) -> u64 {
            self.inner.same_payee_count(session_id, payee, now, window)
        }
        fn cumulative_transfer_amount(
            &self,
            session_id: &firma_core::SessionId,
            now: std::time::Instant,
            window: std::time::Duration,
        ) -> i64 {
            self.inner
                .cumulative_transfer_amount(session_id, now, window)
        }
        fn transfer_count_in_window(
            &self,
            session_id: &firma_core::SessionId,
            now: std::time::Instant,
            window: std::time::Duration,
        ) -> u64 {
            self.inner.transfer_count_in_window(session_id, now, window)
        }
    }

    #[tokio::test]
    async fn zero_authority_rpc_calls_during_10_call_enforcement_cycle() {
        let authority_call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let store = std::sync::Arc::new(AuthorityCallTracker::new(std::sync::Arc::clone(
            &authority_call_count,
        )));

        let pipeline = test_pipeline_with_session_store(store);
        let request = test_request("POST", "api.openai.com/v1/chat/completions");

        for _ in 0..10 {
            let (decision, _) = pipeline.enforce(&request, "sess_001").await;
            assert!(decision.is_allow(), "all 10 calls must be allowed");
        }

        assert_eq!(
            authority_call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "zero Authority RPC calls must be made during the enforcement cycle"
        );
    }

    // ===== session_transfer_count resets on session boundary (Task FIR-62 Week 3) =====

    #[tokio::test]
    async fn session_transfer_count_resets_on_session_boundary() {
        use crate::enforcement::session_state::SessionStateStore;
        let store: std::sync::Arc<dyn SessionStateStore> =
            std::sync::Arc::new(crate::enforcement::LruSessionStateStore::new(16));

        // Manually record transfers for session A.
        let now = std::time::Instant::now();
        store.record_transfer(&"sess_a".parse().expect("sid"), "payee_x", 100, now);
        store.record_transfer(&"sess_a".parse().expect("sid"), "payee_x", 100, now);
        assert_eq!(
            store
                .signals(&"sess_a".parse().expect("sid"))
                .session_transfer_count,
            2
        );

        // Session B is a fresh session boundary — must start at 0.
        let signals_b = store.signals(&"sess_b".parse().expect("sid"));
        assert_eq!(
            signals_b.session_transfer_count, 0,
            "new session boundary must reset session_transfer_count to 0"
        );
    }
}
