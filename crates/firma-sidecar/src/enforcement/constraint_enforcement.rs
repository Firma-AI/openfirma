//! Stage 2 — Constraint Enforcement Engine (CEE).
//!
//! Second enforcement phase. The semantic layer where Cedar policies and
//! quantitative constraints are evaluated. Operates on a previously normalized
//! `ExecutionEnvelope` produced by Stage 1 — it must not infer the canonical
//! action class from raw transport-specific input.
//!
//! Steps:
//! 1. **Scope check** — verifies that the requested `action_class` is within
//!    the token's allowed `action_set`. Wildcard `"*"` permits all actions.
//! 2. **Policy bundle freshness** — if the bundle TTL has expired without a
//!    successful refresh, the Sidecar enters fail-closed mode and denies all
//!    new requests.
//! 3. **Context build** — assembles the Cedar request context from envelope
//!    fields, claims, and runtime signals (budget consumed, risk score).
//! 4. **Cedar eval** — evaluates against the current policy bundle.
//!    Deterministic: same context + same bundle = same decision. Fully local,
//!    no external calls.
//!
//! Target latency: < 200 µs p95.
//!
//! # Security properties
//!
//! Stage 2 prevents valid capabilities from being misused for out-of-policy,
//! over-budget, or contextually disallowed actions:
//! - **Privilege escalation within token** — a valid token does not imply all
//!   calls are allowed; Cedar eval checks the specific call against policy.
//! - **Scope misuse at runtime** — a valid capability for action class X
//!   cannot be used for action class Y.
//! - **Budget overrun / quota abuse** — pre-computed `budget_remaining`
//!   attribute checked against threshold.
//! - **Non-deterministic authorization** — same context + same bundle always
//!   produces the same decision.

use std::sync::Arc;
use std::time::Duration;

use firma_core::token::matches_resource_scope;
use firma_core::{AgentId, CapabilityClaims, DenyReason};

use super::decision::{ConstraintEnforcementStage, EnforcementDecision, EnforcementStage};
use crate::enforcement::session_state::RuntimeSignals;
use crate::normalizer::NormalizedEnvelope;

/// Trait for policy evaluation — abstracts Cedar or any other policy engine.
///
/// The sidecar uses this trait rather than firma-core's `PolicyEvaluator`
/// because it needs a richer context (three-layer attributes). The concrete
/// Cedar implementation will be provided when unit 003 is built.
pub trait PolicyEvaluation: Send + Sync {
    /// Evaluate policy against the given context attributes.
    /// Returns true for ALLOW, false for DENY.
    ///
    /// # Errors
    ///
    /// Returns an error string if policy evaluation fails (e.g., malformed
    /// context or engine error).
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, String>;

    /// Check if the policy bundle is still fresh (TTL not expired).
    fn is_fresh(&self) -> bool;

    /// Check if a policy bundle is currently available.
    ///
    /// Default assumes availability, preserving backwards compatibility for
    /// evaluators that only model freshness.
    fn is_available(&self) -> bool {
        true
    }

    /// Get the current policy bundle version.
    fn version(&self) -> Option<String>;
}


/// Stage 2: Constraint Enforcement Engine (CEE).
///
/// Performs scope check (action within token's allowed set), builds the
/// Cedar evaluation context, and evaluates policies. Fully local.
///
/// Target: < 200us p95.
pub struct ConstraintEnforcer {
    policy: Arc<dyn PolicyEvaluation>,
}

impl ConstraintEnforcer {
    #[must_use]
    pub fn new(policy: Arc<dyn PolicyEvaluation>) -> Self {
        Self { policy }
    }

    /// Return the active policy bundle version, if one has been installed.
    #[must_use]
    pub fn policy_version(&self) -> Option<String> {
        self.policy.version()
    }

    /// Evaluate the request against Cedar policies.
    ///
    /// Returns `Ok(())` if the request passes all checks, or
    /// `Err(EnforcementDecision::Deny)` if any check fails.
    /// The pipeline is responsible for constructing the `Allow` decision
    /// with a fully populated `ExecutionEnvelope`.
    ///
    /// Sequence:
    /// 1. Scope check -- is `action_class` in the token's `action_set`?
    /// 2. Check policy availability
    /// 3. Check policy bundle freshness
    /// 4. Build Cedar context
    /// 5. Evaluate Cedar policies
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if scope check, bundle freshness,
    /// or Cedar policy evaluation fails.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    pub fn evaluate(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
        signals: &RuntimeSignals,
    ) -> Result<(), EnforcementDecision> {
        // Step 1: Scope check (pre-Cedar gate)
        self.check_scope(envelope, claims)?;

        // Step 2: Check policy availability (fail-closed)
        if !self.policy.is_available() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable; failing closed".to_string(),
                envelope: Some(envelope.clone()),
            });
        }

        // Step 3: Check policy bundle freshness
        if !self.policy.is_fresh() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleStale,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable or stale".to_string(),
                envelope: Some(envelope.clone()),
            });
        }

        // Step 4: Build context
        let context = self.build_context(envelope, claims, signals);

        // Step 5: Evaluate policies
        let resource_display = envelope.intent.resource_display();
        match self.policy.evaluate(
            &claims.agent_id,
            &envelope.intent.action_class,
            &resource_display,
            &context,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "policy denied action '{}' on resource '{}'",
                    envelope.intent.action_class, resource_display
                ),
                envelope: Some(envelope.clone()),
            }),
            Err(err) => Err(EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("policy evaluation failed; failing closed: {err}"),
                envelope: Some(envelope.clone()),
            }),
        }
    }

    /// Timeout-aware Stage 2 evaluation.
    ///
    /// Policy evaluation is bounded and any timeout yields a fail-closed DENY
    /// with `EnforcementTimeout`.
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if scope validation fails, the
    /// policy bundle is unavailable (`FailClosed`) or stale
    /// (`PolicyBundleStale`), policy evaluation times out
    /// (`EnforcementTimeout`), or the policy evaluator returns an error
    /// (`FailClosed`).
    #[allow(clippy::result_large_err)]
    pub async fn evaluate_with_timeout(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
        signals: &RuntimeSignals,
        timeout: Duration,
    ) -> Result<(), EnforcementDecision> {
        // Step 1: Scope check (pre-Cedar gate)
        self.check_scope(envelope, claims)?;

        // Step 2: Check policy availability (fail-closed)
        if !self.policy.is_available() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable; failing closed".to_string(),
                envelope: Some(envelope.clone()),
            });
        }

        // Step 3: Deny stale policy bundle
        if !self.policy.is_fresh() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleStale,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable or stale".to_string(),
                envelope: Some(envelope.clone()),
            });
        }

        // Step 4: Build context from immutable request + validated claims.
        let context = self.build_context(envelope, claims, signals);
        let policy = Arc::clone(&self.policy);
        let principal = claims.agent_id.clone();
        let action = envelope.intent.action_class.clone();
        let resource = envelope.intent.resource_display();
        let eval_task = tokio::task::spawn_blocking(move || {
            policy.evaluate(&principal, &action, &resource, &context)
        });

        let eval_result = tokio::time::timeout(timeout, eval_task)
            .await
            .map_err(|_| EnforcementDecision::Deny {
                reason: DenyReason::EnforcementTimeout,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "stage 2 policy evaluation timed out after {} ms",
                    timeout.as_millis()
                ),
                envelope: Some(envelope.clone()),
            })?
            .map_err(|join_err| EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("policy evaluation task failed; failing closed: {join_err}"),
                envelope: Some(envelope.clone()),
            })?;

        match eval_result {
            Ok(true) => Ok(()),
            Ok(false) => Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "policy denied action '{}' on resource '{}'",
                    envelope.intent.action_class,
                    envelope.intent.resource_display()
                ),
                envelope: Some(envelope.clone()),
            }),
            Err(err) => Err(EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("policy evaluation failed; failing closed: {err}"),
                envelope: Some(envelope.clone()),
            }),
        }
    }

    /// Scope check: verify `action_class` is in the token's allowed action set.
    /// Wildcard "*" in `action_set` means all actions are allowed.
    #[expect(clippy::unused_self, reason = "will use self when Cedar is integrated")]
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    fn check_scope(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
    ) -> Result<(), EnforcementDecision> {
        let action = &envelope.intent.action_class;
        let resource = envelope.intent.resource_display();

        if claims.action_set.iter().any(|a| a == "*") {
            if matches_resource_scope(&claims.resource_scope, &resource) {
                return Ok(());
            }
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::ScopeViolation,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::ScopeCheck,
                ),
                detail: format!(
                    "resource '{}' not in token's scope '{}'",
                    resource, claims.resource_scope
                ),
                envelope: Some(envelope.clone()),
            });
        }

        if claims.action_set.iter().any(|a| a == action) {
            if matches_resource_scope(&claims.resource_scope, &resource) {
                return Ok(());
            }
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::ScopeViolation,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::ScopeCheck,
                ),
                detail: format!(
                    "resource '{}' not in token's scope '{}'",
                    resource, claims.resource_scope
                ),
                envelope: Some(envelope.clone()),
            });
        }

        Err(EnforcementDecision::Deny {
            reason: DenyReason::ScopeViolation,
            stage: EnforcementStage::ConstraintEnforcement(ConstraintEnforcementStage::ScopeCheck),
            detail: format!(
                "action '{}' not in token's allowed set: {:?}",
                action, claims.action_set
            ),
            envelope: Some(envelope.clone()),
        })
    }

    /// Build the Cedar evaluation context from envelope + claims + runtime signals.
    ///
    /// Emits the shape declared by `EnforcementContext` in the canonical
    /// `schema.cedarschema`. `action_class`, `resource`, and `agent_id` are
    /// not in the context — they are passed to Cedar as principal/action/
    /// resource entity UIDs.
    #[expect(clippy::unused_self, reason = "reserved for future stateful hooks")]
    fn build_context(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
        signals: &RuntimeSignals,
    ) -> serde_json::Value {
        let session_duration_s = (envelope.timestamp - claims.issued_at).num_seconds().max(0);
        let timestamp_ms = envelope.timestamp.timestamp_millis();
        let params = serde_json::to_string(&envelope.intent.params).unwrap_or_else(|_| "{}".into());
        serde_json::json!({
            "session_id": claims.session_id,
            "timestamp_ms": timestamp_ms,
            "params": params,
            "risk_score": signals.risk_score_long(),
            "budget_remaining": signals.budget_remaining_long(claims.budget_ceiling),
            "session_duration_s": session_duration_s,
            "action_count": i64::try_from(signals.action_count).unwrap_or(i64::MAX),
        })
    }
}


#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::enforcement::session_state::RuntimeSignals;
    use chrono::Utc;
    use firma_core::*;
    use std::collections::HashMap;

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

    struct DenyAllPolicy;
    impl PolicyEvaluation for DenyAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(false)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    struct ErrorPolicy;
    impl PolicyEvaluation for ErrorPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Err("evaluation backend error".to_string())
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

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

    struct UnavailablePolicy;
    impl PolicyEvaluation for UnavailablePolicy {
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
        fn is_available(&self) -> bool {
            false
        }
        fn version(&self) -> Option<String> {
            None
        }
    }

    struct SlowPolicy;
    impl PolicyEvaluation for SlowPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            std::thread::sleep(Duration::from_millis(200));
            Ok(true)
        }

        fn is_fresh(&self) -> bool {
            true
        }

        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    fn test_envelope(action_class: &str) -> NormalizedEnvelope {
        test_envelope_with_resource(action_class, "api.openai.com/v1/chat/completions")
    }

    fn test_envelope_with_resource(action_class: &str, resource: &str) -> NormalizedEnvelope {
        NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: action_class.to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from(resource),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::POST,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat/completions".to_string(),
            },
            timestamp: Utc::now(),
        }
    }

    fn test_claims(actions: Vec<&str>) -> CapabilityClaims {
        test_claims_with_scope(actions, "*")
    }

    fn test_claims_with_scope(actions: Vec<&str>, resource_scope: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "sess_001".parse().expect("literal session id"),
            action_set: actions.into_iter().map(String::from).collect(),
            resource_scope: resource_scope.to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    fn test_signals() -> RuntimeSignals {
        RuntimeSignals {
            action_count: 1,
            budget_consumed: 0.0,
            risk_score: 0.0,
        }
    }

    #[test]
    fn test_allow_when_in_scope_and_policy_allows() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_scope_violation() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.delete");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_wildcard_scope_allows_all() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("system.execute");
        let claims = test_claims(vec!["*"]);

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_when_policy_denies() {
        let evaluator = ConstraintEnforcer::new(Arc::new(DenyAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[test]
    fn test_deny_when_bundle_stale() {
        let evaluator = ConstraintEnforcer::new(Arc::new(StalePolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    #[test]
    fn test_deny_when_bundle_unavailable_fail_closed() {
        let evaluator = ConstraintEnforcer::new(Arc::new(UnavailablePolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[test]
    fn test_scope_check_multiple_actions_in_set() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.read");
        let claims = test_claims(vec![
            "communication.external.send",
            "filesystem.read",
            "credential.read",
        ]);

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_scope_check_empty_action_set_denies() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec![]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_build_context_includes_required_fields() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let mut claims = test_claims(vec!["communication.external.send"]);
        claims.issued_at = envelope.timestamp - chrono::Duration::seconds(42);
        claims.budget_ceiling = Some(100.0);
        let signals = RuntimeSignals {
            action_count: 7,
            budget_consumed: 12.75,
            risk_score: 3.0,
        };

        let context = evaluator.build_context(&envelope, &claims, &signals);

        // Canonical schema fields (7 total):
        assert_eq!(context["session_id"], "sess_001");
        assert!(context["timestamp_ms"].is_i64());
        assert!(context["params"].is_string());
        assert_eq!(context["risk_score"], serde_json::json!(3));
        assert_eq!(context["budget_remaining"], serde_json::json!(87));
        assert_eq!(context["session_duration_s"], serde_json::json!(42));
        assert_eq!(context["action_count"], serde_json::json!(7));

        // Schema does not declare action_class / resource / agent_id /
        // timestamp — they are passed as Cedar principal/action/resource
        // entity UIDs, not context attributes.
        assert!(context.get("action_class").is_none());
        assert!(context.get("resource").is_none());
        assert!(context.get("agent_id").is_none());
        assert!(context.get("timestamp").is_none());
    }

    #[test]
    fn test_build_context_budget_remaining_unbounded_when_ceiling_none() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);
        let signals = RuntimeSignals {
            action_count: 1,
            budget_consumed: 0.0,
            risk_score: 0.0,
        };
        let context = evaluator.build_context(&envelope, &claims, &signals);
        assert_eq!(context["budget_remaining"], serde_json::json!(i64::MAX));
    }

    #[test]
    fn test_build_context_negative_session_duration_clamped_to_zero() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let mut claims = test_claims(vec!["communication.external.send"]);
        // Token issued AFTER request timestamp (clock skew edge case).
        claims.issued_at = envelope.timestamp + chrono::Duration::seconds(10);
        let signals = RuntimeSignals {
            action_count: 1,
            budget_consumed: 0.0,
            risk_score: 0.0,
        };
        let context = evaluator.build_context(&envelope, &claims, &signals);
        assert_eq!(context["session_duration_s"], serde_json::json!(0));
    }

    #[test]
    fn test_stale_bundle_short_circuits_before_policy_eval() {
        // Even if policy would allow, staleness must deny first
        struct StaleButAllowPolicy;
        impl PolicyEvaluation for StaleButAllowPolicy {
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

        let evaluator = ConstraintEnforcer::new(Arc::new(StaleButAllowPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::BundleFreshness
            ))
        );
    }

    #[test]
    fn test_scope_violation_reports_correct_stage() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.delete");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::ScopeCheck
            ))
        );
    }

    #[test]
    fn test_policy_deny_reports_correct_stage() {
        let evaluator = ConstraintEnforcer::new(Arc::new(DenyAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::PolicyEvaluation
            ))
        );
    }

    #[test]
    fn test_policy_evaluator_error_fails_closed() {
        let evaluator = ConstraintEnforcer::new(Arc::new(ErrorPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_stage2_timeout_fails_closed() {
        use std::time::Duration;
        let evaluator = ConstraintEnforcer::new(Arc::new(SlowPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate_with_timeout(
                &envelope,
                &claims,
                &test_signals(),
                Duration::from_millis(20),
            )
            .await
            .unwrap_err();

        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::EnforcementTimeout));
    }

    #[test]
    fn test_resource_scope_prefix_allows_matching_resource() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims =
            test_claims_with_scope(vec!["communication.external.send"], "api.openai.com/*");

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_scope_exact_match_allows() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims = test_claims_with_scope(
            vec!["communication.external.send"],
            "api.openai.com/v1/chat/completions",
        );

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_scope_denies_different_host() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope =
            test_envelope_with_resource("communication.external.send", "other.example.com/v1/data");
        let claims =
            test_claims_with_scope(vec!["communication.external.send"], "api.openai.com/*");

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_resource_scope_denies_subpath_mismatch() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims = test_claims_with_scope(
            vec!["communication.external.send"],
            "api.openai.com/v1/files",
        );

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_resource_scope_wildcard_action_denied_by_resource_scope() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource("system.execute", "other.example.com/anything");
        let claims = test_claims_with_scope(vec!["*"], "api.openai.com/*");

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }
}
