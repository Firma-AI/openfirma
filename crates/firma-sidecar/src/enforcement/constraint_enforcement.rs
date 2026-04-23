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

use super::cedar_evaluator::CedarEvaluatorError;
use super::decision::{ConstraintEnforcementStage, EnforcementDecision, EnforcementStage};
use crate::normalizer::NormalizedEnvelope;
use firma_core::{
    agent::AgentId,
    decision::DenyReason,
    token::{CapabilityClaims, matches_resource_scope},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

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
    /// Returns a [`CedarEvaluatorError`] if policy evaluation fails (e.g.,
    /// malformed entity UIDs, invalid context, or request schema violation).
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError>;

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

/// Sentinel evaluator installed in the watch channel at sidecar boot, before
/// the Authority delivers the first [`PolicyBundle`].
///
/// `is_available()` returns `false`, so every evaluation attempt hits the
/// existing availability check and fails closed as
/// [`DenyReason::PolicyBundleStale`].  The bundle consumer task replaces
/// this sentinel with a real [`CedarPolicyEvaluator`] on first delivery.
#[allow(dead_code)] // used by the bundle consumer task (not yet wired)
struct NoBundleInstalled;

impl PolicyEvaluation for NoBundleInstalled {
    fn evaluate(
        &self,
        _: &AgentId,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<bool, super::cedar_evaluator::CedarEvaluatorError> {
        Ok(false)
    }

    fn is_fresh(&self) -> bool {
        false
    }

    fn is_available(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        None
    }
}

/// Stage 2: Constraint Enforcement Engine (CEE).
///
/// Performs scope check (action within token's allowed set), builds the
/// Cedar evaluation context, and evaluates policies. Fully local.
///
/// Target: < 200us p95.
///
/// The active evaluator is read from a [`tokio::sync::watch`] channel.
/// The channel `Sender` is held by the bundle consumer task, which calls
/// `tx.send_replace(Arc::new(evaluator))` whenever the Authority streams a
/// new [`PolicyBundle`].  Before the first bundle arrives the channel holds
/// a [`NoBundleInstalled`] sentinel whose `is_available()` returns `false`,
/// causing every evaluation to fail closed as
/// [`DenyReason::PolicyBundleStale`].  Hot-path readers call
/// `self.policy.borrow()` — a momentary read-lock that never blocks the
/// writer.
pub struct ConstraintEnforcer {
    policy: watch::Receiver<Arc<dyn PolicyEvaluation>>,
}

impl ConstraintEnforcer {
    /// Construct with an externally owned [`watch::Receiver`].
    ///
    /// The matching [`watch::Sender`] is held by the bundle consumer task.
    /// Seed the channel with `Arc::new(NoBundleInstalled)` at boot so
    /// evaluations fail closed until the first real bundle is installed.
    /// Use [`watch::channel`] directly to create the pair.
    #[must_use]
    pub fn new(policy: watch::Receiver<Arc<dyn PolicyEvaluation>>) -> Self {
        Self { policy }
    }

    /// Construct with a fixed evaluator — no hot-swap.
    ///
    /// Creates an internal watch channel and immediately drops the sender.
    /// The snapshot is readable for the lifetime of the enforcer.
    ///
    /// Use this for static-policy deployments and in tests.
    #[must_use]
    pub fn fixed(policy: impl PolicyEvaluation + 'static) -> Self {
        let (_, rx) = watch::channel(Arc::new(policy) as Arc<dyn PolicyEvaluation>);
        Self { policy: rx }
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
    #[allow(clippy::result_large_err)]
    pub fn evaluate(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
    ) -> Result<(), EnforcementDecision> {
        // Step 1: Scope check (pre-Cedar gate)
        self.check_scope(envelope, claims)?;

        // Borrow the active snapshot once; all checks in this call see the
        // same evaluator version.  The borrow holds a short read-lock that
        // does not block concurrent writers.
        let policy = self.policy.borrow();

        // Step 2: Check policy availability (fail-closed)
        if !policy.is_available() {
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
        if !policy.is_fresh() {
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
        let context = Self::build_context(envelope, claims);

        // Step 5: Evaluate policies
        match policy.evaluate(
            &claims.agent_id,
            &envelope.intent.action_class,
            &envelope.intent.resource,
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
                    envelope.intent.action_class, envelope.intent.resource
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
        timeout: Duration,
    ) -> Result<(), EnforcementDecision> {
        // Step 1: Scope check (pre-Cedar gate)
        self.check_scope(envelope, claims)?;

        // Clone the Arc from a momentary borrow so it can be moved into
        // spawn_blocking without holding the read-lock across the await.
        let policy = Arc::clone(&*self.policy.borrow());

        // Step 2: Check policy availability (fail-closed)
        if !policy.is_available() {
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
        if !policy.is_fresh() {
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
        let context = Self::build_context(envelope, claims);
        let principal = claims.agent_id.clone();
        let action = envelope.intent.action_class.clone();
        let resource = envelope.intent.resource.clone();
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
                    envelope.intent.action_class, envelope.intent.resource
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
    #[allow(clippy::unused_self)] // will use self when Cedar is integrated
    #[allow(clippy::result_large_err)]
    fn check_scope(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
    ) -> Result<(), EnforcementDecision> {
        let action = &envelope.intent.action_class;
        let resource = &envelope.intent.resource;

        if claims.action_set.iter().any(|a| a == "*") {
            if matches_resource_scope(&claims.resource_scope, resource) {
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
            if matches_resource_scope(&claims.resource_scope, resource) {
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

    /// Build the Cedar evaluation context from envelope + claims.
    ///
    /// Produces exactly the `EnforcementContext` record declared in
    /// `firma.cedarschema`:
    /// - `session_id`   — enclosing session identity
    /// - `timestamp_ms` — Unix epoch milliseconds at evaluation time (Long)
    /// - `params`       — JSON-serialized `intent.params` (available to Cedar `when` clauses)
    /// - `risk_score`   — V1 placeholder, always 0 (Long)
    fn build_context(
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
    ) -> serde_json::Value {
        let params =
            serde_json::to_string(&envelope.intent.params).unwrap_or_else(|_| "{}".to_string());
        serde_json::json!({
            "session_id": claims.session_id,
            "timestamp_ms": envelope.timestamp.timestamp_millis(),
            "params": params,
            "risk_score": 0i64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use firma_core::envelope::{ActionParams, ExecutionIntent, HttpMethod, HttpParams};
    use firma_core::token::TokenId;
    use std::{collections::HashMap, time::Duration};

    use crate::enforcement::cedar_evaluator::CedarEvaluatorError;

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, CedarEvaluatorError> {
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
        ) -> Result<bool, CedarEvaluatorError> {
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
        ) -> Result<bool, CedarEvaluatorError> {
            Err(CedarEvaluatorError::RequestBuild(Box::new(
                std::io::Error::other("evaluation backend error"),
            )))
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
        ) -> Result<bool, CedarEvaluatorError> {
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
        ) -> Result<bool, CedarEvaluatorError> {
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
        ) -> Result<bool, CedarEvaluatorError> {
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
                resource: resource.to_string(),
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
            token_id: TokenId::new(),
            agent_id: "agent_test".parse().unwrap(),
            session_id: "sess_001".parse().unwrap(),
            action_set: actions.into_iter().map(String::from).collect(),
            resource_scope: resource_scope.to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    #[test]
    fn test_allow_when_in_scope_and_policy_allows() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let result = evaluator.evaluate(&envelope, &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_scope_violation() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope("filesystem.delete");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_wildcard_scope_allows_all() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope("system.execute");
        let claims = test_claims(vec!["*"]);

        let result = evaluator.evaluate(&envelope, &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_when_policy_denies() {
        let evaluator = ConstraintEnforcer::fixed(DenyAllPolicy);
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[test]
    fn test_deny_when_bundle_stale() {
        let evaluator = ConstraintEnforcer::fixed(StalePolicy);
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    #[test]
    fn test_deny_when_bundle_unavailable_fail_closed() {
        let evaluator = ConstraintEnforcer::fixed(UnavailablePolicy);
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[test]
    fn test_policy_evaluator_error_fails_closed() {
        let evaluator = ConstraintEnforcer::fixed(ErrorPolicy);
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_stage2_timeout_fails_closed() {
        let evaluator = ConstraintEnforcer::fixed(SlowPolicy);
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate_with_timeout(&envelope, &claims, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::EnforcementTimeout));
    }

    #[test]
    fn test_resource_scope_prefix_allows_matching_resource() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims =
            test_claims_with_scope(vec!["communication.external.send"], "api.openai.com/*");

        let result = evaluator.evaluate(&envelope, &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_scope_exact_match_allows() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims = test_claims_with_scope(
            vec!["communication.external.send"],
            "api.openai.com/v1/chat/completions",
        );

        let result = evaluator.evaluate(&envelope, &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_scope_denies_different_host() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope =
            test_envelope_with_resource("communication.external.send", "other.example.com/v1/data");
        let claims =
            test_claims_with_scope(vec!["communication.external.send"], "api.openai.com/*");

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_resource_scope_denies_subpath_mismatch() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims = test_claims_with_scope(
            vec!["communication.external.send"],
            "api.openai.com/v1/files",
        );

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_resource_scope_wildcard_action_denied_by_resource_scope() {
        let evaluator = ConstraintEnforcer::fixed(AllowAllPolicy);
        let envelope = test_envelope_with_resource("system.execute", "other.example.com/anything");
        let claims = test_claims_with_scope(vec!["*"], "api.openai.com/*");

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }
}
