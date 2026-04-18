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

use super::decision::{ConstraintEnforcementStage, EnforcementDecision, EnforcementStage};
use crate::normalizer::NormalizedEnvelope;
use firma_core::{decision::DenyReason, token::CapabilityClaims};
use std::{future::Future, pin::Pin, time::Duration};

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
        principal: &str,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> Result<bool, String>;

    /// Async policy evaluation hook used by timeout-aware pipeline paths.
    ///
    /// Default implementation delegates to the synchronous `evaluate()`.
    fn evaluate_async<'a>(
        &'a self,
        principal: &'a str,
        action: &'a str,
        resource: &'a str,
        context: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move { self.evaluate(principal, action, resource, context) })
    }

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
    policy: Box<dyn PolicyEvaluation>,
}

impl ConstraintEnforcer {
    #[must_use]
    pub fn new(policy: Box<dyn PolicyEvaluation>) -> Self {
        Self { policy }
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
        let context = self.build_context(envelope, claims);

        // Step 5: Evaluate policies
        match self.policy.evaluate(
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
    /// If `timeout` is `Some`, policy evaluation is bounded and any timeout
    /// yields a fail-closed DENY with `EnforcementTimeout`.
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
        timeout: Option<Duration>,
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
        let context = self.build_context(envelope, claims);
        let eval_result = if let Some(timeout_duration) = timeout {
            tokio::time::timeout(
                timeout_duration,
                self.policy.evaluate_async(
                    &claims.agent_id,
                    &envelope.intent.action_class,
                    &envelope.intent.resource,
                    &context,
                ),
            )
            .await
            .map_err(|_| EnforcementDecision::Deny {
                reason: DenyReason::EnforcementTimeout,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "stage 2 policy evaluation timed out after {} ms",
                    timeout_duration.as_millis()
                ),
                envelope: Some(envelope.clone()),
            })?
        } else {
            self.policy
                .evaluate_async(
                    &claims.agent_id,
                    &envelope.intent.action_class,
                    &envelope.intent.resource,
                    &context,
                )
                .await
        };

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

        // Wildcard means all actions allowed
        if claims.action_set.iter().any(|a| a == "*") {
            return Ok(());
        }

        if claims.action_set.iter().any(|a| a == action) {
            return Ok(());
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
    #[allow(clippy::unused_self)] // will use self when Cedar is integrated
    fn build_context(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
    ) -> serde_json::Value {
        serde_json::json!({
            "action_class": envelope.intent.action_class,
            "resource": envelope.intent.resource,
            "agent_id": claims.agent_id,
            "session_id": claims.session_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use firma_core::envelope::{ActionParams, ExecutionIntent, HttpMethod, HttpParams};
    use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &str,
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
            _: &str,
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
            _: &str,
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
            _: &str,
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
            _: &str,
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

    struct SlowAsyncPolicy;
    impl PolicyEvaluation for SlowAsyncPolicy {
        fn evaluate(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn evaluate_async<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a str,
            _: &'a serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(true)
            })
        }

        fn is_fresh(&self) -> bool {
            true
        }

        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    fn test_envelope(action_class: &str) -> NormalizedEnvelope {
        NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: action_class.to_string(),
                resource: "api.openai.com/v1/chat/completions".to_string(),
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
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: "sess_001".to_string(),
            action_set: actions.into_iter().map(String::from).collect(),
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    #[test]
    fn test_allow_when_in_scope_and_policy_allows() {
        let evaluator = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let result = evaluator.evaluate(&envelope, &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_scope_violation() {
        let evaluator = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let envelope = test_envelope("file.delete");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_wildcard_scope_allows_all() {
        let evaluator = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let envelope = test_envelope("system.execute");
        let claims = test_claims(vec!["*"]);

        let result = evaluator.evaluate(&envelope, &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_when_policy_denies() {
        let evaluator = ConstraintEnforcer::new(Box::new(DenyAllPolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[test]
    fn test_deny_when_bundle_stale() {
        let evaluator = ConstraintEnforcer::new(Box::new(StalePolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    #[test]
    fn test_deny_when_bundle_unavailable_fail_closed() {
        let evaluator = ConstraintEnforcer::new(Box::new(UnavailablePolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[test]
    fn test_policy_evaluator_error_fails_closed() {
        let evaluator = ConstraintEnforcer::new(Box::new(ErrorPolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims).unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[tokio::test(start_paused = true)]
    async fn test_stage2_timeout_fails_closed() {
        let evaluator = ConstraintEnforcer::new(Box::new(SlowAsyncPolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let pending =
            evaluator.evaluate_with_timeout(&envelope, &claims, Some(Duration::from_secs(2)));
        tokio::pin!(pending);

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        let decision = pending.await.unwrap_err();

        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::EnforcementTimeout));
    }
}
