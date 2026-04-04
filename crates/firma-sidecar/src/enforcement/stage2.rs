use firma_core::{CapabilityClaims, DenyReason, ExecutionEnvelope};

use super::decision::{EnforcementDecision, EnforcementStage};

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

    /// Check if the policy bundle is still fresh (TTL not expired).
    fn is_fresh(&self) -> bool;

    /// Get the current policy bundle version.
    fn version(&self) -> Option<String>;
}

/// Stage 2: Cedar Policy Evaluation.
///
/// Performs scope check (action within token's allowed set), builds the
/// Cedar evaluation context, and evaluates policies. Fully local.
///
/// Target: < 200us p95.
pub struct Stage2Evaluator {
    policy: Box<dyn PolicyEvaluation>,
}

impl Stage2Evaluator {
    #[must_use]
    pub fn new(policy: Box<dyn PolicyEvaluation>) -> Self {
        Self { policy }
    }

    /// Evaluate the request against Cedar policies.
    ///
    /// Sequence:
    /// 1. Scope check -- is `action_class` in the token's `action_set`?
    /// 2. Check policy bundle freshness
    /// 3. Build Cedar context
    /// 4. Evaluate Cedar policies
    #[must_use]
    pub fn evaluate(
        &self,
        envelope: &ExecutionEnvelope,
        claims: &CapabilityClaims,
    ) -> EnforcementDecision {
        // Step 1: Scope check (pre-Cedar gate)
        if let Err(deny) = self.check_scope(envelope, claims) {
            return deny;
        }

        // Step 2: Check policy bundle freshness
        if !self.policy.is_fresh() {
            return EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleStale,
                stage: EnforcementStage::Stage2,
                detail: "policy bundle TTL expired".to_string(),
                envelope: Some(envelope.clone()),
            };
        }

        // Step 3: Build context
        let context = self.build_context(envelope, claims);

        // Step 4: Evaluate policies
        match self.policy.evaluate(
            &claims.agent_id,
            &envelope.intent.action_class,
            &envelope.intent.resource,
            &context,
        ) {
            Ok(true) => EnforcementDecision::Allow {
                claims: claims.clone(),
                envelope: envelope.clone(),
            },
            Ok(false) => EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::Stage2,
                detail: format!(
                    "policy denied action '{}' on resource '{}'",
                    envelope.intent.action_class, envelope.intent.resource
                ),
                envelope: Some(envelope.clone()),
            },
            Err(err) => EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::Stage2,
                detail: format!("policy evaluation error: {err}"),
                envelope: Some(envelope.clone()),
            },
        }
    }

    /// Scope check: verify `action_class` is in the token's allowed action set.
    /// Wildcard "*" in `action_set` means all actions are allowed.
    #[allow(clippy::unused_self)] // will use self when Cedar is integrated
    #[allow(clippy::result_large_err)]
    fn check_scope(
        &self,
        envelope: &ExecutionEnvelope,
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
            stage: EnforcementStage::Stage2,
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
        envelope: &ExecutionEnvelope,
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
    use firma_core::*;
    use std::collections::HashMap;

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

    fn test_envelope(action_class: &str) -> ExecutionEnvelope {
        ExecutionEnvelope {
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
            capability: "v4.public.test".to_string(),
            metadata: ExecutionMetadata {
                session_id: "sess_001".to_string(),
                agent_id: "agent_test".to_string(),
                timestamp: Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            provenance: None,
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
        let evaluator = Stage2Evaluator::new(Box::new(AllowAllPolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims);
        assert!(decision.is_allow());
    }

    #[test]
    fn test_deny_scope_violation() {
        let evaluator = Stage2Evaluator::new(Box::new(AllowAllPolicy));
        let envelope = test_envelope("file.delete");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims);
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_wildcard_scope_allows_all() {
        let evaluator = Stage2Evaluator::new(Box::new(AllowAllPolicy));
        let envelope = test_envelope("system.execute");
        let claims = test_claims(vec!["*"]);

        let decision = evaluator.evaluate(&envelope, &claims);
        assert!(decision.is_allow());
    }

    #[test]
    fn test_deny_when_policy_denies() {
        let evaluator = Stage2Evaluator::new(Box::new(DenyAllPolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims);
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[test]
    fn test_deny_when_bundle_stale() {
        let evaluator = Stage2Evaluator::new(Box::new(StalePolicy));
        let envelope = test_envelope("llm.inference");
        let claims = test_claims(vec!["llm.inference"]);

        let decision = evaluator.evaluate(&envelope, &claims);
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }
}
