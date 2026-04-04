use super::capability_map::CapabilityMap;
use super::decision::EnforcementDecision;
use super::normalizer::{IntentNormalizer, RawRequest};
use super::stage1::Stage1Validator;
use super::stage2::Stage2Evaluator;

/// The enforcement pipeline. Orchestrates the full `enforce()` flow:
///
/// ```text
/// normalize → select token → Stage 1 (validate) → Stage 2 (Cedar eval)
/// ```
///
/// Short-circuits on any DENY. Every code path returns ALLOW or DENY.
/// The pipeline is stateless per-request — all shared state is accessed
/// via references injected at construction time.
///
/// Target: < 3ms p95 end-to-end overhead.
pub struct EnforcementPipeline {
    normalizer: IntentNormalizer,
    capability_map: CapabilityMap,
    stage1: Stage1Validator,
    stage2: Stage2Evaluator,
}

impl EnforcementPipeline {
    /// Construct the pipeline with all dependencies.
    /// Called once at startup.
    #[must_use]
    pub fn new(
        normalizer: IntentNormalizer,
        capability_map: CapabilityMap,
        stage1: Stage1Validator,
        stage2: Stage2Evaluator,
    ) -> Self {
        Self {
            normalizer,
            capability_map,
            stage1,
            stage2,
        }
    }

    /// Run the full enforcement pipeline.
    ///
    /// This is the ONLY public entry point for enforcement.
    /// Token is selected internally from the `CapabilityMap` (ADR-002).
    ///
    /// Pipeline stages:
    /// 1. Normalize intent: raw request -> `ExecutionEnvelope`
    /// 2. Select capability token from map by (`session_id`, `action_class`, resource)
    /// 3. Stage 1: validate selected token (parse, verify, expiry, revocation)
    /// 4. Stage 2: scope check + Cedar policy evaluation
    #[must_use]
    pub fn enforce(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision {
        // Step 1: Normalize intent
        let envelope = match self.normalizer.normalize(request) {
            Ok(env) => env,
            Err(deny) => return deny,
        };

        // Step 2: Select capability token from map (ADR-002)
        let entry = match self.capability_map.select(
            session_id,
            &envelope.intent.action_class,
            &envelope.intent.resource,
        ) {
            Ok(entry) => entry,
            Err(deny) => return deny,
        };

        // Step 3: Validate selected token (Stage 1)
        let claims = match self.stage1.validate(&entry.raw_token) {
            Ok(claims) => claims,
            Err(deny) => return deny,
        };

        // Step 4: Evaluate policy (Stage 2)
        self.stage2.evaluate(&envelope, &claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::capability_map::CapabilityEntry;
    use crate::enforcement::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::mapping::MappingTable;
    use crate::enforcement::registry::ActionClassRegistry;
    use crate::enforcement::stage2::PolicyEvaluation;
    use chrono::Utc;
    use firma_core::*;
    use std::collections::HashMap;
    use std::time::Duration;

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
        fn is_revoked(&self, _token_id: &str) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &str) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: "sess_001".to_string(),
            action_set: vec!["llm.inference".to_string(), "http.get".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_pipeline() -> EnforcementPipeline {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some("POST".to_string()),
                    host: "api.openai.com".to_string(),
                    path: Some("/v1/chat/completions".to_string()),
                    action_class: "llm.inference".to_string(),
                },
                MappingRuleConfig {
                    method: Some("GET".to_string()),
                    host: "*".to_string(),
                    path: None,
                    action_class: "http.get".to_string(),
                },
            ],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let claims = test_claims();
        let capability_map = CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.test_token".to_string(),
            claims: claims.clone(),
        }]);

        let stage1 = Stage1Validator::new(
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );

        let stage2 = Stage2Evaluator::new(Box::new(AllowAllPolicy));

        EnforcementPipeline::new(IntentNormalizer::new(table), capability_map, stage1, stage2)
    }

    #[test]
    fn test_enforce_happy_path() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_allow());
    }

    #[test]
    fn test_enforce_unclassified_intent() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
    }

    #[test]
    fn test_enforce_scope_violation() {
        // Create a pipeline with narrow token scope
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("DELETE".to_string()),
                host: "api.example.com".to_string(),
                path: Some("/data".to_string()),
                action_class: "http.delete".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        // Token only allows llm.inference, not http.delete
        let claims = CapabilityClaims {
            token_id: "tok_narrow".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: "sess_001".to_string(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        };

        // But the capability map has a wildcard token that matches http.delete
        let cap_claims = claims.clone();
        let mut wide_claims = cap_claims.clone();
        wide_claims.action_set = vec!["*".to_string()];

        let capability_map = CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.narrow".to_string(),
            claims: wide_claims.clone(),
        }]);

        let stage1 = Stage1Validator::new(
            Box::new(MockVerifier {
                claims: wide_claims,
            }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );

        // But the policy denies it
        struct DenyDeletePolicy;
        impl PolicyEvaluation for DenyDeletePolicy {
            fn evaluate(
                &self,
                _: &str,
                action: &str,
                _: &str,
                _: &serde_json::Value,
            ) -> Result<bool, String> {
                Ok(action != "http.delete")
            }
            fn is_fresh(&self) -> bool {
                true
            }
            fn version(&self) -> Option<String> {
                Some("test".to_string())
            }
        }

        let stage2 = Stage2Evaluator::new(Box::new(DenyDeletePolicy));
        let pipeline =
            EnforcementPipeline::new(IntentNormalizer::new(table), capability_map, stage1, stage2);

        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    // ===== Fail-closed discipline tests =====

    #[test]
    fn test_enforce_stage1_failure_short_circuits_stage2() {
        // Stage 1 always fails → Stage 2 should never run
        // If Stage 2 ran, it would allow (AllowAllPolicy), so DENY proves short-circuit
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let claims = test_claims();
        let capability_map = CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.bad".to_string(),
            claims: claims.clone(),
        }]);

        // Stage 1 always rejects
        struct RejectingVerifier;
        impl TokenVerifier for RejectingVerifier {
            fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
                Err(TokenError::SignatureInvalid {
                    reason: "forged".to_string(),
                })
            }
        }

        let stage1 = Stage1Validator::new(
            Box::new(RejectingVerifier),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let stage2 = Stage2Evaluator::new(Box::new(AllowAllPolicy));

        let pipeline =
            EnforcementPipeline::new(IntentNormalizer::new(table), capability_map, stage1, stage2);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
        assert_eq!(
            decision.stage(),
            Some(crate::enforcement::decision::EnforcementStage::Stage1)
        );
    }

    #[test]
    fn test_enforce_no_capability_token_denies() {
        // Empty capability map → no token for the action → DENY
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let capability_map = CapabilityMap::new(vec![]); // empty!

        let claims = test_claims();
        let stage1 = Stage1Validator::new(
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let stage2 = Stage2Evaluator::new(Box::new(AllowAllPolicy));

        let pipeline =
            EnforcementPipeline::new(IntentNormalizer::new(table), capability_map, stage1, stage2);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    // ===== Determinism test =====

    #[test]
    fn test_enforce_deterministic_same_input_same_output() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        // Run 100 times — must always be ALLOW
        for _ in 0..100 {
            let decision = pipeline.enforce(&request, "sess_001");
            assert!(
                decision.is_allow(),
                "non-deterministic: got DENY on repeated call"
            );
        }
    }

    #[test]
    fn test_enforce_deterministic_deny_same_input() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        // Run 100 times — must always be DENY with same reason
        for _ in 0..100 {
            let decision = pipeline.enforce(&request, "sess_001");
            assert!(decision.is_deny());
            assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
        }
    }

    // ===== Policy bundle staleness =====

    #[test]
    fn test_enforce_stale_bundle_denies() {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let claims = test_claims();
        let capability_map = CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.test".to_string(),
            claims: claims.clone(),
        }]);

        let stage1 = Stage1Validator::new(
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );

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

        let stage2 = Stage2Evaluator::new(Box::new(StalePolicy));
        let pipeline =
            EnforcementPipeline::new(IntentNormalizer::new(table), capability_map, stage1, stage2);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }
}
