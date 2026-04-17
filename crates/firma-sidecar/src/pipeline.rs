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

use firma_core::envelope::{ExecutionEnvelope, ExecutionMetadata};
use firma_core::session::SessionId;

// Re-export public API for pipeline callers
pub use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
pub use crate::enforcement::capability_validation::{CapabilityValidator, ValidatedCapability};
pub use crate::enforcement::cedar_evaluator::CedarPolicyEvaluator;
pub use crate::enforcement::config::{
    EnforcementConfig, MappingConfig, MappingRuleConfig, MappingRulesFile, Stage1Config,
    Stage2Config,
};
pub use crate::enforcement::constraint_enforcement::{ConstraintEnforcer, PolicyEvaluation};
pub use crate::enforcement::decision::{
    CapabilityValidationStage, ConstraintEnforcementStage, EnforcementDecision, EnforcementStage,
};
pub use crate::enforcement::registry::ActionClassRegistry;
pub use crate::normalizer::{IntentNormalizer, MappingTable, NormalizedEnvelope, RawRequest};

/// The enforcement pipeline. Orchestrates the full `enforce()` flow:
///
/// ```text
/// normalize → Stage 1 (select + validate token) → Stage 2 (Cedar eval) → assemble envelope
/// ```
///
/// Short-circuits on any DENY or PASSTHROUGH. Every code path returns
/// ALLOW, DENY, or PASSTHROUGH.
/// The pipeline is stateless per-request — all shared state is accessed
/// via references injected at construction time.
///
/// Target: < 3ms p95 end-to-end overhead.
pub struct EnforcementPipeline {
    normalizer: IntentNormalizer,
    stage1: CapabilityValidator,
    stage2: ConstraintEnforcer,
}

impl EnforcementPipeline {
    /// Construct the pipeline with normalizer and both enforcement stages.
    /// Called once at startup.
    #[must_use]
    pub fn new(
        normalizer: IntentNormalizer,
        stage1: CapabilityValidator,
        stage2: ConstraintEnforcer,
    ) -> Self {
        Self {
            normalizer,
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
    /// 1. Normalize intent: raw request → `NormalizedEnvelope`
    /// 2. Stage 1: select capability token, validate token → `ValidatedCapability`
    /// 3. Stage 2: scope check + Cedar policy evaluation
    /// 4. On Allow: assemble a fully populated `ExecutionEnvelope` from
    ///    the normalized envelope + validated capability + session context.
    #[must_use]
    pub fn enforce(&self, request: &RawRequest, session_id: SessionId) -> EnforcementDecision {
        // Normalize intent (may short-circuit with Deny or Passthrough)
        let normalized = match self.normalizer.normalize(request) {
            Ok(env) => env,
            Err(decision) => return decision,
        };

        // Stage 1: Select token → validate
        let capability = match self.stage1.enforce(&normalized, session_id.clone()) {
            Ok(cap) => cap,
            Err(deny) => return deny,
        };

        // Stage 2: Scope check + Cedar policy evaluation
        if let Err(deny) = self.stage2.evaluate(&normalized, &capability.claims) {
            return deny;
        }

        // All stages passed — assemble the fully populated envelope.
        let envelope = ExecutionEnvelope {
            intent: normalized.intent,
            capability: capability.raw_token,
            metadata: ExecutionMetadata {
                session_id,
                agent_id: capability.claims.agent_id.clone(),
                timestamp: normalized.timestamp,
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            provenance: None,
        };

        EnforcementDecision::Allow {
            claims: capability.claims,
            envelope: Box::new(envelope),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::enforcement::registry::ActionClassRegistry;
    use crate::normalizer::MappingTable;
    use chrono::Utc;
    use firma_core::agent::AgentId;
    use firma_core::decision::DenyReason;
    use firma_core::token::{
        CapabilityClaims, RevocationStore, TokenError, TokenId, TokenVerifier,
    };
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

    struct MockVerifier {
        claims: CapabilityClaims,
    }
    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Ok(self.claims.clone())
        }
    }

    fn test_entry(raw_token: &str, claims: CapabilityClaims) -> CapabilityEntry {
        CapabilityEntry::from_raw_token(raw_token, &MockVerifier { claims })
            .unwrap_or_else(|e| panic!("{e}"))
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
            token_id: TokenId::new(),
            agent_id: "agent_test".parse().unwrap(),
            session_id: "sess_001".parse().unwrap(),
            action_set: vec!["llm.inference".to_string(), "http.get".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    pub(crate) fn test_mapping_table(rules: &[MappingRuleConfig]) -> MappingTable {
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
                action_class: "llm.inference".to_string(),
            },
            MappingRuleConfig {
                method: Some("GET".to_string()),
                host: "*".to_string(),
                path: None,
                action_class: "http.get".to_string(),
            },
        ]
    }

    fn test_pipeline() -> EnforcementPipeline {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));

        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![test_entry("v4.public.test_token", claims.clone())]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
        );

        let stage2 = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        EnforcementPipeline::new(normalizer, stage1, stage2)
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

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow { claims, envelope } = decision {
            assert_eq!(claims.agent_id.as_ref(), "agent_test");
            assert_eq!(envelope.metadata.agent_id.as_ref(), "agent_test");
            assert_eq!(envelope.metadata.session_id.as_ref(), "sess_001");
            assert!(
                !envelope.capability.is_empty(),
                "capability must be populated on Allow"
            );
            assert_eq!(envelope.intent.action_class, "llm.inference");
        }
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

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
    }

    #[test]
    fn test_enforce_not_protected_returns_passthrough() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table_with_protection(&rules, false));

        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![test_entry("v4.public.test_token", claims.clone())]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
        );
        let stage2 = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(normalizer, stage1, stage2);

        let request = RawRequest {
            method: "GET".to_string(),
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
        assert!(
            decision.is_passthrough(),
            "non-protected traffic should passthrough, not deny"
        );
        assert!(!decision.is_deny());
        assert!(!decision.is_allow());
    }

    #[test]
    fn test_enforce_scope_violation() {
        let rules = vec![MappingRuleConfig {
            method: Some("DELETE".to_string()),
            host: "api.example.com".to_string(),
            path: Some("/data".to_string()),
            action_class: "http.delete".to_string(),
        }];

        let mut wide_claims = test_claims();
        wide_claims.action_set = vec!["*".to_string()];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![test_entry("v4.public.narrow", wide_claims.clone())]),
            Box::new(MockVerifier {
                claims: wide_claims,
            }),
            Box::new(NoRevocations),
        );

        struct DenyDeletePolicy;
        impl PolicyEvaluation for DenyDeletePolicy {
            fn evaluate(
                &self,
                _: &AgentId,
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

        let stage2 = ConstraintEnforcer::new(Box::new(DenyDeletePolicy));
        let pipeline = EnforcementPipeline::new(normalizer, stage1, stage2);

        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    // ===== Fail-closed discipline tests =====

    #[test]
    fn test_enforce_stage1_failure_short_circuits_stage2() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];

        struct RejectingVerifier;
        impl TokenVerifier for RejectingVerifier {
            fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
                Err(TokenError::SignatureInvalid {
                    reason: "forged".to_string(),
                })
            }
        }

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![test_entry("v4.public.bad", claims.clone())]),
            Box::new(RejectingVerifier),
            Box::new(NoRevocations),
        );
        let stage2 = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(normalizer, stage1, stage2);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
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

    #[test]
    fn test_enforce_no_capability_token_denies() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![]), // empty!
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
        );
        let stage2 = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(normalizer, stage1, stage2);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
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

        for _ in 0..100 {
            let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
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

        for _ in 0..100 {
            let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
            assert!(decision.is_deny());
            assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
        }
    }

    // ===== Policy bundle staleness =====

    #[test]
    fn test_enforce_stale_bundle_denies() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let stage1 = CapabilityValidator::new(
            CapabilityMap::new(vec![test_entry("v4.public.test", claims.clone())]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
        );

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

        let stage2 = ConstraintEnforcer::new(Box::new(StalePolicy));
        let pipeline = EnforcementPipeline::new(normalizer, stage1, stage2);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001".parse().unwrap());
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }
}

// ===== Roundtrip integration tests =====
//
// Authority signs a real PASETO v4 token → Sidecar Stage 1 verifies the Ed25519
// signature → Stage 2 CedarPolicyEvaluator evaluates the policy → Assert Allow.
//
// These tests exercise the full cryptographic and policy evaluation path without
// any mocking of the token layer.

#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::cedar_evaluator::CedarPolicyEvaluator;
    use crate::enforcement::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::registry::ActionClassRegistry;
    use crate::normalizer::MappingTable;
    use chrono::Utc;
    use firma_core::decision::DenyReason;
    use firma_core::policy::PolicyBundle;
    use firma_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
    use firma_core::token::{CapabilityClaims, RevocationStore, TokenError, TokenId, TokenSigner};
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;
    use std::collections::HashMap;

    struct NoRevocations;
    impl RevocationStore for NoRevocations {
        fn is_revoked(&self, _: &TokenId) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _: &TokenId) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
    }

    fn permit_all_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "roundtrip-v1".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            vec![],
            30,
        )
    }

    fn llm_inference_claims(session: &str) -> CapabilityClaims {
        let now = Utc::now();
        CapabilityClaims {
            token_id: TokenId::new(),
            agent_id: "agent_roundtrip".parse().unwrap(),
            session_id: session.parse().unwrap(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::hours(1),
            context_hash: "roundtrip-ctx-hash".to_string(),
        }
    }

    fn openai_pipeline(
        raw_token: &str,
        pk_bytes: &[u8],
        cedar_eval: CedarPolicyEvaluator,
    ) -> EnforcementPipeline {
        let verifier_for_map = PasetoV4Verifier::try_new(pk_bytes).unwrap();
        let verifier_for_stage1 = PasetoV4Verifier::try_new(pk_bytes).unwrap();

        let entry = CapabilityEntry::from_raw_token(raw_token, &verifier_for_map).unwrap();
        let capability_map = CapabilityMap::new(vec![entry]);

        let stage1 = CapabilityValidator::new(
            capability_map,
            Box::new(verifier_for_stage1),
            Box::new(NoRevocations),
        );
        let stage2 = ConstraintEnforcer::new(Box::new(cedar_eval));

        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];
        let registry = ActionClassRegistry::v0_1();
        let rules_file = MappingRulesFile { rules };
        let mapping_table = MappingTable::from_config(&rules_file, &registry, true)
            .unwrap_or_else(|e| panic!("{e}"));
        let normalizer = IntentNormalizer::new(mapping_table);

        EnforcementPipeline::new(normalizer, stage1, stage2)
    }

    #[test]
    fn authority_issues_sidecar_enforces_allow() {
        let (sk, pk) = generate_keypair();
        let claims = llm_inference_claims("sess_roundtrip");
        let expected_token_id = claims.token_id;

        // Authority side: sign a real PASETO v4 token.
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let raw_token = signer.sign(&claims).unwrap();
        assert!(raw_token.starts_with("v4.public."), "must be PASETO v4");

        // Sidecar Stage 2: Cedar permit-all policy.
        let cedar_eval = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();

        let pipeline = openai_pipeline(&raw_token, &pk, cedar_eval);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_roundtrip".parse().unwrap());
        assert!(decision.is_allow(), "roundtrip must ALLOW");

        if let EnforcementDecision::Allow {
            claims: verified,
            envelope,
        } = decision
        {
            assert_eq!(verified.agent_id.as_ref(), "agent_roundtrip");
            assert_eq!(verified.token_id, expected_token_id);
            assert_eq!(envelope.intent.action_class, "llm.inference");
            assert_eq!(envelope.metadata.agent_id.as_ref(), "agent_roundtrip");
        }
    }

    #[test]
    fn wrong_key_denied_at_stage1() {
        let (sk, pk) = generate_keypair();
        let (_sk2, pk2) = generate_keypair(); // different key pair

        let claims = llm_inference_claims("sess_wrongkey");

        // map_token signed by sk; the CapabilityMap accepts it (verified with pk).
        let map_token = PasetoV4Signer::try_new(&sk).unwrap().sign(&claims).unwrap();

        let cedar_eval = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();

        // Map insertion uses pk (correct key) — insertion succeeds.
        let verifier_for_map = PasetoV4Verifier::try_new(&pk).unwrap();
        let entry = CapabilityEntry::from_raw_token(&map_token, &verifier_for_map).unwrap();
        let capability_map = CapabilityMap::new(vec![entry]);

        // Stage1 verifier uses pk2 (wrong key) — map_token signed by sk fails verification.
        let stage1 = CapabilityValidator::new(
            capability_map,
            Box::new(PasetoV4Verifier::try_new(&pk2).unwrap()),
            Box::new(NoRevocations),
        );
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];
        let pipeline = EnforcementPipeline::new(
            IntentNormalizer::new(super::tests::test_mapping_table(&rules)),
            stage1,
            ConstraintEnforcer::new(Box::new(cedar_eval)),
        );

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_wrongkey".parse().unwrap());
        assert!(decision.is_deny(), "wrong key must DENY");
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    #[test]
    fn forbid_all_policy_denied_at_stage2() {
        let (sk, pk) = generate_keypair();
        let claims = llm_inference_claims("sess_forbid");
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let raw_token = signer.sign(&claims).unwrap();

        // Stage 2: Cedar forbid-all policy — valid token, policy denies.
        let forbid_bundle = PolicyBundle::new(
            "forbid-v1".to_string(),
            b"forbid(principal, action, resource);".to_vec(),
            vec![],
            30,
        );
        let cedar_eval = CedarPolicyEvaluator::from_bundle(&forbid_bundle).unwrap();
        let pipeline = openai_pipeline(&raw_token, &pk, cedar_eval);

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_forbid".parse().unwrap());
        assert!(decision.is_deny(), "forbid-all policy must DENY");
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }
}
