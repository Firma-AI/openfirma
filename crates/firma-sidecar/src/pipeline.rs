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

use firma_core::{ExecutionEnvelope, ExecutionMetadata};

// Re-export public API for pipeline callers
pub use crate::enforcement::capability_map::CapabilityMap;
pub use crate::enforcement::capability_validation::CapabilityValidator;
pub use crate::enforcement::constraint_enforcement::{ConstraintEnforcer, PolicyEvaluation};
pub use crate::enforcement::decision::EnforcementDecision;
pub use crate::enforcement::registry::ActionClassRegistry;
pub use crate::normalizer::{IntentNormalizer, MappingTable, RawRequest};

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
    capability_validator: CapabilityValidator,
    constraint_enforcer: ConstraintEnforcer,
}

impl EnforcementPipeline {
    /// Construct the pipeline with normalizer and both enforcement stages.
    /// Called once at startup.
    #[must_use]
    pub fn new(
        normalizer: IntentNormalizer,
        capability_validator: CapabilityValidator,
        constraint_enforcer: ConstraintEnforcer,
    ) -> Self {
        Self {
            normalizer,
            capability_validator,
            constraint_enforcer,
        }
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
    /// 4. On Allow: assemble a fully populated `ExecutionEnvelope` from
    ///    the normalized envelope + validated capability + session context.
    #[must_use]
    pub fn enforce(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision {
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

        // Constraint enforcement: scope check + Cedar policy evaluation
        if let Err(deny) = self
            .constraint_enforcer
            .evaluate(&normalized, &capability.claims)
        {
            return deny;
        }

        // All stages passed — assemble the fully populated envelope.
        let envelope = ExecutionEnvelope::new(
            normalized.intent,
            capability.raw_token,
            ExecutionMetadata {
                session_id: session_id.to_string(),
                agent_id: capability.claims.agent_id.clone(),
                timestamp: normalized.timestamp,
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        );

        EnforcementDecision::Allow {
            claims: capability.claims,
            envelope: Box::new(envelope),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
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

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );

        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer)
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

        if let EnforcementDecision::Allow { claims, envelope } = decision {
            assert_eq!(claims.agent_id, "agent_test");
            assert_eq!(envelope.metadata().agent_id, "agent_test");
            assert_eq!(envelope.metadata().session_id, "sess_001");
            assert!(
                !envelope.capability().is_empty(),
                "capability must be populated on Allow"
            );
            assert_eq!(envelope.intent().action_class, "llm.inference");
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

        let decision = pipeline.enforce(&request, "sess_001");
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

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

        let request = RawRequest {
            method: "GET".to_string(),
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
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

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.narrow".to_string(),
                claims: wide_claims.clone(),
            }]),
            Box::new(MockVerifier {
                claims: wide_claims,
            }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );

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

        let constraint_enforcer = ConstraintEnforcer::new(Box::new(DenyDeletePolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

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
    fn test_enforce_validation_failure_short_circuits_enforcement() {
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

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.bad".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(RejectingVerifier),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

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

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]), // empty!
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

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

        for _ in 0..100 {
            let decision = pipeline.enforce(&request, "sess_001");
            assert!(decision.is_deny());
            assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
        }
    }

    // ===== Policy bundle staleness =====

    #[test]
    fn test_enforce_allow_envelope_fields_complete() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{\"model\":\"gpt-4\"}".to_vec()),
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow { claims, envelope } = decision {
            // Verify intent fields
            assert_eq!(envelope.intent().action_class, "llm.inference");
            assert_eq!(
                envelope.intent().resource,
                "api.openai.com/v1/chat/completions"
            );
            assert_eq!(envelope.intent().raw_transport, "https");
            assert_eq!(
                envelope.intent().raw_action_ref,
                "POST /v1/chat/completions"
            );

            // Verify metadata fields
            assert_eq!(envelope.metadata().session_id, "sess_001");
            assert_eq!(envelope.metadata().agent_id, "agent_test");
            assert!(envelope.metadata().trace_id.is_none());
            assert!((envelope.metadata().budget_consumed - 0.0).abs() < f64::EPSILON);
            assert!(envelope.metadata().risk_score.is_none());

            // Verify provenance is None (V1 placeholder)
            assert!(envelope.provenance().is_none());

            // Verify capability token is populated
            assert!(!envelope.capability().is_empty());

            // Verify claims match
            assert_eq!(claims.token_id, "tok_001");
            assert_eq!(claims.agent_id, "agent_test");
        }
    }

    #[test]
    fn test_enforce_revoked_token_denied_through_pipeline() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];

        struct RevokedStore;
        impl firma_core::RevocationStore for RevokedStore {
            fn is_revoked(&self, _token_id: &str) -> Result<bool, firma_core::TokenError> {
                Ok(true)
            }
            fn add_revocation(&self, _: &str) -> Result<(), firma_core::TokenError> {
                Ok(())
            }
        }

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(RevokedStore),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

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
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenRevoked));
    }

    #[test]
    fn test_enforce_expired_token_denied_through_pipeline() {
        let mut claims = test_claims();
        claims.expiry = Utc::now() - chrono::Duration::hours(1);

        let rules = vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

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
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenExpired));
    }

    #[test]
    fn test_enforce_scope_violation_through_pipeline() {
        // Token only allows llm.inference, but request maps to http.get
        let mut claims = test_claims();
        claims.action_set = vec!["llm.inference".to_string()]; // no http.get

        let rules = vec![
            MappingRuleConfig {
                method: Some("GET".to_string()),
                host: "api.example.com".to_string(),
                path: None,
                action_class: "http.get".to_string(),
            },
        ];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

        let request = RawRequest {
            method: "GET".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let decision = pipeline.enforce(&request, "sess_001");
        // Token selection fails because no token covers http.get
        assert!(decision.is_deny());
    }

    #[test]
    fn test_enforce_sensitive_headers_stripped_in_allow() {
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

        let decision = pipeline.enforce(&request, "sess_001");
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

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
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

        let constraint_enforcer = ConstraintEnforcer::new(Box::new(StalePolicy));
        let pipeline =
            EnforcementPipeline::new(normalizer, capability_validator, constraint_enforcer);

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
