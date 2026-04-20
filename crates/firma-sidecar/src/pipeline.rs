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

use firma_core::{DenyReason, ExecutionEnvelope, ExecutionMetadata, InjectedCredentials};

use crate::audit::AuditPayload;
use crate::authority_client::readiness::ReadinessView;
use crate::credential::{CredentialInjectionError, CredentialInjector};
use crate::enforcement::decision::EnforcementStage;
// Re-export public API for pipeline callers (test-only)
#[cfg(test)]
pub use crate::credential::NullCredentialInjector;
pub use crate::enforcement::capability_map::CapabilityMap;
pub use crate::enforcement::capability_validation::CapabilityValidator;
pub use crate::enforcement::constraint_enforcement::{ConstraintEnforcer, PolicyEvaluation};
pub use crate::enforcement::decision::EnforcementDecision;
pub use crate::enforcement::registry::ActionClassRegistry;
pub use crate::normalizer::{IntentNormalizer, MappingTable, RawRequest};

/// Proto wire values for the enforcement decision enum.
const DECISION_ALLOW: i32 = 1;
pub(crate) const DECISION_DENY: i32 = 2;
/// Proto wire value for the `ABORT` decision introduced by task 005
/// step 6. Emitted when the connector aborts an already-approved call
/// (currently only `CONNECTOR_TIMEOUT`).
pub(crate) const DECISION_ABORT: i32 = 3;

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
        }
    }

    /// Install a readiness view for Authority-backed runtime state.
    #[must_use]
    pub fn with_readiness(mut self, readiness: ReadinessView) -> Self {
        self.readiness = readiness;
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

        let decision = self.enforce_inner(request, session_id).await;
        let payload = audit_payload_from_decision(&decision, session_id, start.elapsed());

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

        // Credential injection: fetch credentials for the outbound
        // target. connector_id is the host portion of the resource.
        let connector_id = extract_host(envelope.intent().resource.as_str());
        let target = envelope.intent().resource.as_str();
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
}

/// Extracts an [`AuditPayload`] from an [`EnforcementDecision`].
///
/// This is a pure data extraction — no cryptography, no I/O. Designed
/// to run on the enforcement hot path with < 1µs overhead.
#[must_use]
pub fn audit_payload_from_decision(
    decision: &EnforcementDecision,
    session_id: &str,
    enforcement_latency: Duration,
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
            claims.token_id.clone(),
            claims.agent_id.clone(),
            envelope.intent().action_class.clone(),
            envelope.intent().resource.clone(),
            DECISION_ALLOW,
            String::new(),
            claims.context_hash.clone(),
            String::new(),
        ),
        EnforcementDecision::Deny {
            reason,
            detail,
            envelope,
            ..
        } => {
            let (action, resource) = envelope
                .as_ref()
                .map(|e| (e.intent.action_class.clone(), e.intent.resource.clone()))
                .unwrap_or_default();

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
            String::new(),
            String::new(),
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

/// Extracts the host portion from a resource string.
///
/// Resource format is `host/path` (no scheme). Returns the host part
/// before the first `/`, or the entire string if no `/` is present.
fn extract_host(resource: &str) -> &str {
    resource.split('/').next().unwrap_or(resource)
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
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
        })
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
            action_class: "llm.inference".to_string(),
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
            std::sync::Arc::new(NoRevocations),
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

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(DenyDeletePolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
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
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
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
            action_class: "llm.inference".to_string(),
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

    #[tokio::test]
    async fn test_enforce_revoked_token_denied_through_pipeline() {
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
            std::sync::Arc::new(RevokedStore),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
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
            action_class: "llm.inference".to_string(),
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
        // Token only allows llm.inference, but request maps to http.get
        let mut claims = test_claims();
        claims.action_set = vec!["llm.inference".to_string()]; // no http.get

        let rules = vec![MappingRuleConfig {
            method: Some("GET".to_string()),
            host: "api.example.com".to_string(),
            path: None,
            action_class: "http.get".to_string(),
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
        // Token selection fails because no token covers http.get
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
            std::sync::Arc::new(NoRevocations),
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

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(StalePolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
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
        assert_eq!(payload.token_id, "tok_001");
        assert_eq!(payload.agent_id, "agent_test");
        assert_eq!(payload.action, "llm.inference");
        assert!(payload.enforcement_latency_us >= 0);
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
    }

    #[tokio::test]
    async fn test_enforce_passthrough_emits_audit_event() {
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
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
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

        // Empty injector — no connectors configured
        let injector = crate::credential::provider::BasicCredentialInjector::empty();

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
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
}
