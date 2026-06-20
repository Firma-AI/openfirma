//! End-to-end pipeline bench. Target: p95 < 3 ms.

#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use firma_core::{CapabilityClaims, RevocationStore, TokenError, TokenId, TokenVerifier};
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::credential::NullCredentialInjector;
use firma_sidecar::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
use firma_sidecar::enforcement::capability_validation::CapabilityValidator;
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::constraint_enforcement::ConstraintEnforcer;
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::enforcement::session_state::LruSessionStateStore;
use firma_sidecar::normalizer::{IntentNormalizer, MappingTable, RawRequest};
use firma_sidecar::pipeline::{EnforcementPipeline, PipelineArgs};
use tokio::runtime::Runtime;

include!("support/common_fixtures.rs");

/// Canonical action class emitted by the normalizer for the bench request.
/// Must be (a) a valid v0.1 `ActionClassRegistry` entry so the mapping
/// compiles, (b) present in the token's `action_set` so the Stage 2 scope
/// check passes, and (c) authorised for `agent-bench` in the reference
/// Cedar bundle so the ALLOW path is exercised.
const BENCH_ACTION_CLASS: &str = "communication.external.send";

struct MockVerifier {
    claims: CapabilityClaims,
}
impl TokenVerifier for MockVerifier {
    fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
        Ok(self.claims.clone())
    }
}

struct NoRevocations;
impl RevocationStore for NoRevocations {
    fn is_revoked(&self, _: &TokenId) -> Result<bool, TokenError> {
        Ok(false)
    }
    fn add_revocation(&self, _: &TokenId) -> Result<(), TokenError> {
        Ok(())
    }
}

fn claims() -> CapabilityClaims {
    CapabilityClaims {
        token_id: "3713c5fc-b569-650c-c780-c64051473370"
            .parse()
            .expect("literal token id"),
        agent_id: "agent-bench".parse().expect("literal agent id"),
        session_id: "sess-bench".parse().expect("literal session id"),
        action_set: vec![BENCH_ACTION_CLASS.to_string()],
        resource_scope: "*".to_string(),
        issued_at: Utc::now(),
        expiry: Utc::now() + chrono::Duration::hours(1),
        context_hash: String::new(),
        budget_ceiling: None,
    }
}

fn mapping_table() -> MappingTable {
    let registry = ActionClassRegistry::v0_1();
    let rules = MappingRulesFile {
        rules: vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.bench.local".to_string(),
            path: Some("/invoke".to_string()),
            action_class: BENCH_ACTION_CLASS.to_string(),
        }],
    };
    MappingTable::from_config(&rules, &registry, true).expect("mapping compiles")
}

fn build_pipeline() -> EnforcementPipeline {
    let claims = claims();
    let normalizer = IntentNormalizer::new(mapping_table());
    let validator = CapabilityValidator::new(
        CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.bench".to_string(),
            claims: claims.clone(),
        }]),
        Box::new(MockVerifier { claims }),
        Arc::new(NoRevocations),
        Duration::from_secs(0),
    );
    let evaluator: Arc<dyn firma_sidecar::enforcement::constraint_enforcement::PolicyEvaluation> =
        Arc::new(
            CedarPolicyEvaluator::from_bundle(&reference_bundle())
                .expect("reference bundle compiles"),
        );
    let enforcer = ConstraintEnforcer::new(evaluator);
    EnforcementPipeline::new(PipelineArgs {
        normalizer,
        capability_validator: validator,
        constraint_enforcer: enforcer,
        credential_injector: Box::new(NullCredentialInjector),
        session_state_store: Arc::new(LruSessionStateStore::new(16)),
    })
}

fn sample_request() -> RawRequest {
    RawRequest {
        method: "POST".to_string(),
        host: "api.bench.local".to_string(),
        path: "/invoke".to_string(),
        headers: std::collections::HashMap::new(),
        body: None,
        is_https: true,
    }
}

fn bench_pipeline_enforce(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let pipeline = build_pipeline();
    let request = sample_request();

    // One-shot sanity check: we MUST be benching the ALLOW path, otherwise
    // the measurement is of the short-circuited DENY path instead of the
    // full enforce → credential-inject flow.
    let (decision, _payload) = rt.block_on(pipeline.enforce(&request, "sess-bench"));
    assert!(
        decision.is_allow(),
        "pipeline must allow for bench correctness: {decision:?}"
    );

    c.bench_function("pipeline_enforce", |b| {
        b.iter(|| {
            let _ = black_box(rt.block_on(pipeline.enforce(black_box(&request), "sess-bench")));
        });
    });
}

criterion_group!(benches, bench_pipeline_enforce);
criterion_main!(benches);
