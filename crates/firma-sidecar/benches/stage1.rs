//! Stage 1 bench: `CapabilityValidator::enforce` under a realistic
//! revocation-store population. Target: p95 < 1 ms.

#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use firma_core::{CapabilityClaims, RevocationStore, TokenError, TokenId, TokenVerifier};
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
use firma_sidecar::config::TenancyMode;
use firma_sidecar::enforcement::capability_validation::CapabilityValidator;
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::enforcement::revocation::{BloomLruRevocationStore, RevocationConfig};
use firma_sidecar::normalizer::{IntentNormalizer, MappingTable, RawRequest};

struct MockVerifier {
    claims: CapabilityClaims,
}
impl TokenVerifier for MockVerifier {
    fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
        Ok(self.claims.clone())
    }
}

fn seed_revocations(store: &BloomLruRevocationStore, n: usize) {
    for _ in 0..n {
        let _ = store.add_revocation(&TokenId::new());
    }
}

fn test_claims() -> CapabilityClaims {
    CapabilityClaims {
        token_id: "3713c5fc-b569-650c-c780-c64051473370"
            .parse()
            .expect("literal token id"),
        agent_id: "agent-bench".parse().expect("literal agent id"),
        session_id: "sess-bench".parse().expect("literal session id"),
        action_set: vec!["communication.external.send".to_string()],
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
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }],
    };
    MappingTable::from_config(&rules, &registry, true).expect("mapping compiles")
}

fn bench_stage1_validate(c: &mut Criterion) {
    let claims = test_claims();
    let normalizer = IntentNormalizer::new(mapping_table());
    let request = RawRequest {
        method: "POST".to_string(),
        host: "api.openai.com".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: std::collections::HashMap::new(),
        body: None,
        is_https: true,
    };
    let envelope = normalizer.normalize(&request).expect("normalizes");

    let revocations = Arc::new(BloomLruRevocationStore::new(RevocationConfig::default()));
    seed_revocations(&revocations, 10_000);

    let validator = CapabilityValidator::new(
        CapabilityMap::new(vec![CapabilityEntry {
            raw_token: "v4.public.bench_token".to_string(),
            claims: claims.clone(),
        }]),
        Box::new(MockVerifier { claims }),
        revocations,
        Duration::from_secs(0),
        TenancyMode::default(),
    );

    c.bench_function("stage1_enforce", |b| {
        b.iter(|| {
            let _ = black_box(validator.enforce(black_box(&envelope), "sess-bench"));
        });
    });
}

criterion_group!(benches, bench_stage1_validate);
criterion_main!(benches);
