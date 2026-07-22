//! Bundle hot-reload latency. Target: p95 < 500 ms.
//!
//! Measures `CedarPolicyEvaluator::from_bundle` parse cost plus the first
//! `evaluate()` on the fresh snapshot. Replace with `BundleLoader::apply`
//! once task 013's atomic-swap API lands.
//
// Fixture: benches/fixtures/reference_bundle.cedar (Task 2).

#![allow(clippy::expect_used)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use firma_core::AgentId;
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::constraint_enforcement::PolicyEvaluation;
use serde_json::json;

include!("support/common_fixtures.rs");

fn bench_reload(c: &mut Criterion) {
    let bundle = reference_bundle();
    let principal: AgentId = "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal agent id");
    let ctx = json!({ "risk_score": 10 });

    c.bench_function("cedar_bundle_reload", |b| {
        b.iter_batched(
            || ctx.clone(),
            |ctx| {
                let ev =
                    CedarPolicyEvaluator::from_bundle(black_box(&bundle)).expect("bundle parses");
                let _ = black_box(ev.evaluate(&principal, "bench.action.allow", "resource-1", ctx));
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_reload);
criterion_main!(benches);
