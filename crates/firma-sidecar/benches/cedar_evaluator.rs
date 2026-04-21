//! Criterion benchmarks for the Cedar policy evaluator.
//!
//! Targets (task 013):
//! - `evaluate()` p95 < 200 µs for a 100-policy bundle.
//! - Bundle hot-reload (build evaluator + first `evaluate()` on the new
//!   snapshot) < 500 ms.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::format_push_string)]

use std::fmt::Write as _;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use firma_core::AgentId;
use firma_core::policy::PolicyBundle;
use firma_sidecar::cedar_bench_api::{CedarPolicyEvaluator, PolicyEvaluation};
use serde_json::json;

const SCHEMA: &str = "\
namespace Firma {
    entity Agent;
    entity Resource;
    action \"bench.action\" appliesTo { principal: [Agent], resource: [Resource] };
}";

fn synth_policies(count: usize) -> String {
    // One `permit` policy per iteration; each one names a distinct agent so
    // the evaluator has to evaluate the full set for the miss path.
    let mut src = String::new();
    for i in 0..count {
        writeln!(
            src,
            "permit(principal == Firma::Agent::\"agent-{i}\", action, resource);"
        )
        .expect("writeln to a String cannot fail");
    }
    src
}

fn bundle(policy_count: usize) -> PolicyBundle {
    PolicyBundle::new(
        format!("bench-v{policy_count}"),
        synth_policies(policy_count).into_bytes(),
        SCHEMA.as_bytes().to_vec(),
        60,
    )
}

fn agent() -> AgentId {
    "agent-bench".parse().expect("literal agent id")
}

fn context() -> serde_json::Value {
    json!({})
}

fn bench_evaluate_100_policies(c: &mut Criterion) {
    let evaluator =
        CedarPolicyEvaluator::from_bundle(&bundle(100)).expect("100-policy Cedar bundle compiles");
    let principal = agent();
    let ctx = context();
    c.bench_function("cedar_evaluate_100_policies", |b| {
        b.iter(|| {
            let result = evaluator.evaluate(
                black_box(&principal),
                black_box("bench.action"),
                black_box("resource-1"),
                black_box(&ctx),
            );
            let _ = black_box(result);
        });
    });
}

fn bench_hot_reload(c: &mut Criterion) {
    let fresh_bundle = bundle(100);
    c.bench_function("cedar_bundle_hot_reload", |b| {
        b.iter(|| {
            // apply_bundle equivalent: build a fresh evaluator from the bundle
            // bytes and run the first evaluate against that new snapshot.
            let evaluator =
                CedarPolicyEvaluator::from_bundle(black_box(&fresh_bundle)).expect("bundle parses");
            let principal = agent();
            let ctx = context();
            let _ = black_box(evaluator.evaluate(&principal, "bench.action", "resource-1", &ctx));
        });
    });
}

criterion_group!(benches, bench_evaluate_100_policies, bench_hot_reload);
criterion_main!(benches);
