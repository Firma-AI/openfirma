//! Stage 2 policy-eval bench. Target: p95 < 200 µs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use firma_core::AgentId;
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::constraint_enforcement::PolicyEvaluation;
use serde_json::json;

include!("fixtures.rs");

fn agent() -> AgentId {
    "agent-bench".parse().expect("literal agent id")
}

fn ctx() -> serde_json::Value {
    json!({ "budget_remaining": 100, "risk_score": 10 })
}

fn bench_allow(c: &mut Criterion) {
    let ev =
        CedarPolicyEvaluator::from_bundle(&reference_bundle()).expect("reference bundle compiles");
    let p = agent();
    let ctx = ctx();
    c.bench_function("cedar_evaluate_allow", |b| {
        b.iter(|| {
            let _ = black_box(ev.evaluate(
                black_box(&p),
                black_box("bench.action.allow"),
                black_box("resource-1"),
                black_box(&ctx),
            ));
        });
    });
}

fn bench_deny(c: &mut Criterion) {
    let ev =
        CedarPolicyEvaluator::from_bundle(&reference_bundle()).expect("reference bundle compiles");
    let p = agent();
    let ctx = ctx();
    c.bench_function("cedar_evaluate_deny", |b| {
        b.iter(|| {
            let _ = black_box(ev.evaluate(
                black_box(&p),
                black_box("bench.action.deny"),
                black_box("resource-1"),
                black_box(&ctx),
            ));
        });
    });
}

fn bench_context(c: &mut Criterion) {
    let ev =
        CedarPolicyEvaluator::from_bundle(&reference_bundle()).expect("reference bundle compiles");
    let p = agent();
    let ctx = ctx();
    c.bench_function("cedar_evaluate_context", |b| {
        b.iter(|| {
            let _ = black_box(ev.evaluate(
                black_box(&p),
                black_box("bench.action.ctx"),
                black_box("resource-1"),
                black_box(&ctx),
            ));
        });
    });
}

criterion_group!(benches, bench_allow, bench_deny, bench_context);
criterion_main!(benches);
