//! Stage 2 policy-eval bench. Target: p95 < 200 µs.

#![allow(clippy::expect_used)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use firma_core::AgentId;
use firma_sidecar::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use firma_sidecar::enforcement::constraint_enforcement::PolicyEvaluation;
use serde_json::json;

include!("support/common_fixtures.rs");

fn agent() -> AgentId {
    "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal agent id")
}

fn ctx() -> serde_json::Value {
    json!({ "risk_score": 10 })
}

fn bench_allow(c: &mut Criterion) {
    let ev =
        CedarPolicyEvaluator::from_bundle(&reference_bundle()).expect("reference bundle compiles");
    let p = agent();
    let ctx = ctx();
    c.bench_function("cedar_evaluate_allow", |b| {
        b.iter_batched(
            || ctx.clone(),
            |ctx| {
                let _ = black_box(ev.evaluate(
                    black_box(&p),
                    black_box("bench.action.allow"),
                    black_box("resource-1"),
                    black_box(ctx),
                ));
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_deny(c: &mut Criterion) {
    let ev =
        CedarPolicyEvaluator::from_bundle(&reference_bundle()).expect("reference bundle compiles");
    let p = agent();
    let ctx = ctx();
    c.bench_function("cedar_evaluate_deny", |b| {
        b.iter_batched(
            || ctx.clone(),
            |ctx| {
                let _ = black_box(ev.evaluate(
                    black_box(&p),
                    black_box("bench.action.deny"),
                    black_box("resource-1"),
                    black_box(ctx),
                ));
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_context(c: &mut Criterion) {
    let ev =
        CedarPolicyEvaluator::from_bundle(&reference_bundle()).expect("reference bundle compiles");
    let p = agent();
    let ctx = ctx();
    c.bench_function("cedar_evaluate_context", |b| {
        b.iter_batched(
            || ctx.clone(),
            |ctx| {
                let _ = black_box(ev.evaluate(
                    black_box(&p),
                    black_box("bench.action.ctx"),
                    black_box("resource-1"),
                    black_box(ctx),
                ));
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_allow, bench_deny, bench_context);
criterion_main!(benches);
