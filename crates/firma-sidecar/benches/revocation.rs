//! Criterion benchmarks for the revocation cache.
//!
//! Target: `is_revoked` miss case p50 < 1 microsecond on dev hardware.
//! Runs in CI without a hard threshold.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use firma_core::RevocationStore;
use firma_sidecar::revocation_bench_api::{BloomLruRevocationStore, RevocationConfig};

fn bench_is_revoked_miss(c: &mut Criterion) {
    let store = BloomLruRevocationStore::new(RevocationConfig::default());
    for i in 0..100_000_u64 {
        let _ = store.add_revocation(&format!("tok-{i}"));
    }
    let mut i = 0_u64;
    c.bench_function("is_revoked_miss", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            let key = format!("miss-{i}");
            let _ = black_box(store.is_revoked(&key));
        });
    });
}

fn bench_is_revoked_hit(c: &mut Criterion) {
    let store = BloomLruRevocationStore::new(RevocationConfig::default());
    for i in 0..10_000_u64 {
        let _ = store.add_revocation(&format!("hit-{i}"));
    }
    let mut i = 0_u64;
    c.bench_function("is_revoked_hit", |b| {
        b.iter(|| {
            i = i.wrapping_add(1) % 10_000;
            let key = format!("hit-{i}");
            let _ = black_box(store.is_revoked(&key));
        });
    });
}

fn bench_add_revocation(c: &mut Criterion) {
    let store = BloomLruRevocationStore::new(RevocationConfig::default());
    let mut i = 0_u64;
    c.bench_function("add_revocation", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            let key = format!("add-{i}");
            let _ = black_box(store.add_revocation(&key));
        });
    });
}

criterion_group!(
    benches,
    bench_is_revoked_miss,
    bench_is_revoked_hit,
    bench_add_revocation
);
criterion_main!(benches);
