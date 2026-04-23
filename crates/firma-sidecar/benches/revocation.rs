//! Criterion benchmarks for the revocation cache.
//!
//! Target: `is_revoked` miss case p50 < 1 microsecond on dev hardware.
//! Runs in CI without a hard threshold.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use firma_core::{RevocationStore, TokenId};
use firma_sidecar::enforcement::revocation::{BloomLruRevocationStore, RevocationConfig};

fn bench_is_revoked_miss(c: &mut Criterion) {
    let store = BloomLruRevocationStore::new(RevocationConfig::default());
    let mut populated = Vec::with_capacity(100_000);
    for _ in 0..100_000_u64 {
        let id = TokenId::new();
        let _ = store.add_revocation(&id);
        populated.push(id);
    }
    let _ = populated;
    c.bench_function("is_revoked_miss", |b| {
        b.iter(|| {
            let id = TokenId::new();
            let _ = black_box(store.is_revoked(&id));
        });
    });
}

fn bench_is_revoked_hit(c: &mut Criterion) {
    let store = BloomLruRevocationStore::new(RevocationConfig::default());
    let mut ids = Vec::with_capacity(10_000);
    for _ in 0..10_000_u64 {
        let id = TokenId::new();
        let _ = store.add_revocation(&id);
        ids.push(id);
    }
    let mut i = 0_usize;
    c.bench_function("is_revoked_hit", |b| {
        b.iter(|| {
            i = (i + 1) % ids.len();
            let _ = black_box(store.is_revoked(&ids[i]));
        });
    });
}

fn bench_add_revocation(c: &mut Criterion) {
    let store = BloomLruRevocationStore::new(RevocationConfig::default());
    c.bench_function("add_revocation", |b| {
        b.iter(|| {
            let id = TokenId::new();
            let _ = black_box(store.add_revocation(&id));
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
