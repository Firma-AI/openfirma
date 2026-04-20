//! Library surface for tests and benchmarks.

#[path = "enforcement/revocation.rs"]
mod revocation;

/// Narrow re-export for Criterion benches.
///
/// This module is not part of the stable public API.
pub mod revocation_bench_api {
    pub use crate::revocation::{BloomLruRevocationStore, RevocationConfig};
}
