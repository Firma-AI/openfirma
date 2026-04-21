//! Library surface for tests and benchmarks.

#[path = "enforcement/revocation.rs"]
mod revocation;

/// Bench-only shim: the Cedar evaluator lives under `enforcement` in the
/// binary crate; mirror that structure here so `super::constraint_enforcement`
/// in `enforcement/cedar_evaluator.rs` resolves to the trait we redefine
/// locally below. Nothing leaves `enforcement` — the public bench surface is
/// `cedar_bench_api`.
#[path = "enforcement"]
mod enforcement {
    #[path = "cedar_evaluator.rs"]
    pub mod cedar_evaluator;

    pub mod constraint_enforcement {
        use firma_core::AgentId;

        /// Mirror of `crate::enforcement::constraint_enforcement::PolicyEvaluation`
        /// in the binary crate. Kept in sync manually.
        pub trait PolicyEvaluation: Send + Sync {
            /// See the binary-crate trait for full semantics.
            ///
            /// # Errors
            ///
            /// Propagates a human-readable error string on evaluation failure.
            fn evaluate(
                &self,
                principal: &AgentId,
                action: &str,
                resource: &str,
                context: &serde_json::Value,
            ) -> Result<bool, String>;

            fn is_fresh(&self) -> bool;

            fn is_available(&self) -> bool {
                true
            }

            #[allow(dead_code)]
            fn version(&self) -> Option<String>;
        }
    }
}

/// Narrow re-export for Criterion benches.
///
/// This module is not part of the stable public API.
pub mod revocation_bench_api {
    pub use crate::revocation::{BloomLruRevocationStore, RevocationConfig};
}

/// Narrow re-export of the Cedar evaluator for Criterion benches.
pub mod cedar_bench_api {
    pub use crate::enforcement::cedar_evaluator::CedarPolicyEvaluator;
    pub use crate::enforcement::constraint_enforcement::PolicyEvaluation;
}
