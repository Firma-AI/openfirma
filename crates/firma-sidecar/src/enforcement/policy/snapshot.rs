//! Immutable snapshot of a Cedar policy bundle.
//!
//! A [`BundleSnapshot`] is constructed by [`BundleLoader`][super::loader::BundleLoader]
//! from a [`RawBundle`][super::loader::RawBundle] and atomically swapped into the
//! [`CedarPolicyEvaluator`][super::evaluator::CedarPolicyEvaluator] via
//! `ArcSwap`. Readers on the hot path never see a torn snapshot.

use std::time::Instant;

use cedar_policy::{Entities, PolicySet, Schema};

/// Immutable view of a Cedar policy bundle.
///
/// Holds everything Stage 2 needs to authorize a request against the
/// current bundle: the parsed `PolicySet`, the optional `Schema`, the
/// static `Entities`, the bundle version (for audit correlation), and
/// the instant at which this snapshot was installed (for TTL-based
/// staleness).
pub struct BundleSnapshot {
    /// Parsed Cedar policies.
    pub policies: PolicySet,
    /// Optional Cedar schema. When present, `Request` construction
    /// validates against it.
    pub schema: Option<Schema>,
    /// Static entities published with the bundle (Component Reference
    /// §9.1: `Agent`, `Session`, `Resource`, `Connector`,
    /// `MemoryNamespace`).
    pub entities: Entities,
    /// Authority-assigned bundle version.
    pub version: String,
    /// Install time used to compute staleness against the evaluator TTL.
    pub loaded_at: Instant,
}
