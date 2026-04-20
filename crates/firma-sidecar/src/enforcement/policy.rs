//! Cedar policy evaluator plus bundle snapshot and loader.
//!
//! The sidecar never reads policy bundles from disk (Component
//! Reference §4.6). The Authority owns the on-disk bundle source and
//! pushes new bundles over `WatchPolicyBundle`. This module owns the
//! in-memory data structures, atomic hot-swap mechanics, Cedar
//! evaluation, and freshness semantics.
//!
//! - [`BundleSnapshot`] — immutable view of one bundle.
//! - [`CedarPolicyEvaluator`] — implements
//!   [`PolicyEvaluation`][super::constraint_enforcement::PolicyEvaluation]
//!   using an `ArcSwapOption<BundleSnapshot>`.
//! - [`BundleLoader`] — parses a [`RawBundle`] from the Authority and
//!   atomically installs the resulting snapshot.
//! - [`BundleError`] — parse failures; the previous snapshot is kept on
//!   any error.

pub mod evaluator;
pub mod loader;
pub mod snapshot;

pub(crate) use evaluator::CedarPolicyEvaluator;
pub(crate) use loader::{BundleLoader, RawBundle};
