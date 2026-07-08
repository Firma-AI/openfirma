//! Two-phase enforcement engine.
//!
//! Contains both enforcement stages that evaluate an already-normalized
//! `ExecutionEnvelope`. Intent normalization and interception live in
//! sibling modules ([`crate::normalizer`], [`crate::interceptor`]); the
//! [`crate::pipeline`] module orchestrates the full flow.
//!
//! Stage 1 and Stage 2 are two sequential enforcement phases inside the same
//! Sidecar process, not two separate components. The Authority is never
//! contacted on the hot path — all evaluation is local.
//!
//! # Module layout
//!
//! - [`capability_validation`] — Stage 1: capability token selection and
//!   validation (parse, signature verify, expiry, revocation).
//! - [`constraint_enforcement`] — Stage 2: Constraint Enforcement Engine
//!   (CEE) — Cedar policy evaluation, scope/budget/threshold checks.
//! - [`capability_map`] — Pre-provisioned capability tokens indexed by
//!   action class for fast selection.
//! - [`decision`] — Unified ALLOW/DENY result type for every enforcement call.
//! - [`error`] — Internal error types; every variant maps to a DENY decision
//!   (fail-closed boundary).
//! - [`registry`] — Canonical Action Class Registry v0.1 (15 action classes).
//! - [`revocation`] — Bloom filter + LRU revocation cache.

pub mod capability_map;
pub mod capability_validation;
pub mod cedar_evaluator;
pub mod constraint_enforcement;
pub mod decision;
pub mod error;
pub mod registry;
pub mod revocation;
pub mod session_state;
pub mod session_state_persistent;
pub use session_state::{LruSessionStateStore, SessionStateStore};
pub use session_state_persistent::PersistentSessionStateStore;
