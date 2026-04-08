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
//! - [`config`] — Deserialized enforcement configuration (TOML).
//! - [`registry`] — Canonical Action Class Registry v0.1 (15 action classes).

pub(crate) mod capability_map;
pub(crate) mod capability_validation;
pub(crate) mod config;
pub(crate) mod constraint_enforcement;
pub(crate) mod decision;
pub(crate) mod error;
pub(crate) mod registry;
