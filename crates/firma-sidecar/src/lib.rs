//! Firma Sidecar — the enforcement layer between an agent and the outside
//! world.
//!
//! Every outbound agent call passes through the Sidecar. It is a single
//! statically-linked binary with no persistent database; all state is
//! in-memory and re-populated from Authority streams on restart.
//!
//! # Architecture
//!
//! ```text
//! agent → interceptor → normalizer → Stage 1 → Stage 2 → connector → external
//! ```
//!
//! - [`interceptor`] — Captures outbound agent traffic before it
//!   reaches the external system (HTTP proxy, gRPC hook, Unix socket).
//! - [`normalizer`] — Intent Normalizer / Envelope Builder.
//!   Deterministically maps raw intercepted events into canonical
//!   `ExecutionEnvelope` instances with a normalized `intent.action_class`.
//! - [`enforcement`] — Two-phase enforcement engine:
//!   - Stage 1 (Capability Validation): token selection, parse, signature
//!     verify, expiry, revocation check.
//!   - Stage 2 (Constraint Enforcement Engine / CEE): scope check, policy
//!     bundle freshness, Cedar policy evaluation.
//! - [`pipeline`] — Orchestrates normalizer + both enforcement stages into
//!   a single `enforce()` entry point. This is the primary public API;
//!   all types needed to construct and inspect the pipeline are re-exported
//!   from here.

pub mod enforcement;
pub mod interceptor;
pub mod normalizer;
pub mod pipeline;
