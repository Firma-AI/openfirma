//! Enforcement pipeline for the Firma Sidecar.
//!
//! This module implements the core two-phase enforcement engine:
//!
//! ```text
//! normalize → select token → Stage 1 (validate) → Stage 2 (Cedar eval)
//! ```
//!
//! Every intercepted request passes through this pipeline. It transforms
//! a raw request into a canonical representation, selects and validates the
//! agent's capability token, evaluates Cedar authorization policies, and
//! returns a binary ALLOW/DENY decision.

pub mod capability_map;
pub mod config;
pub mod decision;
pub mod error;
pub mod mapping;
pub mod normalizer;
pub mod pipeline;
pub mod registry;
pub mod stage1;
pub mod stage2;

// Re-export primary public API
pub use decision::{EnforcementDecision, EnforcementStage};
pub use normalizer::RawRequest;
pub use pipeline::EnforcementPipeline;
pub use stage2::PolicyEvaluation;
