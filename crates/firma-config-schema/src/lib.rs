//! Behavior-free serde schema for the unified `firma.toml` configuration.
//!
//! This crate is the single source of truth for the *shape* of Firma
//! configuration. It contains representation only: `serde`-derived structs
//! and enums, their default values, and value types that enforce intrinsic
//! constructibility invariants. It deliberately holds no cross-field or
//! environment validation, no path rebasing, and no derived runtime types.
//! Dependencies are limited to `serde` and representation-fidelity helpers for
//! individual fields (such as `bytesize` for human-readable byte sizes).
//!
//! Each Firma component owns a validated configuration type built from the
//! relevant portion of this schema (typically via `TryFrom`), keeping
//! cross-field and runtime validation inside the component while representation
//! and intrinsic value invariants live here.
//!
//! Modules mirror the top-level `firma.toml` sections. Sections are populated
//! incrementally as each component migrates; see the crate rollout plan.

pub mod authority;
pub mod gateway;
pub mod run;
pub mod secret_matcher;
pub mod sidecar;
pub mod utils;
