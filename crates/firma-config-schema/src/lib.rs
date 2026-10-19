//! Behavior-free serde schema for the unified `firma.toml` configuration.
//!
//! This crate is the single source of truth for the *shape* of Firma
//! configuration. It contains representation only: `serde`-derived structs
//! and enums and their default values. It deliberately holds no cross-field or
//! environment validation, no path rebasing, and no derived runtime types.
//! Dependencies are limited to `serde`, shared configuration value types, and
//! representation-fidelity helpers for individual fields.
//!
//! Each Firma component owns a validated configuration type built from the
//! relevant portion of this schema (typically via `TryFrom`), keeping
//! cross-field and runtime validation inside the component while representation
//! and intrinsic value invariants live here.
//!
//! Modules mirror the top-level and nested `firma.toml` sections.

pub mod authority;
pub mod broker;
pub mod gateway;
pub mod run;
pub mod secret_matcher;
pub mod secret_provider;
pub mod sidecar;
mod utils;
