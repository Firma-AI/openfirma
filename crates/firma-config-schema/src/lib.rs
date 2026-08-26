//! Behavior-free serde schema for the unified `firma.toml` configuration.
//!
//! This crate is the single source of truth for the *shape* of Firma
//! configuration. It contains representation only: `serde`-derived structs
//! and enums plus their default values. It deliberately holds no validation,
//! no path rebasing, and no derived domain types. Dependencies are limited to
//! `serde` and representation-fidelity helpers for individual fields (such as
//! `bytesize` for human-readable byte sizes).
//!
//! Each Firma component owns a validated configuration type built from the
//! relevant portion of this schema (typically via `TryFrom`), keeping
//! validation and behavior inside the component while representation lives
//! here.
//!
//! Modules mirror the top-level `firma.toml` sections. Sections are populated
//! incrementally as each component migrates; see the crate rollout plan.

pub mod gateway;
pub mod run;
pub mod secret_matcher;
pub mod sidecar;
