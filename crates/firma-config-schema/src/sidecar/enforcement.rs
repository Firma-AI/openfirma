//! Schema for the enforcement-engine sections of `[sidecar]`.
//!
//! Representation only. These sections are flattened at the top level of the
//! sidecar config (`[mapping]`, `[capability_validation]`,
//! `[constraint_enforcement]`). `firma-sidecar` validates them and re-bases the
//! mapping paths.

use serde::{Deserialize, Serialize};

/// Enforcement engine configuration.
///
/// Groups the three enforcement sub-systems: intent-mapping rules, capability
/// validation (Stage 1), and constraint enforcement (Stage 2).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EnforcementConfig {
    /// Intent normalization / mapping rules.
    #[serde(default)]
    pub mapping: MappingConfig,
    /// Capability validation settings.
    #[serde(default)]
    pub capability_validation: CapabilityValidationConfig,
    /// Constraint enforcement settings.
    #[serde(default)]
    pub constraint_enforcement: ConstraintEnforcementConfig,
}

/// Mapping rules configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MappingConfig {
    /// Path to the primary mapping rules TOML file.
    #[serde(default = "default_mapping_path")]
    pub rules_path: String,
    /// Additional mapping rule files merged on top of `rules_path`.
    #[serde(default)]
    pub rules_paths: Vec<String>,
    /// Whether unlisted hosts are protected by default.
    #[serde(default = "default_true")]
    pub default_protected: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            rules_path: default_mapping_path(),
            rules_paths: Vec::new(),
            default_protected: true,
        }
    }
}

/// Capability validation configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CapabilityValidationConfig {
    /// Clock skew tolerance for expiry checks (seconds). Default: 0 (strict).
    #[serde(default)]
    pub clock_skew_tolerance_seconds: u64,
}

/// Constraint enforcement configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConstraintEnforcementConfig {
    /// Policy bundle TTL in seconds. Default: 30.
    #[serde(default = "default_bundle_ttl")]
    pub bundle_ttl_seconds: u64,
    /// Optional Stage 2 evaluation timeout in milliseconds.
    #[serde(default = "default_stage2_timeout_ms")]
    pub enforcement_timeout_ms: u64,
    /// Maximum number of active sessions tracked in the session-state cache.
    /// Default: 8192. Minimum: 1.
    #[serde(default = "default_session_state_capacity")]
    pub session_state_capacity: usize,
    /// Session-state storage backend.
    #[serde(default)]
    pub session_state_backend: SessionStateBackend,
    /// Optional path for the persistent session-state JSONL file. Only used
    /// when `session_state_backend = "persistent"`.
    #[serde(default)]
    pub session_state_path: Option<String>,
}

impl Default for ConstraintEnforcementConfig {
    fn default() -> Self {
        Self {
            bundle_ttl_seconds: default_bundle_ttl(),
            enforcement_timeout_ms: default_stage2_timeout_ms(),
            session_state_capacity: default_session_state_capacity(),
            session_state_backend: SessionStateBackend::default(),
            session_state_path: None,
        }
    }
}

/// Session-state storage backend selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStateBackend {
    /// In-memory LRU cache (default). State lost on eviction / restart.
    #[default]
    Lru,
    /// File-backed JSONL store; state survives eviction and restart.
    Persistent,
}

/// Sentinel: default `mapping.rules_path`.
pub const DEFAULT_MAPPING_PATH: &str = "mapping-rules.toml";

fn default_mapping_path() -> String {
    DEFAULT_MAPPING_PATH.to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_bundle_ttl() -> u64 {
    30
}

const fn default_stage2_timeout_ms() -> u64 {
    50
}

const fn default_session_state_capacity() -> usize {
    8192
}
