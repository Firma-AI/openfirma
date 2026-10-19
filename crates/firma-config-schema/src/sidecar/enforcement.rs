//! Schema for the enforcement-engine sections of `[sidecar]`.
//!
//! Representation only. These sections are flattened at the top level of the
//! sidecar config (`[sidecar.constraint_enforcement]`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Enforcement engine configuration.
///
/// Configurable constraint enforcement (Stage 2).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementConfig {
    /// Constraint enforcement settings.
    #[serde(default)]
    pub constraint_enforcement: ConstraintEnforcementConfig,
}

/// Constraint enforcement configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintEnforcementConfig {
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
    pub session_state_path: Option<PathBuf>,
}

impl Default for ConstraintEnforcementConfig {
    fn default() -> Self {
        Self {
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

const fn default_session_state_capacity() -> usize {
    8192
}
