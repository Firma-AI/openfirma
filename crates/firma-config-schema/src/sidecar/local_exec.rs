//! Schema for `[sidecar.local_exec]`.
//!
//! Representation only. When present, the sidecar binds a UDS endpoint that
//! `firma-run` clients contact for pre-execution governance decisions.
//! `firma-sidecar` validates that the socket path is absolute.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Policy applied to every fresh local-exec request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Allow all executions unconditionally.
    Allow,
    /// Deny all executions unconditionally. Default (fail-closed).
    #[default]
    Deny,
    /// Require HITL approval via the token flow.
    PendingHitl,
}

/// Local-exec governance endpoint configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalExecConfig {
    /// Absolute path to the Unix domain socket file.
    pub socket_path: PathBuf,
    /// Policy applied to every fresh local-exec request.
    #[serde(default)]
    pub default_action: DefaultAction,
    /// Approval token time-to-live in seconds (default: 300).
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// Suggested retry interval returned to `firma-run` in `pending_hitl`
    /// responses (milliseconds, default: 500).
    #[serde(default = "default_retry_after_ms")]
    pub retry_after_ms: u64,
}

const fn default_token_ttl_secs() -> u64 {
    300
}

const fn default_retry_after_ms() -> u64 {
    500
}
