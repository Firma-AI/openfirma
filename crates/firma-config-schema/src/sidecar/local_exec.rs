//! Schema for `[sidecar.local_exec]`.
//!
//! Representation only. When present, the sidecar binds a UDS endpoint that
//! `firma-run` clients contact for pre-execution governance decisions.
//! `firma-sidecar` validates that the socket path is absolute.

use std::path::PathBuf;
use std::time::Duration;

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
#[serde(deny_unknown_fields)]
pub struct LocalExecConfig {
    /// Absolute path to the Unix domain socket file.
    pub socket_path: PathBuf,
    /// Policy applied to every fresh local-exec request.
    #[serde(default)]
    pub default_action: DefaultAction,
    /// Approval token time-to-live (default: 5 minutes).
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_token_ttl"
    )]
    pub token_ttl: Duration,
    /// Suggested retry interval returned to `firma-run` in `pending_hitl`
    /// responses (default: 500 milliseconds).
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_retry_after"
    )]
    pub retry_after: Duration,
}

const fn default_token_ttl() -> Duration {
    Duration::from_mins(5)
}

const fn default_retry_after() -> Duration {
    Duration::from_millis(500)
}
