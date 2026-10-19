//! Standalone-startup log contract.
//!
//! Locks the six-line INFO sequence the sidecar emits on every
//! successful start. The contract is part of the operator-facing
//! interface: `examples/demo/` uses these lines to detect readiness, so
//! the order, prefix, and field surface are all stable.
//!
//! The six lines, in order, are:
//!
//! 1. `config loaded path="…"`
//! 2. `connector registry built hosts=N default_timeout_ms=T`
//! 3. `interceptor listening addr="…"`
//! 4. `authority stream connected endpoint="…"`
//! 5. `policy bundle loaded version="…" ttl_seconds=N`
//! 6. `sidecar ready`
//!
//! Lines 4 and 5 are emitted only after both Authority streams have hydrated,
//! so they report a real connection and the Authority bundle version actually
//! enforced. The per-stream `authority stream connected stream=…` lines are
//! connection diagnostics, not contract lines.

use std::path::Path;

/// Inputs needed to emit the ready sequence.
///
/// Each field maps 1:1 to one structured field on the contract lines.
pub struct StartupReport<'a> {
    /// Filesystem path the sidecar config was read from.
    pub config_path: &'a Path,
    /// Required Authority endpoint URL.
    pub authority_endpoint: String,
    /// Per-host connector overrides count.
    pub connector_hosts: usize,
    /// Default connector timeout, milliseconds.
    pub connector_default_timeout_ms: u64,
    /// Interceptor listen address as printed in line 3.
    pub interceptor_addr: String,
}

/// Emit contract lines 1-3, which do not depend on the Authority.
pub fn log_pre_ready_sequence(report: &StartupReport<'_>) {
    tracing::info!(path = %report.config_path.display(), "config loaded");
    tracing::info!(
        hosts = report.connector_hosts,
        default_timeout_ms = report.connector_default_timeout_ms,
        "connector registry built"
    );
    tracing::info!(addr = %report.interceptor_addr, "interceptor listening");
}

/// Emit contract lines 4-5 once both Authority streams have hydrated.
pub fn log_authority_hydrated(report: &StartupReport<'_>, version: Option<&str>, ttl_seconds: u32) {
    tracing::info!(endpoint = %report.authority_endpoint, "authority stream connected");
    tracing::info!(version, ttl_seconds, "policy bundle loaded");
}

/// Emit contract line 6 (`ready`). Callers must have already emitted
/// lines 1-5.
pub fn log_ready_line() {
    tracing::info!("sidecar ready");
}
