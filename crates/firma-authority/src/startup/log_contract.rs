//! Standalone-startup log contract for the Mini Authority.
//!
//! Locks the human-readable INFO sequence the Authority emits on every
//! successful standalone start. `firma run` uses the machine-readable startup
//! report for readiness; these lines remain a stable operator-facing contract.
//!
//! Lines, in order:
//!
//! 1. `config loaded         policy_dir="…" listen_addr="…"`
//! 2. `policy bundle loaded  policies=N`
//! 3. `listening              addr="…"`
//! 4. `authority ready`

use std::path::Path;

/// Inputs needed to emit the ready sequence.
pub struct StartupReport<'a> {
    /// Filesystem path to the policy directory used by the authority.
    pub policy_dir: &'a Path,
    /// Listen address as configured (before bind resolution).
    pub configured_listen_addr: &'a str,
    /// Number of `.cedar` files loaded into the enforcement bundle.
    pub policy_count: usize,
    /// Effective listen address after bind (host:port).
    pub effective_listen_addr: String,
}

/// Emit the four contract lines at INFO level, in order.
pub fn log_ready_sequence(report: &StartupReport<'_>) {
    tracing::info!(
        policy_dir = %report.policy_dir.display(),
        listen_addr = %report.configured_listen_addr,
        "config loaded"
    );
    tracing::info!(policies = report.policy_count, "policy bundle loaded");
    tracing::info!(addr = %report.effective_listen_addr, "listening");
    tracing::info!("authority ready");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn report_carries_field_values() {
        let dir = PathBuf::from("/tmp/firma-policy");
        let report = StartupReport {
            policy_dir: &dir,
            configured_listen_addr: "[::1]:50051",
            policy_count: 1,
            effective_listen_addr: "[::1]:50051".to_string(),
        };
        assert_eq!(report.policy_count, 1);
        assert_eq!(report.configured_listen_addr, "[::1]:50051");
    }

    #[test]
    fn emits_without_panicking_when_subscriber_absent() {
        let dir = PathBuf::from("/tmp/firma-policy");
        let report = StartupReport {
            policy_dir: &dir,
            configured_listen_addr: "[::1]:0",
            policy_count: 0,
            effective_listen_addr: "127.0.0.1:12345".to_string(),
        };
        log_ready_sequence(&report);
    }
}
