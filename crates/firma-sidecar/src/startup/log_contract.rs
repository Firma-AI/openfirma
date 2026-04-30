//! Standalone-startup log contract.
//!
//! Locks the seven-line INFO sequence the sidecar emits on every
//! successful start. The contract is part of the operator-facing
//! interface: `examples/demo/` and the `demo-e2e` CI gate scrape these
//! lines to assert readiness, so the order, prefix, and field surface
//! are all stable.
//!
//! The seven lines, in order, are:
//!
//! 1. `config loaded path="…"`
//! 2. `mapping table loaded rules=N`
//! 3. `policy bundle loaded version="…" policies=N`
//! 4. `authority stream connected endpoint="…"`
//! 5. `connector registry built hosts=N default_timeout_ms=T`
//! 6. `interceptor listening addr="…"`
//! 7. `ready`
//!
//! Line 4 fires unconditionally. When `policy.authority_url` is unset
//! the endpoint is reported as `"(disabled)"` so the contract surface
//! stays stable across deployment flavours.

use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

/// Inputs needed to emit the ready sequence.
///
/// Each field maps 1:1 to one structured field on the contract lines.
pub struct StartupReport<'a> {
    /// Filesystem path the sidecar config was read from.
    pub config_path: &'a Path,
    /// Number of mapping rules loaded across the primary file plus
    /// every entry of `mapping.rules_paths`.
    pub mapping_rules: usize,
    /// Eight-character hex prefix of the SHA-256 of the concatenated
    /// `.cedar` files in `policy.dir`.
    pub policy_bundle_version: String,
    /// Count of `.cedar` files contributing to the bundle hash.
    pub policy_count: usize,
    /// Authority endpoint string (URL or `"(disabled)"`).
    pub authority_endpoint: String,
    /// Per-host connector overrides count.
    pub connector_hosts: usize,
    /// Default connector timeout, milliseconds.
    pub connector_default_timeout_ms: u64,
    /// Interceptor listen address as printed in line 6.
    pub interceptor_addr: String,
}

/// Emit the seven contract lines at INFO level, in order.
pub fn log_ready_sequence(report: &StartupReport<'_>) {
    tracing::info!(path = %report.config_path.display(), "config loaded");
    tracing::info!(rules = report.mapping_rules, "mapping table loaded");
    tracing::info!(
        version = %report.policy_bundle_version,
        policies = report.policy_count,
        "policy bundle loaded"
    );
    tracing::info!(endpoint = %report.authority_endpoint, "authority stream connected");
    tracing::info!(
        hosts = report.connector_hosts,
        default_timeout_ms = report.connector_default_timeout_ms,
        "connector registry built"
    );
    tracing::info!(addr = %report.interceptor_addr, "interceptor listening");
    tracing::info!("ready");
}

/// Compute the deterministic policy bundle version.
///
/// Concatenates the bytes of every `.cedar` file directly under
/// `policy_dir` (sorted by file name for reproducibility), hashes the
/// result with SHA-256, and returns `(version_hex_prefix, count)`.
///
/// # Errors
///
/// Returns an error when the directory cannot be read.
pub fn compute_policy_bundle_version(policy_dir: &Path) -> std::io::Result<(String, usize)> {
    let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(policy_dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "cedar"))
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err),
    };
    entries.sort();

    let mut hasher = Sha256::new();
    for path in &entries {
        let bytes = std::fs::read(path)?;
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        write!(hex, "{byte:02x}").map_err(std::io::Error::other)?;
    }
    Ok((hex, entries.len()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn version_prefix_is_eight_hex_chars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.cedar"),
            b"permit(principal, action, resource);",
        )
        .unwrap();
        let (version, count) = compute_policy_bundle_version(dir.path()).unwrap();
        assert_eq!(version.len(), 8);
        assert_eq!(count, 1);
        assert!(version.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn version_is_stable_across_call_order_when_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.cedar"), b"permit;").unwrap();
        std::fs::write(dir.path().join("b.cedar"), b"forbid;").unwrap();
        let (v1, _) = compute_policy_bundle_version(dir.path()).unwrap();
        let (v2, _) = compute_policy_bundle_version(dir.path()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn missing_dir_returns_empty_count() {
        let dir = tempfile::tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let (version, count) = compute_policy_bundle_version(&nope).unwrap();
        assert_eq!(count, 0);
        // Empty hash prefix is the SHA-256 of the empty string,
        // truncated to 8 hex chars.
        assert_eq!(version, "e3b0c442");
    }

    #[test]
    fn skips_non_cedar_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.cedar"), b"permit;").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();
        let (_, count) = compute_policy_bundle_version(dir.path()).unwrap();
        assert_eq!(count, 1);
    }
}
