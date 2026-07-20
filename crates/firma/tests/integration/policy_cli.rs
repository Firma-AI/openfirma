//! Black-box CLI tests for `firma policy validate` and `firma policy test`.
//!
//! Paths are built from [`CARGO_MANIFEST_DIR`] so the suite is independent of
//! the working directory (passes from any CWD and in CI). The `policy test`
//! cases pass an absolute fixture path; `bundle.path` inside each fixture is
//! resolved by the runner against the fixture file's parent directory, so the
//! relative `bundle/` reference stays correct regardless of CWD.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a testdata file under `tests/testdata/policy/`.
fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata/policy")
        .join(rel)
}

#[test]
fn validate_good_policy_exits_zero_with_ok() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["policy", "validate"])
        .arg(testdata("good.cedar"))
        .output()
        .expect("spawn firma");

    assert!(
        out.status.success(),
        "expected exit 0, got {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK"), "stdout missing OK: {stdout}");
}

#[test]
fn validate_bad_policy_exits_nonzero_with_line_and_column() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["policy", "validate"])
        .arg(testdata("bad.cedar"))
        .output()
        .expect("spawn firma");

    assert!(
        !out.status.success(),
        "expected non-zero exit for invalid policy, got success"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The graphical diagnostic encodes the primary span as a bracketed,
    // colon-separated `[..:line:col]` location; assert the trailing two parts
    // are integers so both a line and a column are present (not a byte
    // offset). Mirrors the unit-test notion in `policy::validate`.
    let has_line_col = stderr
        .match_indices('[')
        .filter_map(|(open, _)| {
            let close = stderr[open..].find(']')? + open;
            Some(&stderr[open + 1..close])
        })
        .any(|inner| {
            let mut parts = inner.rsplitn(3, ':');
            let col = parts.next();
            let line = parts.next();
            matches!(
                (line, col),
                (Some(line), Some(col))
                    if !line.is_empty()
                        && line.bytes().all(|b| b.is_ascii_digit())
                        && !col.is_empty()
                        && col.bytes().all(|b| b.is_ascii_digit())
            )
        });
    assert!(
        has_line_col,
        "stderr must carry a `[line:col]` location with integer line and \
         column; got:\n{stderr}"
    );
}

#[test]
fn test_allow_fixture_exits_zero_with_allow() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["policy", "test"])
        .arg(testdata("allow.toml"))
        .output()
        .expect("spawn firma");

    assert!(
        out.status.success(),
        "expected exit 0, got {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("ALLOW"),
        "stdout should start with ALLOW: {stdout}"
    );
}

#[test]
fn test_host_forbid_fixture_denies_metadata_endpoint() {
    // A forbid keyed on `resource.host` must fire in the offline validator,
    // proving host-attribute parity with the Sidecar hot path. The fixture
    // expects DENY, so a correctly-firing forbid yields exit 0 + "DENY".
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["policy", "test"])
        .arg(testdata("host_deny.toml"))
        .output()
        .expect("spawn firma");

    assert!(
        out.status.success(),
        "expected exit 0 (decision matches expected DENY), got {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("DENY"),
        "stdout should start with DENY: {stdout}"
    );
}

#[test]
fn test_deny_mismatch_fixture_exits_nonzero() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["policy", "test"])
        .arg(testdata("deny_mismatch.toml"))
        .output()
        .expect("spawn firma");

    assert!(
        !out.status.success(),
        "expected non-zero exit on decision/expectation mismatch, got success"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("expected DENY") && stderr.contains("got ALLOW"),
        "stderr should explain the mismatch; got:\n{stderr}"
    );
}
