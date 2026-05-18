//! Black-box CLI test: empty run dir => empty table, exit 0.

use std::process::Command;

#[test]
fn empty_runtime_dir_lists_nothing_and_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["sidecar", "status"])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");

    assert!(
        out.status.success(),
        "expected exit 0, got {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SANDBOX_ID"), "header missing: {stdout}");
}

#[test]
fn json_mode_emits_array() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["sidecar", "status", "--json"])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "[]");
}
