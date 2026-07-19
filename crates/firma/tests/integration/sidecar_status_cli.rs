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

#[test]
fn traversal_id_is_rejected_before_marker_access() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create escaped marker target");
    std::fs::write(outside.join("metadata.toml"), "not valid toml = =")
        .expect("write escaped marker target");

    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["sidecar", "status", "--sandbox-id", "../outside"])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    insta::assert_snapshot!(stderr, @"
    error: invalid value '../outside' for '--sandbox-id <SANDBOX_ID>': sandbox id must be a UUID v7: invalid character: found `.` at 0

    For more information, try '--help'.
    ");
    assert!(
        !stderr.contains("failed to parse sidecar marker"),
        "lookup touched the escaped marker: {stderr}"
    );
}

#[test]
fn non_v7_status_id_is_rejected() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args([
            "sidecar",
            "status",
            "--sandbox-id",
            "550e8400-e29b-41d4-a716-446655440000",
        ])
        .output()
        .expect("spawn firma");
    assert_eq!(out.status.code(), Some(2));
    insta::assert_snapshot!(String::from_utf8_lossy(&out.stderr), @"
    error: invalid value '550e8400-e29b-41d4-a716-446655440000' for '--sandbox-id <SANDBOX_ID>': sandbox id must be a UUID v7

    For more information, try '--help'.
    ");
}

#[test]
fn missing_valid_v7_status_id_is_an_empty_result() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args([
            "sidecar",
            "status",
            "--sandbox-id",
            "01900000-0000-7000-8000-000000000001",
            "--json",
        ])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[]");
}
