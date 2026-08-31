//! Black-box CLI test: empty run dir => empty table, exit 0.

use std::process::Command;

use firma_identifiers::SandboxId;

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
fn status_explicitly_removes_stale_markers_before_listing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sandbox_id = "sbx_01j0000000e008000000000001";
    let marker_dir = tmp.path().join("run").join(sandbox_id);
    std::fs::create_dir_all(&marker_dir).expect("create marker directory");

    #[cfg(unix)]
    let mut child = Command::new("true")
        .spawn()
        .expect("spawn short-lived child");
    #[cfg(windows)]
    let mut child = Command::new("cmd")
        .args(["/C", "exit"])
        .spawn()
        .expect("spawn short-lived child");
    let pid = child.id();
    child.wait().expect("reap short-lived child");

    std::fs::write(
        marker_dir.join("metadata.toml"),
        format!(
            "sandbox_id = \"{sandbox_id}\"\n\
             agent_id = \"codex\"\n\
             session_id = \"session\"\n\
             authority_url = \"https://authority.local\"\n\
             policy_bundle_version = \"deadbeef\"\n\
             pid = {pid}\n\
             started_at = \"2026-05-18T10:00:00Z\"\n"
        ),
    )
    .expect("write stale marker");

    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["sidecar", "status", "--json"])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");

    assert!(out.status.success(), "status failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[]");
    assert!(!marker_dir.exists(), "stale marker was not removed");
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
    error: invalid value '../outside' for '--sandbox-id <SANDBOX_ID>': sandbox id must start with `sbx` as prefix: `../outside` does not

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
            "sbx_2n1t201rmv88eb2sj4cn248g00",
        ])
        .output()
        .expect("spawn firma");
    assert_eq!(out.status.code(), Some(2));
    insta::assert_snapshot!(String::from_utf8_lossy(&out.stderr), @"
    error: invalid value 'sbx_2n1t201rmv88eb2sj4cn248g00' for '--sandbox-id <SANDBOX_ID>': sandbox id must be backed by a UUID v7: `sbx_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4

    For more information, try '--help'.
    ");
}

#[test]
fn missing_valid_status_id_is_an_empty_result() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sandbox_id = SandboxId::generate().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args([
            "sidecar",
            "status",
            "--sandbox-id",
            sandbox_id.as_str(),
            "--json",
        ])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[]");
}

#[test]
fn malformed_daemon_pidfile_exits_two() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pidfile = tmp.path().join("sidecar.pid");
    std::fs::write(&pidfile, "not-a-pid\n").expect("write malformed pidfile");

    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["sidecar", "status", "--daemon", "--json"])
        .env("FIRMA_STATE_DIR", tmp.path())
        .output()
        .expect("spawn firma");

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&*pidfile.to_string_lossy()),
        "diagnostic omitted pidfile path: {stderr}"
    );
    insta::assert_snapshot!(stderr.replace(&*pidfile.to_string_lossy(), "[PIDFILE]"), @r#"[ERR]  sidecar status: invalid pidfile '[PIDFILE]': expected one canonical non-zero decimal process ID followed by a newline, got "not-a-pid\n""#);
}
