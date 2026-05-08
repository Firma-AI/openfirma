//! Locks task 002's acceptance criterion against the canonical
//! reference config: every malformed sidecar TOML must exit non-zero
//! with a diagnostic that names the offending key.
//!
//! The cases below exercise three distinct failure modes:
//!
//! - parse error (typo in `[interceptor]` field name)
//! - validation error (`log.level = "verbose"`)
//! - validation error (`policy.dir` empty)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

fn write_config(toml_body: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("sidecar.toml");
    std::fs::write(&path, toml_body).unwrap();
    (tmp, path)
}

fn run_sidecar(config_path: &PathBuf) -> (i32, String, String) {
    let output = Command::new(firma_bin())
        .args(["sidecar", "--config-file"])
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn firma sidecar");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn invalid_interceptor_mode_exits_non_zero() {
    let (_tmp, cfg) = write_config(
        r#"
[interceptor]
mode = "telnet"
listen_addr = "127.0.0.1:7474"
"#,
    );
    let (code, _, stderr) = run_sidecar(&cfg);
    assert_ne!(code, 0, "expected non-zero exit; stderr: {stderr}");
    let lowered = stderr.to_lowercase();
    assert!(
        lowered.contains("interceptor") || lowered.contains("mode") || lowered.contains("telnet"),
        "diagnostic should reference the offending field; got: {stderr}",
    );
}

#[test]
fn invalid_log_level_exits_non_zero() {
    let (_tmp, cfg) = write_config(
        r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:7474"

[log]
level = "verbose"
"#,
    );
    let (code, _, stderr) = run_sidecar(&cfg);
    assert_ne!(code, 0, "expected non-zero exit; stderr: {stderr}");
    assert!(
        stderr.contains("log.level") || stderr.contains("verbose"),
        "diagnostic should mention log.level: {stderr}",
    );
}

#[test]
fn empty_policy_dir_exits_non_zero() {
    let (_tmp, cfg) = write_config(
        r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:7474"

[policy]
dir = ""
"#,
    );
    let (code, _, stderr) = run_sidecar(&cfg);
    assert_ne!(code, 0, "expected non-zero exit; stderr: {stderr}");
    assert!(
        stderr.contains("policy.dir"),
        "diagnostic should mention policy.dir: {stderr}",
    );
}
