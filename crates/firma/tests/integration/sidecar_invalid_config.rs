//! Every malformed sidecar TOML must exit non-zero with a diagnostic that
//! names the offending key and, where one exists, what replaces it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{CONFIG_FILE_NAME, firma_bin};

fn write_config(toml_body: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(&path, toml_body).unwrap();
    (tmp, path)
}

/// The state directory a spawned Sidecar resolves its unset artifact paths
/// against. Always a temporary one: pointing at the host default would let the
/// developer's own audit key and trust anchors decide the outcome.
fn state_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("state")
}

fn run_sidecar(config_path: &PathBuf) -> (i32, String, String) {
    let output = Command::new(firma_bin())
        .args(["sidecar", "--config"])
        .arg(config_path)
        .env("FIRMA_STATE_DIR", state_dir(config_path))
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
[sidecar.interceptor]
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
fn empty_policy_dir_exits_non_zero() {
    let (_tmp, cfg) = write_config(
        r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:7474"

[sidecar.policy]
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

#[test]
fn relative_env_config_rebases_sidecar_resources_from_an_absolute_dir() {
    let current_dir = std::env::current_dir().unwrap();
    let tmp = tempfile::tempdir_in(&current_dir).unwrap();
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join(CONFIG_FILE_NAME);
    std::fs::write(
        &config_path,
        r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:0"

[sidecar.audit]
signing_key_path = "missing-signing.key"
[sidecar.authority]
url = "http://127.0.0.1:50051"
"#,
    )
    .unwrap();
    let relative_config = config_path.strip_prefix(&current_dir).unwrap();

    let output = Command::new(firma_bin())
        .arg("sidecar")
        .env("FIRMA_CONFIG", relative_config)
        .env("FIRMA_STATE_DIR", state_dir(&config_path))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn firma sidecar");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let expected_signing_key_path = config_dir.join("missing-signing.key");
    assert!(
        !output.status.success(),
        "expected startup failure: {stderr}"
    );
    assert!(
        stderr.contains(&expected_signing_key_path.display().to_string()),
        "diagnostic must use the absolute config-relative signing-key path {}: {stderr}",
        expected_signing_key_path.display()
    );
}

/// The Authority CA is adopted from the state directory when the config names
/// none, so a diagnostic that only says "set `authority.ca_cert_path`" never
/// tells the operator which file the Sidecar looked for.
#[test]
fn https_authority_without_ca_names_the_state_dir_default() {
    let (_tmp, cfg) = write_config(
        r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:7474"

[sidecar.authority]
url = "https://authority.test:9443"
"#,
    );

    let (code, _, stderr) = run_sidecar(&cfg);

    assert_ne!(code, 0, "expected non-zero exit; stderr: {stderr}");
    let expected = state_dir(&cfg).join("tls").join("authority-ca.crt");
    assert!(
        stderr.contains(&expected.display().to_string()),
        "diagnostic must name the state-directory default {}: {stderr}",
        expected.display()
    );
}

/// Upgrading operators meet a removed `[sidecar.mapping]` table at Sidecar
/// startup first, so the startup diagnostic must name where mappings live now
/// rather than only reporting an unknown field. Without `[authority]` the file
/// cannot list mapping files, so the diagnostic points at the connected
/// Authority instead of suggesting a section that would start a local one.
#[test]
fn removed_sidecar_mapping_table_points_at_the_connected_authority() {
    let (_tmp, cfg) = write_config(
        r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:7474"

[sidecar.mapping]
rules_path = "mapping-rules.toml"

[sidecar.authority]
url = "http://127.0.0.1:50051"
"#,
    );

    let (code, _, stderr) = run_sidecar(&cfg);

    assert_ne!(code, 0, "expected non-zero exit; stderr: {stderr}");
    let config_path = cfg.display().to_string();
    assert!(stderr.contains(&config_path), "{stderr}");
    insta::assert_snapshot!(stderr.replace(&config_path, "[CONFIG]"), @"[ERR]  failed to load `[CONFIG]` from Flag: [CONFIG]: `[sidecar.mapping]` is no longer supported because the Authority owns mappings; delete it and configure mappings on the Authority this Sidecar connects to");
}
