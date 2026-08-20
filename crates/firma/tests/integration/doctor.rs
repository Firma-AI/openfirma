//! End-to-end smoke test for `firma doctor`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::PathBuf;
use std::process::Command;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::os::unix::net::UnixListener;

use serde_json::Value;

#[test]
fn doctor_json_emits_valid_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_firma"));

    let output = Command::new(&bin)
        .args(["doctor", "--json", "--state-dir"])
        .arg(tmp.path())
        .args(["--timeout-ms", "250"])
        .output()
        .expect("spawn firma doctor");

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor stdout was not JSON: {e}; raw: {stdout}"));

    assert!(parsed["checks"].is_array(), "checks must be array");
    assert!(parsed["exit_code"].is_number(), "exit_code must be number");

    let categories: Vec<&str> = parsed["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .filter_map(|c| c["category"].as_str())
        .collect();

    for required in [
        "firma binary",
        "sandbox bwrap",
        "sandbox vz",
        "sandbox wsl2",
        "sandbox firecracker",
        "sidecar reachable",
        "authority reachable",
        "config parsed",
        "capability seed",
        "state dir",
        "data dir",
    ] {
        assert!(
            categories.contains(&required),
            "missing category {required}; got {categories:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn doctor_uses_lifecycle_socket_default_when_path_is_omitted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    fs::create_dir(&state_dir).expect("create state directory");
    let mut permissions = fs::metadata(&state_dir)
        .expect("read state directory metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&state_dir, permissions).expect("restrict state directory permissions");
    let socket_path = state_dir.join("sidecar.sock");
    let _listener = UnixListener::bind(&socket_path).expect("bind sidecar socket");
    let config_path = tmp.path().join("firma.toml");
    fs::write(
        &config_path,
        "[sidecar.interceptor]\nmode = \"unix_socket\"\n",
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["doctor", "--json", "--config"])
        .arg(&config_path)
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--timeout-ms", "250"])
        .output()
        .expect("spawn firma doctor");

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "doctor stdout was not JSON: {error}; raw: {stdout}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        output.status.code(),
        parsed["exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok()),
        "process status must match the rendered report"
    );
    let sidecar_check = parsed["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|check| check["category"] == "sidecar reachable")
        .expect("sidecar reachability check");

    assert_eq!(sidecar_check["status"], "ok");
    assert_eq!(
        sidecar_check["detail"]["path"],
        socket_path.to_string_lossy().as_ref()
    );
}
