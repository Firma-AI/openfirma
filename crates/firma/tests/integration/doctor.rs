//! End-to-end smoke test for `firma doctor`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::PathBuf;
use std::process::{Command, Output};

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

fn config_check_from_output(output: &Output) -> Value {
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "doctor stdout was not JSON: {error}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    parsed["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|check| check["category"] == "config parsed")
        .expect("config parsed check")
        .clone()
}

#[test]
fn config_commands_expose_only_canonical_environment_variable() {
    for command in ["doctor", "control", "monitor"] {
        let output = Command::new(env!("CARGO_BIN_EXE_firma"))
            .args([command, "--help"])
            .output()
            .unwrap_or_else(|error| panic!("spawn firma {command}: {error}"));
        assert!(output.status.success());

        let help = String::from_utf8(output.stdout).expect("UTF-8 help");
        assert!(
            help.contains("FIRMA_CONFIG"),
            "{command} help must expose FIRMA_CONFIG: {help}"
        );
        assert!(
            !help.contains("FIRMA_STACK_CONFIG"),
            "{command} help must not expose FIRMA_STACK_CONFIG: {help}"
        );
    }
}

#[test]
fn doctor_uses_only_canonical_config_environment_variable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("firma.toml");
    std::fs::write(&config_path, "[sidecar]\n").expect("write config");
    let removed_path = tmp.path().join("removed.toml");
    std::fs::write(&removed_path, "not valid TOML").expect("write removed config");

    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["doctor", "--json", "--state-dir"])
        .arg(tmp.path())
        .env("FIRMA_CONFIG", &config_path)
        .env("FIRMA_STACK_CONFIG", &removed_path)
        .current_dir(tmp.path())
        .output()
        .expect("spawn firma doctor");
    let config_check = config_check_from_output(&output);

    assert_eq!(config_check["status"], "ok");
    assert_eq!(
        config_check["detail"]["path"],
        config_path.to_string_lossy().as_ref()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["doctor", "--json", "--config"])
        .arg(&config_path)
        .arg("--state-dir")
        .arg(tmp.path())
        .env("FIRMA_CONFIG", &removed_path)
        .env("FIRMA_STACK_CONFIG", &removed_path)
        .current_dir(tmp.path())
        .output()
        .expect("spawn firma doctor");
    let config_check = config_check_from_output(&output);

    assert_eq!(config_check["status"], "ok");
    assert_eq!(
        config_check["detail"]["path"],
        config_path.to_string_lossy().as_ref()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["doctor", "--json", "--state-dir"])
        .arg(tmp.path())
        .env_remove("FIRMA_CONFIG")
        .env("FIRMA_STACK_CONFIG", &removed_path)
        .current_dir(tmp.path())
        .output()
        .expect("spawn firma doctor");
    let config_check = config_check_from_output(&output);

    assert_eq!(config_check["status"], "fail");
    assert_eq!(
        config_check["reason"],
        "could not resolve firma.toml: no config found"
    );

    let discovered_dir = tmp.path().join(".firma");
    std::fs::create_dir(&discovered_dir).expect("create project config directory");
    let discovered_path = discovered_dir.join("firma.toml");
    std::fs::write(&discovered_path, "not valid TOML").expect("write discovered config");

    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["doctor", "--json", "--state-dir"])
        .arg(tmp.path())
        .env_remove("FIRMA_CONFIG")
        .env("FIRMA_STACK_CONFIG", &removed_path)
        .current_dir(tmp.path())
        .output()
        .expect("spawn firma doctor");
    let config_check = config_check_from_output(&output);
    let reason = config_check["reason"].as_str().expect("failure reason");

    assert_eq!(config_check["status"], "fail");
    assert!(
        reason.contains(discovered_path.to_string_lossy().as_ref()),
        "failure must identify discovered config '{}'; got: {reason}",
        discovered_path.display()
    );
    assert!(
        !reason.contains(removed_path.to_string_lossy().as_ref()),
        "removed environment input must not be selected: {reason}"
    );
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
