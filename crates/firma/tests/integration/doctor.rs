//! End-to-end smoke test for `firma doctor`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::process::Command;

use serde_json::Value;

#[test]
fn doctor_json_emits_valid_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"));

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
