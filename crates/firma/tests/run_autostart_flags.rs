//! CLI surface for `firma run --sidecar`. Verifies clap accepts the unified
//! `--sidecar <local|url>` flag and that invalid forms are rejected.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics acceptable on test failure"
)]

use std::process::Command;

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

#[test]
fn parse_sidecar_local() {
    let out = Command::new(firma_bin())
        .args(["run", "--sidecar", "local", "--help"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "--sidecar local rejected: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn parse_sidecar_endpoint_urls() {
    for value in ["tcp://127.0.0.1:8080", "unix:///tmp/firma.sock"] {
        let out = Command::new(firma_bin())
            .args(["run", "--sidecar", value, "--help"])
            .output()
            .expect("spawn");
        assert!(
            out.status.success(),
            "--sidecar {value} rejected: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn parse_no_autostart_alone() {
    let out = Command::new(firma_bin())
        .args(["run", "--no-autostart", "--help"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_autostart_with_sidecar_url_is_accepted_by_clap() {
    // No longer a clap conflict — `--sidecar <url>` + `--no-autostart` is a
    // valid (redundant) combination. `--help` short-circuits before runtime.
    let out = Command::new(firma_bin())
        .args([
            "run",
            "--no-autostart",
            "--sidecar",
            "tcp://127.0.0.1:8080",
            "--help",
        ])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "expected clap to accept the combination: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn sidecar_local_with_no_autostart_fails_at_runtime() {
    // No `--help`, so the run executes selection resolution, which rejects
    // the incompatible pair with the typed error.
    let out = Command::new(firma_bin())
        .args(["run", "--sidecar", "local", "--no-autostart", "--", "true"])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected runtime failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--sidecar local` is incompatible with `--no-autostart"),
        "expected SidecarLocalNoAutostart message, got: {stderr}"
    );
}

#[test]
fn parse_sidecar_config_template_path() {
    let out = Command::new(firma_bin())
        .args([
            "run",
            "--sidecar-config",
            "/etc/firma/sidecar.toml",
            "--help",
        ])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn sidecar_invalid_endpoint_fails_at_runtime() {
    // `--sidecar` is `Option<String>` at the clap layer, so an invalid
    // endpoint is only rejected at runtime during selection resolution.
    let out = Command::new(firma_bin())
        .args(["run", "--sidecar", "http://nope", "--", "true"])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected runtime failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported sidecar endpoint"),
        "expected endpoint-parse error, got: {stderr}"
    );
}

#[test]
fn parse_sidecar_startup_timeout_secs() {
    let out = Command::new(firma_bin())
        .args(["run", "--sidecar-startup-timeout-secs", "30", "--help"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
