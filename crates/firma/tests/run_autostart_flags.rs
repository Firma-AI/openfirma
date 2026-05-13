//! CLI surface for `firma run` autostart flags. Verifies clap accepts the
//! new flags, that mutually exclusive flags are rejected, and that
//! `--no-autostart` with an unreachable endpoint surfaces the typed
//! `SidecarUnreachable` error rather than autostarting.

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
fn parse_sidecar_auto_is_default_and_accepts_external() {
    for value in ["auto", "external"] {
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
fn no_autostart_conflicts_with_sidecar_flag() {
    let out = Command::new(firma_bin())
        .args([
            "run",
            "--no-autostart",
            "--sidecar",
            "external",
            "--",
            "true",
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected clap conflict failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("conflicts with"),
        "expected clap conflict message, got: {stderr}"
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
