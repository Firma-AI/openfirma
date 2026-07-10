//! Smoke: `--authority`, `--authority-profile` accepted; conflict with
//! `--no-autostart + --authority local` detected.
//!
//! Follows the existing pattern in `run_autostart_flags.rs`:
//! `env!("CARGO_BIN_EXE_firma")` + `std::process::Command`. No new
//! dev-dep needed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::process::Command;

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

#[test]
fn authority_flag_listed_in_help() {
    let out = Command::new(firma_bin())
        .args(["run", "--help"])
        .output()
        .expect("run --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--authority"),
        "missing flag in help: {stdout}"
    );
    assert!(stdout.contains("--authority-profile"));
}

#[test]
fn no_autostart_with_authority_local_conflicts() {
    let out = Command::new(firma_bin())
        .args([
            "run",
            "--no-autostart",
            "--authority",
            "local",
            "--",
            "true",
        ])
        .output()
        .expect("invoke");
    assert!(!out.status.success(), "must reject: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--no-autostart") && stderr.contains("--authority local"),
        "expected conflict message, got: {stderr}"
    );
}
