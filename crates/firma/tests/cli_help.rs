//! Smoke test: `--help` exits 0 for every subcommand.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::process::Command;

fn firma_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for the [[bin]] under test.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

fn assert_help(args: &[&str], expect: &[&str]) {
    let output = Command::new(firma_bin())
        .args(args)
        .output()
        .expect("spawn firma");
    assert!(
        output.status.success(),
        "firma {args:?} --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in expect {
        assert!(
            stdout.contains(needle),
            "missing `{needle}` in output of firma {args:?}: {stdout}"
        );
    }
}

#[test]
fn top_level_help_lists_subcommands() {
    assert_help(&["--help"], &["sidecar", "authority", "run"]);
}

#[test]
fn sidecar_help_ok() {
    assert_help(&["sidecar", "--help"], &["--config", "FIRMA_SIDECAR"]);
}

#[test]
fn authority_help_ok() {
    assert_help(
        &["authority", "--help"],
        &["revocations", "generate-key", "issue"],
    );
}

#[test]
fn authority_revocations_help_ok() {
    assert_help(&["authority", "revocations", "--help"], &["add", "compact"]);
}

#[test]
fn run_help_ok() {
    assert_help(&["run", "--help"], &["--profile", "--backend"]);
}

#[test]
fn dns_stub_help_ok() {
    assert_help(&["__dns-stub", "--help"], &["--listen"]);
}

#[test]
fn proxy_bridge_help_ok() {
    assert_help(
        &["__proxy-bridge", "--help"],
        &["--listen", "--upstream-uds"],
    );
}
