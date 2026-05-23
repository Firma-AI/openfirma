//! Implicit-init gating in `firma run`.
//!
//! Spec §4.1: implicit init creates a long-lived Ed25519 key and persists
//! `[authority]` to firma.toml. Both must be gated on a deliberate user
//! choice — `--authority` flag, an existing `firma.toml`, or an
//! interactive y/N prompt. Non-TTY without commitment aborts before any
//! filesystem mutation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

/// Run `firma run codex` in `cwd` with stdin redirected from /dev/null
/// (Unix) or NUL (Windows) so the prompt sees a non-TTY.
fn run_non_tty(cwd: &std::path::Path) -> std::process::Output {
    Command::new(firma_bin())
        .current_dir(cwd)
        .args(["run", "codex"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("FIRMA_CONFIG")
        .output()
        .expect("spawn firma run")
}

#[test]
fn non_tty_without_authority_flag_errors_before_scaffolding() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cwd = tmp.path();

    let out = run_non_tty(cwd);

    assert!(
        !out.status.success(),
        "firma run must fail when no firma.toml + no TTY + no --authority"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("stdin is not a terminal") || stderr.contains("--authority"),
        "stderr should hint at --authority / firma config:\n{stderr}"
    );

    // Verify no scaffolding happened. .firma/ must not exist.
    assert!(
        !cwd.join(".firma").exists(),
        ".firma/ must not be created on non-TTY abort"
    );
}

#[test]
fn no_autostart_without_firma_toml_errors_with_hint() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cwd = tmp.path();

    let out = Command::new(firma_bin())
        .current_dir(cwd)
        .args(["run", "--no-autostart", "codex"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("FIRMA_CONFIG")
        .output()
        .expect("spawn firma run");

    assert!(
        !out.status.success(),
        "--no-autostart with no firma.toml must fail"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("firma config") || stderr.contains("--no-autostart"),
        "stderr should hint at firma config:\n{stderr}"
    );
    assert!(
        !cwd.join(".firma").exists(),
        ".firma/ must not be created on --no-autostart abort"
    );
}
