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

use firma_config::CONFIG_DIR_NAME;

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
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "{CONFIG_DIR_NAME}/ must not be created on non-TTY abort"
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
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "{CONFIG_DIR_NAME}/ must not be created on --no-autostart abort"
    );
}

#[test]
fn copilot_command_auto_selects_profile_without_flag() {
    // `firma run copilot` (no --profile) must infer the copilot profile and
    // reach config resolution — same gating as codex — rather than rejecting
    // `copilot` as an unknown command/profile.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cwd = tmp.path();

    let out = Command::new(firma_bin())
        .current_dir(cwd)
        .args(["run", "--no-autostart", "copilot"])
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
        "copilot must be accepted and fail at config resolution, not as unknown profile:\n{stderr}"
    );
    assert!(
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "{CONFIG_DIR_NAME}/ must not be created on --no-autostart abort"
    );
}

#[test]
fn explicit_missing_run_config_does_not_scaffold() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cwd = tmp.path();
    let missing = cwd.join("missing-run.toml");

    let out = Command::new(firma_bin())
        .current_dir(cwd)
        .args(["run", "--config"])
        .arg(&missing)
        .arg("codex")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("FIRMA_CONFIG")
        .output()
        .expect("spawn firma run");

    assert!(!out.status.success(), "missing explicit --config must fail");
    assert!(
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "{CONFIG_DIR_NAME}/ must not be created when explicit --config is missing"
    );
}

#[test]
fn remote_authority_does_not_implicit_scaffold_without_trust_material() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cwd = tmp.path();

    let out = Command::new(firma_bin())
        .current_dir(cwd)
        .args([
            "run",
            "--authority",
            "https://authority.example.com:9443",
            "codex",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("FIRMA_CONFIG")
        .output()
        .expect("spawn firma run");

    assert!(
        !out.status.success(),
        "remote implicit init without trust material must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent-remote") && stderr.contains("--authority-pub-key"),
        "stderr should explain how to configure remote authority trust material:\n{stderr}"
    );
    assert!(
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "{CONFIG_DIR_NAME}/ must not be created for incomplete remote implicit init"
    );
}
