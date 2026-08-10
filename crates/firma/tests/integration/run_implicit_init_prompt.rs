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

use super::CONFIG_DIR_NAME;

fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

fn isolated_firma_command(cwd: &std::path::Path) -> Command {
    let mut command = Command::new(firma_bin());
    command.current_dir(cwd).env_remove("FIRMA_CONFIG");
    // Pin the trusted config directory to the empty tmp cwd so discovery cannot
    // pick up the developer's real `~/.firma`; otherwise these no-config abort
    // paths would find an unrelated machine-wide config and proceed.
    #[cfg(unix)]
    {
        command.env("HOME", cwd).env_remove("XDG_CONFIG_HOME");
    }
    #[cfg(windows)]
    {
        command.env("USERPROFILE", cwd);
    }
    command
}

/// Run `firma run codex` in `cwd` with stdin redirected from /dev/null
/// (Unix) or NUL (Windows) so the prompt sees a non-TTY.
fn run_non_tty(cwd: &std::path::Path) -> std::process::Output {
    isolated_firma_command(cwd)
        .args(["run", "codex"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    let out = isolated_firma_command(cwd)
        .args(["run", "--no-autostart", "codex"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    let out = isolated_firma_command(cwd)
        .args(["run", "--no-autostart", "copilot"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    let out = isolated_firma_command(cwd)
        .args(["run", "--config"])
        .arg(&missing)
        .arg("codex")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn firma run");

    assert!(!out.status.success(), "missing explicit --config must fail");
    assert!(
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "{CONFIG_DIR_NAME}/ must not be created when explicit --config is missing"
    );
}

/// `firma run --authority local` with no config and no TTY commits to local
/// implicit init: it scaffolds into the trusted config directory (`$HOME/.firma`)
/// — never a cwd-local `.firma` a planted config could shadow — then launches a
/// real local stack for the wrapped command. Driving `true` keeps the launch
/// short; a clean exit is also what flushes coverage for the scaffold path.
///
/// Linux-only: implicit init launches a real `bwrap` sandbox. The absence of
/// `bwrap`/user namespaces fails the test loudly rather than silently skipping.
#[cfg(target_os = "linux")]
#[test]
fn authority_local_implicit_init_scaffolds_into_trusted_dir_and_runs() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let home = tmp.path().join("home");
    let cwd = tmp.path().join("cwd");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();

    let mut command = Command::new(firma_bin());
    command
        .current_dir(&cwd)
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("FIRMA_CONFIG")
        // No --profile: the scaffold must infer the wrapped command's profile.
        .args([
            "run",
            "--authority",
            "local",
            "--sidecar",
            "local",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = command.output().expect("spawn firma run");

    assert!(
        out.status.success(),
        "implicit init + local stack run must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Scaffold lands in the trusted config directory, not cwd/.firma.
    assert!(
        home.join(CONFIG_DIR_NAME)
            .join(super::CONFIG_FILE_NAME)
            .is_file(),
        "implicit init must scaffold firma.toml into $HOME/.firma"
    );
    assert!(
        !cwd.join(CONFIG_DIR_NAME).exists(),
        "implicit init must not create a cwd-local {CONFIG_DIR_NAME}/"
    );
}

#[test]
fn remote_authority_does_not_implicit_scaffold_without_trust_material() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cwd = tmp.path();

    let out = isolated_firma_command(cwd)
        .args([
            "run",
            "--authority",
            "https://authority.example.com:9443",
            "codex",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
