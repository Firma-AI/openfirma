//! Smoke test: the one test PR #174 should have shipped.
//!
//! Scaffolds a real persisted config with `firma config`, deletes the
//! authority signing key to mimic a `$XDG_RUNTIME_DIR` tmpfs wiped on reboot,
//! then runs `firma run -- echo hello` end to end and asserts the sandboxed
//! command actually executes. Regression guard for the persisted-authority
//! autostart path, which used to fail closed with "failed to read key file …
//! No such file or directory" when the configured key had vanished.
//!
//! The whole point: exercise the full `firma run` startup — authority + sidecar
//! + sandbox — not just a subcommand's `--help`.
//!
//! Linux-only: `firma run` confines structurally via bubblewrap. When the
//! sandbox itself is unavailable (bwrap not installed, or the host cannot
//! create unprivileged user namespaces — common on CI runners, WSL, hardened
//! kernels), the test skips rather than fails: a missing sandbox is an
//! environment limitation, not the regression under test. The always-running
//! `regenerates_missing_key_file` unit test in `firma-run` guards the fix
//! itself on every platform without needing a sandbox.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

/// Substrings that mean the host cannot provide the bubblewrap sandbox
/// `firma run` needs. All of these are emitted *before* the authority key is
/// read, so none can mask the regression under test (a missing key surfaces as
/// "authority autostart failed" / "failed to read key file").
#[cfg(target_os = "linux")]
const SANDBOX_UNAVAILABLE_MARKERS: &[&str] = &[
    "bubblewrap is not installed",
    "backend error (bwrap)",
    "user namespace creation is restricted",
    "unprivileged user namespaces",
    "max_user_namespaces",
    "requires unprivileged user namespaces",
    "WSL",
];

#[cfg(target_os = "linux")]
#[test]
fn run_executes_echo_after_authority_key_was_wiped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");

    // 1. Scaffold a full agent-local stack (sidecar + co-located authority).
    let status = Command::new(firma_bin())
        .args([
            "config",
            "-y",
            "--mode",
            "agent-local",
            "--profile",
            "generic",
            "--posture",
            "dev",
        ])
        .arg("--output-dir")
        .arg(&cfg_dir)
        .arg("--state-dir")
        .arg(&state_dir)
        .status()
        .expect("spawn firma config");
    assert!(status.success(), "firma config scaffold failed");

    let config_path = cfg_dir.join("firma.toml");
    let key_file = state_dir.join("authority.key");
    assert!(key_file.is_file(), "config should have generated the key");

    // 2. Simulate the runtime-dir wipe: the persisted config still points at a
    //    key that no longer exists on disk.
    std::fs::remove_file(&key_file).expect("remove authority key");
    let _ = std::fs::remove_file(state_dir.join("authority.pub"));
    assert!(!key_file.exists(), "precondition: key absent before run");

    // 3. Run the full stack against a trivial command.
    let output = Command::new(firma_bin())
        .args(["run", "--profile", "generic"])
        .arg("--config")
        .arg(&config_path)
        .args(["--", "echo", "hello"])
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn firma run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success()
        && SANDBOX_UNAVAILABLE_MARKERS
            .iter()
            .any(|m| stderr.contains(m))
    {
        eprintln!("skipping: sandbox unavailable on this host:\n{stderr}");
        return;
    }

    assert!(
        output.status.success(),
        "firma run failed (regression?):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("hello"),
        "expected 'hello' from the sandboxed command:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The wiped key must have been regenerated on demand.
    assert!(
        key_file.is_file(),
        "authority key should have been regenerated on demand"
    );
}
