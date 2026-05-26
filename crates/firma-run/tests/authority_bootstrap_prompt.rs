//! Integration tests for the first-run Authority bootstrap prompt.
//!
//! These exercise the decision matrix inside `routing::resolve_authority`:
//! when the prompt fires, when it is bypassed, and what gets persisted.
//! A non-existent `firma_exe` forces `AuthoritySupervisor::spawn` to fail,
//! letting us assert on bootstrap side-effects (prompt invocation counts,
//! persisted `firma.toml`) without actually launching an Authority.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::error::RunError;
use firma_run::identity::RunIdentity;
use firma_run::routing::{AutostartFlags, resolve_authority};

struct RecordingPrompt {
    tty: bool,
    answer: bool,
    confirm_calls: usize,
}

impl RecordingPrompt {
    fn new(tty: bool, answer: bool) -> Self {
        Self {
            tty,
            answer,
            confirm_calls: 0,
        }
    }
}

impl AuthorityPromptIo for RecordingPrompt {
    fn is_tty(&self) -> bool {
        self.tty
    }
    fn confirm(&mut self, _prompt: &str) -> std::io::Result<bool> {
        self.confirm_calls += 1;
        Ok(self.answer)
    }
}

fn flags() -> AutostartFlags {
    AutostartFlags {
        sidecar_autostart: false,
        no_autostart: false,
        template_path: None,
        startup_timeout: Duration::from_millis(200),
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        use_http_proxy_sidecar: false,
    }
}

/// Skip the test when something already serves `[::1]:50051` — the
/// resolver short-circuits in that case and never reaches the prompt.
fn skip_if_port_bound() -> bool {
    TcpStream::connect_timeout(
        &"[::1]:50051".parse().expect("parse ipv6 addr"),
        Duration::from_millis(100),
    )
    .is_ok()
}

fn fake_firma_exe(tmp: &std::path::Path) -> PathBuf {
    tmp.join("does-not-exist-firma")
}

#[test]
fn prompt_fires_when_no_commit_and_persists_on_yes() {
    if skip_if_port_bound() {
        eprintln!("skip: [::1]:50051 already in use");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    let identity = RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");

    let mut prompt = RecordingPrompt::new(true, true);
    let err = resolve_authority(
        &identity,
        &runtime_dir,
        &flags(),
        &AuthorityCli::Unset,
        "developer",
        Some(cfg.as_path()),
        cfg.parent(),
        &fake_firma_exe(tmp.path()),
        &mut prompt,
    )
    .err()
    .expect("spawn must fail with bogus firma_exe");

    // Bootstrap path ran: prompt invoked + section persisted before spawn.
    assert_eq!(prompt.confirm_calls, 1);
    let persisted = std::fs::read_to_string(&cfg).unwrap();
    assert!(persisted.contains("[authority]"), "got: {persisted}");
    assert!(
        persisted.contains(r#"listen_addr = "[::1]:0""#),
        "got: {persisted}"
    );
    // Final error is the spawn failure, not the bootstrap path. The
    // exact variant differs by platform (`AuthorityStartupFailed` on Unix,
    // `UnsupportedPlatform` on Windows); both prove spawn was attempted.
    assert!(
        !matches!(
            err,
            RunError::AuthorityBootstrapDeclined | RunError::AuthorityBootstrapNoTty
        ),
        "{err:?}"
    );
}

#[test]
fn prompt_declined_returns_typed_error_and_does_not_persist() {
    if skip_if_port_bound() {
        eprintln!("skip: [::1]:50051 already in use");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    let identity = RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");

    let mut prompt = RecordingPrompt::new(true, false);
    let err = resolve_authority(
        &identity,
        &runtime_dir,
        &flags(),
        &AuthorityCli::Unset,
        "developer",
        Some(cfg.as_path()),
        cfg.parent(),
        &fake_firma_exe(tmp.path()),
        &mut prompt,
    )
    .err()
    .expect("declined prompt must surface a typed error");

    assert_eq!(prompt.confirm_calls, 1);
    assert!(
        matches!(err, RunError::AuthorityBootstrapDeclined),
        "{err:?}"
    );
    assert!(!cfg.exists(), "firma.toml must not be written on decline");
}

#[test]
fn no_tty_returns_typed_error_without_calling_confirm() {
    if skip_if_port_bound() {
        eprintln!("skip: [::1]:50051 already in use");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    let identity = RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");

    let mut prompt = RecordingPrompt::new(false, true);
    let err = resolve_authority(
        &identity,
        &runtime_dir,
        &flags(),
        &AuthorityCli::Unset,
        "developer",
        Some(cfg.as_path()),
        cfg.parent(),
        &fake_firma_exe(tmp.path()),
        &mut prompt,
    )
    .err()
    .expect("no-tty must surface a typed error");

    assert_eq!(prompt.confirm_calls, 0);
    assert!(matches!(err, RunError::AuthorityBootstrapNoTty), "{err:?}");
    assert!(!cfg.exists(), "firma.toml must not be written on no-tty");
}

#[test]
fn cli_local_skips_prompt_even_without_config() {
    if skip_if_port_bound() {
        eprintln!("skip: [::1]:50051 already in use");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    let identity = RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");

    let mut prompt = RecordingPrompt::new(true, false);
    let err = resolve_authority(
        &identity,
        &runtime_dir,
        &flags(),
        &AuthorityCli::Local,
        "developer",
        Some(cfg.as_path()),
        cfg.parent(),
        &fake_firma_exe(tmp.path()),
        &mut prompt,
    )
    .err()
    .expect("spawn must fail with bogus firma_exe");

    // `--authority local` is a commitment: prompt must not be consulted.
    assert_eq!(prompt.confirm_calls, 0);
    assert!(!cfg.exists(), "CLI commitment must not trigger persistence");
    // Spawn was reached: exact variant differs by platform
    // (`AuthorityStartupFailed` on Unix, `UnsupportedPlatform` on Windows).
    assert!(
        !matches!(
            err,
            RunError::AuthorityBootstrapDeclined | RunError::AuthorityBootstrapNoTty
        ),
        "{err:?}"
    );
}

#[test]
fn config_authority_section_skips_prompt() {
    if skip_if_port_bound() {
        eprintln!("skip: [::1]:50051 already in use");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    std::fs::write(&cfg, "[authority]\nlisten_addr = \"[::1]:0\"\n").unwrap();
    let identity = RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");

    let mut prompt = RecordingPrompt::new(true, false);
    let err = resolve_authority(
        &identity,
        &runtime_dir,
        &flags(),
        &AuthorityCli::Unset,
        "developer",
        Some(cfg.as_path()),
        cfg.parent(),
        &fake_firma_exe(tmp.path()),
        &mut prompt,
    )
    .err()
    .expect("spawn must fail with bogus firma_exe");

    assert_eq!(prompt.confirm_calls, 0);
    // Spawn was reached: exact variant differs by platform
    // (`AuthorityStartupFailed` on Unix, `UnsupportedPlatform` on Windows).
    assert!(
        !matches!(
            err,
            RunError::AuthorityBootstrapDeclined | RunError::AuthorityBootstrapNoTty
        ),
        "{err:?}"
    );
}
