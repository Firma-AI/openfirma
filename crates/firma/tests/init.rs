//! Tests for `firma init`.
//!
//! Verifies that the scaffolded unified `firma.toml` is syntactically
//! valid, round-trips through the strict section loader, and that both
//! component config types deserialize from their sections. Regression
//! guard for Windows path serialization: backslash-bearing paths must not
//! be emitted into TOML basic strings (where `\t`, `\s`, etc. are invalid
//! escape sequences).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::Path;
use std::process::Command;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn run_init(output_dir: &Path) {
    let output = firma()
        .args(["init", "--yes", "--output-dir"])
        .arg(output_dir)
        .output()
        .expect("spawn firma init");
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_unified_config_parses(firma_toml: &Path) {
    // The single firma.toml must parse as TOML — the regression we are
    // guarding against is unescaped backslashes inside basic strings on
    // Windows (e.g. `key_file = "C:\Users\..."` choking on `\U`).
    let text = std::fs::read_to_string(firma_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", firma_toml.display()));
    toml::from_str::<toml::Value>(&text)
        .unwrap_or_else(|e| panic!("parse {}: {e}\n---\n{text}", firma_toml.display()));

    // Both sections must round-trip through the strict loader and
    // deserialize into their component config types.
    let abody = firma_config::load_section(firma_toml, "authority")
        .unwrap_or_else(|e| panic!("[authority] section: {e}"));
    toml::from_str::<firma_authority::AuthorityConfig>(&abody)
        .unwrap_or_else(|e| panic!("[authority] deserialize: {e}\n---\n{abody}"));

    let sbody = firma_config::load_section(firma_toml, "sidecar")
        .unwrap_or_else(|e| panic!("[sidecar] section: {e}"));
    toml::from_str::<firma_sidecar::config::SidecarConfig>(&sbody)
        .unwrap_or_else(|e| panic!("[sidecar] deserialize: {e}\n---\n{sbody}"));
}

#[test]
fn init_writes_parseable_config() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let output_dir = tmp.path().join("config");

    run_init(&output_dir);

    let firma_toml = output_dir.join("firma.toml");
    assert!(firma_toml.is_file(), "firma.toml created");
    // No legacy files.
    assert!(!output_dir.join("authority.toml").exists());
    assert!(!output_dir.join("sidecar.toml").exists());
    assert!(!output_dir.join("firma-stack.toml").exists());

    assert_unified_config_parses(&firma_toml);
}

#[test]
fn init_handles_relative_paths() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let work = tmp.path().join("workdir");
    std::fs::create_dir_all(&work).unwrap();

    let output = firma()
        .current_dir(&work)
        .args(["init", "--yes", "--output-dir", "../config"])
        .output()
        .expect("spawn firma init");
    assert!(
        output.status.success(),
        "init (relative) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let firma_toml = work.join("../config/firma.toml");
    assert!(
        firma_toml.is_file(),
        "firma.toml does not exist on disk: {}",
        firma_toml.display(),
    );

    assert_unified_config_parses(&firma_toml);
}

#[cfg(unix)]
#[test]
fn init_writes_sensitive_dirs_with_mode_0700() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().expect("tmpdir");
    let output_dir = tmp.path().join("config");

    run_init(&output_dir);

    for path in [
        &output_dir,
        &output_dir.join(".runtime"),
        &output_dir.join(".runtime/generated-firma-ca"),
        &output_dir.join("policies"),
        &output_dir.join("issuance-policies"),
    ] {
        let mode = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o700,
            "expected {} to be mode 0700, got {mode:o}",
            path.display(),
        );
    }
}
