//! Tests for `firma config`.
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

fn run_init(config_dir: &Path, state_dir: &Path) {
    let output = firma()
        .args(["config", "--yes", "--output-dir"])
        .arg(config_dir)
        .args(["--state-dir"])
        .arg(state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_unified_config_parses(firma_toml: &Path) {
    let text = std::fs::read_to_string(firma_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", firma_toml.display()));
    toml::from_str::<toml::Value>(&text)
        .unwrap_or_else(|e| panic!("parse {}: {e}\n---\n{text}", firma_toml.display()));

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
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let firma_toml = config_dir.join("firma.toml");
    assert!(firma_toml.is_file(), "firma.toml in config_dir");
    assert!(!config_dir.join("authority.toml").exists());
    assert!(!config_dir.join("sidecar.toml").exists());

    // Keys must be in state_dir, not config_dir.
    assert!(
        state_dir.join("authority.key").is_file(),
        "authority.key in state_dir"
    );
    assert!(
        state_dir.join("audit.key").is_file(),
        "audit.key in state_dir"
    );
    assert!(
        !config_dir.join("authority.key").exists(),
        "no authority.key in config_dir"
    );

    assert_unified_config_parses(&firma_toml);
}

#[test]
fn init_state_paths_in_config_are_absolute() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    let text = std::fs::read_to_string(config_dir.join("firma.toml")).unwrap();
    let value: toml::Value = toml::from_str(&text).unwrap();

    let key_file = value["authority"]["key_file"]
        .as_str()
        .expect("authority.key_file");
    assert!(
        Path::new(key_file).is_absolute(),
        "authority.key_file must be absolute, got {key_file}"
    );

    let audit_path = value["sidecar"]["audit"]["file_path"]
        .as_str()
        .expect("sidecar.audit.file_path");
    assert!(
        Path::new(audit_path).is_absolute(),
        "sidecar.audit.file_path must be absolute, got {audit_path}"
    );
}

#[test]
fn init_handles_relative_paths() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let work = tmp.path().join("workdir");
    std::fs::create_dir_all(&work).unwrap();
    let state_dir = tmp.path().join("state");

    let output = firma()
        .current_dir(&work)
        .args([
            "config",
            "--yes",
            "--output-dir",
            "../config",
            "--state-dir",
        ])
        .arg(&state_dir)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "init (relative) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let firma_toml = work.join("../config/firma.toml");
    assert!(
        firma_toml.is_file(),
        "firma.toml does not exist: {}",
        firma_toml.display()
    );
    assert_unified_config_parses(&firma_toml);
}

#[cfg(unix)]
#[test]
fn init_writes_sensitive_dirs_with_mode_0700() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    for path in [
        &config_dir,
        &config_dir.join("policies"),
        &config_dir.join("issuance-policies"),
        &state_dir,
        &state_dir.join("generated-firma-ca"),
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
            path.display()
        );
    }
}
