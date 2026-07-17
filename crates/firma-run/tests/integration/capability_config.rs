//! Capability verification-key configuration coverage for `firma run`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::{Path, PathBuf};

use firma_run::config::{CapabilitySource, resolve_profile};
use firma_run::runtime::RunInput;

fn run_input(config: &Path) -> RunInput {
    RunInput {
        profile: "codex".to_string(),
        config: Some(config.to_path_buf()),
        backend: None,
        sidecar_cli: firma_run::sidecar::SidecarCli::Unset,
        capability_file: None,
        identity_mode: None,
        preserve_host_user: false,
        print_effective_config: false,
        no_autostart: false,
        sidecar_template_path: None,
        sidecar_startup_timeout_secs: 10,
        command: vec!["echo".to_string(), "ok".to_string()],
        authority_cli: firma_run::authority::AuthorityCli::Unset,
        authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
        user_config_path: None,
        allow_non_structural: true,
        monitor_mode: false,
    }
}

#[test]
fn profile_capability_fields_merge_over_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.defaults.capability]
public_key_path = "keys/default.pub"
refresh_ratio = 0.55

[run.profiles.codex.capability]
grace_seconds = 45
"#,
    )
    .expect("write config");

    let resolved = resolve_profile(&run_input(&config_path)).expect("resolve profile");

    assert_eq!(
        resolved.capability.public_key_path,
        Some(PathBuf::from("keys/default.pub"))
    );
    assert!((resolved.capability.refresh_ratio - 0.55).abs() < f64::EPSILON);
    assert_eq!(resolved.capability.grace_seconds, 45);
}

#[test]
fn structured_profile_source_preserves_default_capability_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.defaults.capability]
kind = "file"
path = "default-capability.toml"
public_key_path = "keys/default.pub"
refresh_ratio = 0.55

[run.profiles.codex.capability]
grace_seconds = 45

[run.profiles.codex.capability.source]
kind = "disabled"
"#,
    )
    .expect("write config");

    let resolved = resolve_profile(&run_input(&config_path)).expect("resolve profile");

    assert_eq!(resolved.capability.source, CapabilitySource::Disabled);
    assert_eq!(
        resolved.capability.public_key_path,
        Some(PathBuf::from("keys/default.pub"))
    );
    assert!((resolved.capability.refresh_ratio - 0.55).abs() < f64::EPSILON);
    assert_eq!(resolved.capability.grace_seconds, 45);
}

#[test]
fn legacy_profile_source_preserves_default_capability_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.defaults.capability]
public_key_path = "keys/default.pub"
refresh_ratio = 0.55

[run.defaults.capability.source]
kind = "disabled"

[run.profiles.codex.capability]
kind = "file"
path = "profile-capability.toml"
grace_seconds = 45
"#,
    )
    .expect("write config");

    let resolved = resolve_profile(&run_input(&config_path)).expect("resolve profile");

    assert_eq!(
        resolved.capability.source,
        CapabilitySource::File {
            path: PathBuf::from("profile-capability.toml")
        }
    );
    assert_eq!(
        resolved.capability.public_key_path,
        Some(PathBuf::from("keys/default.pub"))
    );
    assert!((resolved.capability.refresh_ratio - 0.55).abs() < f64::EPSILON);
    assert_eq!(resolved.capability.grace_seconds, 45);
}

#[test]
fn cli_capability_source_preserves_profile_verification_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.defaults.capability]
public_key_path = "keys/default.pub"
refresh_ratio = 0.50

[run.profiles.codex.capability]
public_key_path = "keys/profile.pub"
grace_seconds = 60
"#,
    )
    .expect("write config");
    let capability_file = dir.path().join("existing-capability.toml");
    let mut input = run_input(&config_path);
    input.capability_file = Some(capability_file.clone());

    let resolved = resolve_profile(&input).expect("resolve profile");

    assert_eq!(
        resolved.capability.source,
        CapabilitySource::File {
            path: capability_file
        }
    );
    assert_eq!(
        resolved.capability.public_key_path,
        Some(PathBuf::from("keys/profile.pub"))
    );
    assert!((resolved.capability.refresh_ratio - 0.50).abs() < f64::EPSILON);
    assert_eq!(resolved.capability.grace_seconds, 60);
}

#[test]
fn omitted_verification_key_preserves_existing_behavior() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        "[run.profiles.codex.capability]\nrefresh_ratio = 0.60\n",
    )
    .expect("write config");

    let resolved = resolve_profile(&run_input(&config_path)).expect("resolve profile");

    assert_eq!(resolved.capability.public_key_path, None);
}
