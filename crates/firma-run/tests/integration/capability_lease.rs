#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use firma_run::capability::read_capability_token;
use firma_run::config::CapabilitySource;
use firma_run::error::RunError;
use firma_run::runtime::{LaunchHooks, RunInput, execute_run};
use firma_test_helpers::process_fixture;
use serde::{Deserialize, Serialize};

const RAW_TOKEN: &str = "v4.public.authority-issued-token";

fn write_seed(path: &std::path::Path, raw_token: &str) -> String {
    let body = super::helper::canonical_seed_toml(raw_token);
    std::fs::write(path, &body).expect("write capability seed");
    body
}

fn assert_safe_parse_error(path: &std::path::Path, body: &str, secret: &str) {
    std::fs::write(path, body).expect("write invalid capability seed");

    let error = read_capability_token(&CapabilitySource::File {
        path: path.to_path_buf(),
    })
    .expect_err("noncanonical capability seed must fail closed")
    .to_string();

    assert!(error.contains(&path.display().to_string()), "got: {error}");
    assert!(error.contains("is not canonical CapabilitySeed TOML"));
    assert!(
        !error.contains(secret),
        "error exposed seed material: {error}"
    );
    assert!(
        !error.contains(body),
        "error exposed seed document: {error}"
    );
}

#[test]
fn disabled_source_yields_no_token() {
    let token =
        read_capability_token(&CapabilitySource::Disabled).expect("disabled source never fails");

    assert!(token.is_none());
}

#[test]
fn file_source_extracts_exact_raw_token_from_canonical_seed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");
    let body = write_seed(&seed_path, RAW_TOKEN);

    let token = read_capability_token(&CapabilitySource::File { path: seed_path })
        .expect("read token file");

    assert_eq!(token.as_deref(), Some(RAW_TOKEN));
    assert_ne!(token.as_deref(), Some(body.as_str()));
}

#[test]
fn plain_token_file_fails_closed_without_exposing_token() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");

    assert_safe_parse_error(&seed_path, RAW_TOKEN, RAW_TOKEN);
}

#[test]
fn malformed_seed_fails_closed_without_exposing_document() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");
    let secret = "v4.public.secret-parser-canary";
    let body = format!("raw_token = \"{secret}\"\n[invalid");

    assert_safe_parse_error(&seed_path, &body, secret);
}

#[test]
fn incomplete_seed_fails_closed_without_exposing_token() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");
    let mut body = super::helper::canonical_seed_toml(RAW_TOKEN);
    let context_hash = body
        .find("context_hash")
        .expect("canonical seed has context_hash");
    body.truncate(context_hash);

    assert_safe_parse_error(&seed_path, &body, RAW_TOKEN);
}

#[test]
fn unknown_seed_field_fails_closed_without_exposing_value() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");
    let unknown_value = "secret-unknown-value";
    let body = format!(
        "{}unknown = \"{unknown_value}\"\n",
        super::helper::canonical_seed_toml(RAW_TOKEN)
    );

    assert_safe_parse_error(&seed_path, &body, unknown_value);
}

#[test]
fn empty_raw_token_fails_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");
    write_seed(&seed_path, "  ");

    let error = read_capability_token(&CapabilitySource::File { path: seed_path })
        .expect_err("empty raw_token must fail closed");

    assert!(error.to_string().contains("empty raw_token"));
}

#[test]
fn non_utf8_seed_fails_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let seed_path = tempdir.path().join("seed.toml");
    std::fs::write(&seed_path, [0xff, 0xfe]).expect("write non-UTF-8 seed");

    let error = read_capability_token(&CapabilitySource::File { path: seed_path })
        .expect_err("non-UTF-8 seed must fail closed");

    assert!(error.to_string().contains("valid UTF-8"));
}

#[test]
fn missing_file_source_fails_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let token_path = tempdir.path().join("does-not-exist.txt");

    let err = read_capability_token(&CapabilitySource::File { path: token_path })
        .expect_err("unreadable capability file must fail closed");

    assert!(err.to_string().contains("does-not-exist.txt"));
}

#[derive(Debug, Serialize, Deserialize)]
struct RejectionFixture {
    config_path: String,
    seed_path: String,
}

#[test]
fn noncanonical_seed_is_rejected_before_backend_preparation() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config_path = tempdir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    std::fs::write(
        &config_path,
        format!(
            "[sidecar.authority]\nagent_id = \"{}\"\n\n[run]\nprofile = \"generic\"\n",
            super::helper::agent_id()
        ),
    )
    .expect("write config");
    let seed_path = tempdir.path().join("plain-token.txt");
    std::fs::write(&seed_path, RAW_TOKEN).expect("write plain token");

    let status = rejection_before_backend_fixture(RejectionFixture {
        config_path: config_path.display().to_string(),
        seed_path: seed_path.display().to_string(),
    })
    .status()
    .expect("run lifecycle fixture");

    assert!(status.success());
}

process_fixture! {
    fn rejection_before_backend_fixture(config: RejectionFixture) {
        let config_path = std::path::PathBuf::from(config.config_path);
        let args = RunInput {
            profile: "generic".to_string(),
            config: Some(config_path.clone()),
            backend: Some(firma_run::backend::BackendKind::Wsl2),
            sidecar_cli: firma_run::sidecar::SidecarCli::Unset,
            capability_file: Some(std::path::PathBuf::from(config.seed_path)),
            identity_mode: None,
            preserve_host_user: false,
            print_effective_config: false,
            no_autostart: false,
            sidecar_template_path: None,
            sidecar_startup_timeout_secs: 10,
            command: vec!["echo".to_string(), "must-not-launch".to_string()],
            authority_cli: firma_run::authority::AuthorityCli::Unset,
            authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
            user_config_path: Some(config_path),
            allow_non_structural: true,
            monitor_mode: false,
        };

        let error = execute_run(&args, &LaunchHooks::default())
            .expect_err("noncanonical seed must stop before backend preparation");

        assert!(matches!(error, RunError::Capability(_)), "got: {error}");
    }
}
