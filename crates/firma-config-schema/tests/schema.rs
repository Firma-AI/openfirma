//! Serde-contract tests for the config schema.
//!
//! The crate is representation only, so its contract is the wire mapping:
//! `snake_case` enum renames, per-field defaults, and human-readable byte
//! sizes. These are asserted here independently of any consumer. Format is
//! JSON for convenience; the `serde` attributes under test are
//! format-agnostic.

use bytesize::ByteSize;
use firma_config_schema::sidecar::infra::{
    CaConfig, CredentialMode, CredentialTransform, LogConfig, PolicyConfig, SidecarMode,
};
use firma_config_schema::sidecar::interceptor::{InterceptorConfig, InterceptorMode};

#[test]
fn interceptor_config_fills_defaults_for_missing_fields() {
    let config: InterceptorConfig = serde_json::from_str("{}").expect("empty object deserializes");

    assert_eq!(config.mode, InterceptorMode::default());
    assert_eq!(config.drain_timeout_secs, 30);
    assert_eq!(config.max_request_body_bytes, 4 * 1024 * 1024);
    assert_eq!(config.max_decompressed_body_size, ByteSize::mb(16));
    assert_eq!(config.total_body_budget_bytes, 64 * 1024 * 1024);
    assert_eq!(config.connect_relay.setup_timeout_secs, 10);
    assert_eq!(config.connect_relay.session_max_secs, 600);
    assert!(config.https_mitm.enabled);
    assert!(config.https_mitm.bypass_hosts.is_empty());
    assert_eq!(
        config.https_mitm.intercept_hosts,
        config.https_mitm.strict_hosts,
    );
}

#[test]
fn interceptor_mode_uses_snake_case() {
    let cases = [
        (r#""http_proxy""#, InterceptorMode::HttpProxy),
        (r#""grpc""#, InterceptorMode::Grpc),
        #[cfg(unix)]
        (r#""unix_socket""#, InterceptorMode::UnixSocket),
    ];
    for (json, expected) in cases {
        let mode: InterceptorMode = serde_json::from_str(json).expect("mode deserializes");
        assert_eq!(mode, expected);
    }
}

#[test]
fn max_decompressed_body_size_accepts_human_readable_units() {
    let config: InterceptorConfig =
        serde_json::from_str(r#"{ "max_decompressed_body_size": "8 MB" }"#)
            .expect("human-readable size deserializes");
    assert_eq!(config.max_decompressed_body_size, ByteSize::mb(8));
}

#[test]
fn sidecar_infra_enums_use_snake_case() {
    assert_eq!(
        serde_json::from_str::<SidecarMode>(r#""enforce""#).expect("mode"),
        SidecarMode::Enforce,
    );
    assert_eq!(
        serde_json::from_str::<SidecarMode>(r#""monitor""#).expect("mode"),
        SidecarMode::Monitor,
    );
    assert_eq!(
        serde_json::from_str::<CredentialMode>(r#""basic""#).expect("mode"),
        CredentialMode::Basic,
    );
    assert_eq!(
        serde_json::from_str::<CredentialMode>(r#""vault""#).expect("mode"),
        CredentialMode::Vault,
    );
    assert_eq!(
        serde_json::from_str::<CredentialTransform>(r#""github_pat_basic""#).expect("transform"),
        CredentialTransform::GithubPatBasic,
    );
}

#[test]
fn infra_sections_default_to_documented_paths() {
    assert_eq!(
        PolicyConfig::default().dir,
        std::path::PathBuf::from("./policies/"),
    );
    assert_eq!(
        CaConfig::default().dir,
        std::path::PathBuf::from("./firma-ca/"),
    );
    assert_eq!(LogConfig::default().level, "info");
}
