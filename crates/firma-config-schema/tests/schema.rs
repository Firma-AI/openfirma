//! Serde-contract tests for the config schema.
//!
//! The crate is representation only, so its contract is the wire mapping:
//! `snake_case` enum renames, per-field defaults, and human-readable byte
//! sizes. These are asserted here independently of any consumer. Format is
//! JSON for convenience; the `serde` attributes under test are
//! format-agnostic.

use std::time::Duration;

use bytesize::ByteSize;
use firma_config_schema::sidecar::infra::{
    CaConfig, CredentialMode, CredentialTransform, PolicyConfig, SidecarMode,
};
use firma_config_schema::sidecar::interceptor::{InterceptorConfig, InterceptorMode};
use firma_config_schema::{authority, run, secret_matcher, sidecar};

#[test]
fn interceptor_config_fills_defaults_for_missing_fields() {
    let config: InterceptorConfig = serde_json::from_str("{}").expect("empty object deserializes");

    assert_eq!(config.mode, InterceptorMode::default());
    // `Default` must match the deserialize default for socket_path (both
    // `None`); the validating constructor in `firma-sidecar` resolves the
    // built-in default path for `unix_socket` mode.
    assert_eq!(config.socket_path, None);
    assert_eq!(InterceptorConfig::default().socket_path, None);
    assert_eq!(config.drain_timeout, Duration::from_secs(30));
    assert_eq!(config.max_request_body_bytes, 4 * 1024 * 1024);
    assert_eq!(config.max_decompressed_body_size, ByteSize::mb(16));
    assert_eq!(config.total_body_budget_bytes, 64 * 1024 * 1024);
    assert_eq!(config.connect_relay.setup_timeout, Duration::from_secs(10));
    assert_eq!(config.connect_relay.session_max, Duration::from_mins(10));
    assert!(config.https_mitm.enabled);
    assert!(config.https_mitm.bypass_hosts.is_empty());
    assert_eq!(
        config.https_mitm.intercept_hosts,
        config.https_mitm.strict_hosts,
    );
}

#[test]
fn interceptor_drain_timeout_accepts_subsecond_duration() {
    let config: sidecar::SidecarConfig = toml::from_str(
        r#"
        [interceptor]
        drain_timeout = "500ms"
        "#,
    )
    .expect("human-readable duration deserializes");

    assert_eq!(config.interceptor.drain_timeout, Duration::from_millis(500));
}

#[test]
fn connect_setup_timeout_accepts_subsecond_duration() {
    let config: sidecar::SidecarConfig = toml::from_str(
        r#"
        [interceptor.connect_relay]
        setup_timeout = "500ms"
        "#,
    )
    .expect("human-readable duration deserializes");

    assert_eq!(
        config.interceptor.connect_relay.setup_timeout,
        Duration::from_millis(500)
    );
}

#[test]
fn connect_session_max_accepts_subsecond_duration() {
    let config: sidecar::SidecarConfig = toml::from_str(
        r#"
        [interceptor.connect_relay]
        session_max = "750ms"
        "#,
    )
    .expect("human-readable duration deserializes");

    assert_eq!(
        config.interceptor.connect_relay.session_max,
        Duration::from_millis(750)
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
fn legacy_authority_max_ttl_seconds_key_is_rejected() {
    assert!(toml::from_str::<authority::AuthorityConfig>("max_ttl_seconds = 3600\n").is_err());
}

#[test]
fn legacy_authority_bundle_ttl_seconds_key_is_rejected() {
    assert!(toml::from_str::<authority::AuthorityConfig>("bundle_ttl_seconds = 30\n").is_err());
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
}

#[test]
fn authority_rejects_direct_and_flat_tls_typos() {
    for (field, config) in [
        ("listen_adrr", "listen_adrr = \"127.0.0.1:50051\""),
        ("tls_cert_pat", "tls_cert_pat = \"authority.pem\""),
    ] {
        let error = toml::from_str::<authority::AuthorityConfig>(config)
            .expect_err("unknown authority field must fail");
        assert!(error.to_string().contains(field), "error: {error}");
    }
}

#[test]
fn sidecar_rejects_stale_and_nested_fields() {
    for (field, config) in [
        (
            "preflight",
            "[preflight]\nsession_id = \"removed-session\"\n",
        ),
        (
            "drain_timeout_sec",
            "[interceptor]\ndrain_timeout_sec = 30\n",
        ),
    ] {
        let error = toml::from_str::<sidecar::SidecarConfig>(config)
            .expect_err("unknown sidecar field must fail");
        assert!(error.to_string().contains(field), "error: {error}");
    }
}

#[test]
fn sidecar_rejects_unknown_fields_in_dynamic_map_values() {
    let error = toml::from_str::<sidecar::SidecarConfig>(
        r#"
[credentials.openai]
target_host = "api.openai.com"
header = "authorization"
value_from_env = "OPENAI_API_KEY"
target_hots = "typo.example.com"
"#,
    )
    .expect_err("unknown credential field must fail");

    assert!(error.to_string().contains("target_hots"), "error: {error}");
}

#[test]
fn sidecar_rejects_unknown_fields_in_tagged_variants() {
    let error = toml::from_str::<sidecar::SidecarConfig>(
        r#"
[[http_secret_providers]]
provider_id = "vault"
host = "vault.example.com"

[[http_secret_providers.matchers]]
type = "safe_command"
path = "/health"
stale_option = true
"#,
    )
    .expect_err("unknown tagged-variant field must fail");

    assert!(error.to_string().contains("stale_option"), "error: {error}");
}

#[test]
fn secret_matcher_rejects_unknown_selector_fields() {
    let error = serde_json::from_str::<secret_matcher::SecretMatcher>(
        r#"{
            "type": "json",
            "record_path": "$[*]",
            "value_path": "$.value",
            "name": { "source": "record_key" },
            "item_selector": {
                "path": "$.title",
                "scope": "record",
                "selector_typo": true
            }
        }"#,
    )
    .expect_err("unknown nested selector field must fail");

    assert!(
        error.to_string().contains("selector_typo"),
        "error: {error}"
    );
}

#[test]
fn run_rejects_unknown_fields_in_defaults_and_every_profile() {
    for (field, config) in [
        ("sidecar_endpont", "[defaults]\nsidecar_endpont = \"x\"\n"),
        (
            "allow_non_structurals",
            "[profiles.selected]\nallow_non_structurals = true\n",
        ),
        (
            "identity_modes",
            "[profiles.unselected]\nidentity_modes = \"host_user\"\n",
        ),
    ] {
        let error = toml::from_str::<run::FileConfig>(config)
            .expect_err("unknown run profile field must fail");
        assert!(error.to_string().contains(field), "error: {error}");
    }
}

#[test]
fn run_validates_backends_in_defaults_and_unselected_profiles() {
    for config in [
        "[defaults]\nbackend = \"bworp\"\n",
        "[profiles.unselected]\nbackend = \"bworp\"\n",
    ] {
        let error = toml::from_str::<run::FileConfig>(config)
            .expect_err("unknown backend must fail whole-file parsing");
        assert!(error.to_string().contains("bworp"), "error: {error}");
    }
}

#[test]
fn intentional_run_compatibility_keys_still_parse() {
    let config = toml::from_str::<run::FileConfig>(
        r#"
[defaults.capability]
kind = "file"
path = "capability.toml"

[defaults.codex_cli]
enforce_wrapper_defaults = true
"#,
    )
    .expect("legacy capability and codex_cli keys remain supported");

    assert!(config.defaults.capability.is_some());
    assert!(config.defaults.codex_cli.is_some());
}
