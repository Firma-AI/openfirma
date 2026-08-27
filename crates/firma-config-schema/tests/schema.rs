//! Serde-contract tests for the config schema.
//!
//! The crate is representation only, so its contract is the wire mapping:
//! `snake_case` enum renames, per-field defaults, and human-readable byte
//! sizes. These are asserted here independently of any consumer. Format is
//! JSON for convenience; the `serde` attributes under test are
//! format-agnostic.

use bytesize::ByteSize;
use firma_config_schema::sidecar::infra::{
    CaConfig, CredentialMode, CredentialTransform, PolicyConfig, SidecarMode,
};
use firma_config_schema::sidecar::interceptor::{InterceptorConfig, InterceptorMode};
use firma_config_schema::utils::{NonZeroDuration, ZeroDurationError};
use firma_config_schema::{authority, gateway, run, secret_matcher, sidecar};
use serde::Deserialize;
use std::time::Duration;

#[test]
fn non_zero_duration_accepts_friendly_compact_durations() {
    for (json, expected) in [
        (r#""1h""#, Duration::from_hours(1)),
        (r#""30s""#, Duration::from_secs(30)),
        (r#""500ms""#, Duration::from_millis(500)),
    ] {
        let non_zero_duration: NonZeroDuration =
            serde_json::from_str(json).expect("friendly non-zero duration parses");
        assert_eq!(non_zero_duration.duration(), expected);
    }
}

#[test]
fn non_zero_duration_rejects_equivalent_friendly_zero_values() {
    for value in ["0ns", "0ms", "0s", "0m", "0h"] {
        let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value);
        let error =
            NonZeroDuration::deserialize(deserializer).expect_err("zero duration must fail");
        assert_eq!(error.to_string(), "duration must be greater than zero");
    }
}

#[test]
fn non_zero_duration_accepts_sub_millisecond_non_zero_duration() {
    let non_zero_duration: NonZeroDuration =
        serde_json::from_str(r#""1ns""#).expect("nanosecond duration parses");

    assert_eq!(non_zero_duration.duration(), Duration::from_nanos(1));
}

#[test]
fn non_zero_duration_construction_rejects_zero() {
    assert_eq!(NonZeroDuration::new(Duration::ZERO), Err(ZeroDurationError));
    assert_eq!(
        NonZeroDuration::try_from(Duration::ZERO),
        Err(ZeroDurationError)
    );
    assert_eq!(
        ZeroDurationError.to_string(),
        "duration must be greater than zero"
    );

    let duration = Duration::from_nanos(1);
    let non_zero_duration =
        NonZeroDuration::try_from(duration).expect("non-zero duration constructs successfully");
    assert_eq!(Duration::from(non_zero_duration), duration);
}

#[test]
fn non_zero_duration_serialization_round_trips_with_friendly_representation() {
    let non_zero_duration = NonZeroDuration::new(Duration::new(65, 123_456_789))
        .expect("non-zero duration constructs successfully");

    let serialized =
        serde_json::to_string(&non_zero_duration).expect("non-zero duration serializes");
    let value: serde_json::Value =
        serde_json::from_str(&serialized).expect("serialized non-zero duration is JSON");
    assert!(
        value.is_string(),
        "non-zero duration must serialize as a string"
    );

    let deserialized: NonZeroDuration =
        serde_json::from_str(&serialized).expect("serialized non-zero duration deserializes");
    assert_eq!(deserialized, non_zero_duration);
}

#[test]
fn interceptor_config_fills_defaults_for_missing_fields() {
    let config: InterceptorConfig = serde_json::from_str("{}").expect("empty object deserializes");

    assert_eq!(config.mode, InterceptorMode::default());
    // `Default` must match the deserialize default for socket_path (both
    // `None`); the validating constructor in `firma-sidecar` resolves the
    // built-in default path for `unix_socket` mode.
    assert_eq!(config.socket_path, None);
    assert_eq!(InterceptorConfig::default().socket_path, None);
    assert_eq!(config.drain_timeout.duration(), Duration::from_secs(30));
    assert_eq!(config.max_request_body_size, ByteSize::mib(4));
    assert_eq!(config.max_decompressed_body_size, ByteSize::mb(16));
    assert_eq!(config.total_body_budget, ByteSize::mib(64));
    assert_eq!(
        config.connect_relay.setup_timeout.duration(),
        Duration::from_secs(10)
    );
    assert_eq!(
        config.connect_relay.session_max.duration(),
        Duration::from_mins(10)
    );
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
fn byte_size_fields_require_unit_bearing_strings() {
    for config in [
        "[interceptor]\nmax_request_body_size = 4194304\n",
        "[interceptor]\nmax_decompressed_body_size = 16000000\n",
        "[interceptor]\ntotal_body_budget = 67108864\n",
        "[audit]\nwal_max_size = 104857600\n",
        "[secret_gateway]\nmax_buffer_size = 10000000\n",
        "[interceptor]\nmax_request_body_size = \"4194304\"\n",
    ] {
        assert!(
            toml::from_str::<sidecar::SidecarConfig>(config).is_err(),
            "raw byte size must be rejected: {config}"
        );
    }
}

#[test]
fn secret_gateway_connection_timeout_rejects_zero() {
    let error = toml::from_str::<gateway::GatewayClientConfig>("connection_timeout = \"0s\"")
        .expect_err("zero connection timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn secret_gateway_operation_timeout_rejects_zero() {
    let error = toml::from_str::<gateway::GatewayClientConfig>("operation_timeout = \"0ms\"")
        .expect_err("zero operation timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn run_mediator_timeout_rejects_zero() {
    let error =
        toml::from_str::<run::FileConfig>("[profiles.test.sidecar_local_exec]\ntimeout = \"0s\"\n")
            .expect_err("zero mediator timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn run_mediator_hitl_max_wait_rejects_zero() {
    let error = toml::from_str::<run::FileConfig>(
        "[profiles.test.sidecar_local_exec]\nhitl_max_wait = \"0m\"\n",
    )
    .expect_err("zero HITL maximum wait must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_authority_connect_timeout_rejects_zero() {
    let error =
        toml::from_str::<sidecar::SidecarConfig>("[authority]\nconnect_timeout = \"0ns\"\n")
            .expect_err("zero Authority connect timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_authority_reconnect_min_backoff_rejects_zero() {
    let error =
        toml::from_str::<sidecar::SidecarConfig>("[authority]\nreconnect_min_backoff = \"0ms\"\n")
            .expect_err(
                "zero Authority minimum reconnect backoff must fail during deserialization",
            );

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_authority_reconnect_max_backoff_rejects_zero() {
    let error =
        toml::from_str::<sidecar::SidecarConfig>("[authority]\nreconnect_max_backoff = \"0s\"\n")
            .expect_err(
                "zero Authority maximum reconnect backoff must fail during deserialization",
            );

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_interceptor_drain_timeout_rejects_zero() {
    let error = toml::from_str::<sidecar::SidecarConfig>("[interceptor]\ndrain_timeout = \"0m\"\n")
        .expect_err("zero interceptor drain timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_connect_relay_setup_timeout_rejects_zero() {
    let error = toml::from_str::<sidecar::SidecarConfig>(
        "[interceptor.connect_relay]\nsetup_timeout = \"0h\"\n",
    )
    .expect_err("zero CONNECT relay setup timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_connect_relay_session_max_rejects_zero() {
    let error = toml::from_str::<sidecar::SidecarConfig>(
        "[interceptor.connect_relay]\nsession_max = \"0s\"\n",
    )
    .expect_err("zero CONNECT relay session maximum must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_connector_default_timeout_rejects_zero() {
    let error =
        toml::from_str::<sidecar::SidecarConfig>("[connector]\ndefault_timeout = \"0ns\"\n")
            .expect_err("zero connector default timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_connector_host_timeout_rejects_zero() {
    let error = toml::from_str::<sidecar::SidecarConfig>(
        r#"
        [[connector.hosts]]
        host = "api.example.com"
        rps = 10
        burst = 5
        timeout = "0ms"
        "#,
    )
    .expect_err("zero per-host connector timeout must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_local_exec_retry_after_rejects_zero() {
    let error = toml::from_str::<sidecar::SidecarConfig>(
        "[local_exec]\nsocket_path = \"/run/firma/local-exec.sock\"\nretry_after = \"0s\"\n",
    )
    .expect_err("zero local-exec retry interval must fail during deserialization");

    assert!(error.span().is_some(), "error must identify the input span");
    assert!(
        error
            .to_string()
            .contains("duration must be greater than zero"),
        "error: {error}"
    );
}

#[test]
fn sidecar_scalar_fields_accept_human_readable_units() {
    let config: sidecar::SidecarConfig = toml::from_str(
        r#"
        [interceptor]
        drain_timeout = "500ms"
        max_request_body_size = "4 MiB"
        total_body_budget = "64 MiB"

        [connector]
        default_timeout = "30s"

        [audit]
        wal_max_size = "100 MiB"
        "#,
    )
    .expect("human-readable scalar values deserialize");

    assert_eq!(
        config.interceptor.drain_timeout.duration(),
        Duration::from_millis(500)
    );
    assert_eq!(config.interceptor.max_request_body_size, ByteSize::mib(4));
    assert_eq!(config.interceptor.total_body_budget, ByteSize::mib(64));
    assert_eq!(
        config.connector.default_timeout.duration(),
        Duration::from_secs(30)
    );
    assert_eq!(config.audit.wal_max_size, ByteSize::mib(100));
}

#[test]
fn superseded_numeric_scalar_keys_are_rejected() {
    for config in ["max_ttl_seconds = 3600\n", "bundle_ttl_seconds = 30\n"] {
        assert!(
            toml::from_str::<authority::AuthorityConfig>(config).is_err(),
            "superseded Authority scalar must be rejected: {config}"
        );
    }

    for config in [
        "[interceptor]\ndrain_timeout_secs = 30\n",
        "[interceptor]\nmax_request_body_bytes = 4194304\n",
        "[interceptor]\ntotal_body_budget_bytes = 67108864\n",
        "[interceptor.connect_relay]\nsetup_timeout_secs = 10\n",
        "[interceptor.connect_relay]\nsession_max_secs = 600\n",
        "[interceptor.https_mitm]\ncert_ttl_secs = 86400\n",
        "[capability_validation]\nclock_skew_tolerance_seconds = 5\n",
        "[connector]\ndefault_timeout_ms = 30000\n",
        "[[connector.hosts]]\nhost = \"api.example.com\"\nrps = 1\nburst = 1\ntimeout_ms = 5000\n",
        "[connector]\nhosts = [{ host = \"api.example.com\", rps = 1, burst = 1, timeout_ms = 5000 }]\n",
        "[audit]\nwal_max_bytes = 104857600\n",
        "[authority]\nconnect_timeout_secs = 10\n",
        "[authority]\nreconnect_min_backoff_ms = 250\n",
        "[authority]\nreconnect_max_backoff_secs = 30\n",
        "[authority]\nrevocation_readiness_grace_ms = 500\n",
        "[local_exec]\ntoken_ttl_secs = 300\n",
        "[local_exec]\nretry_after_ms = 500\n",
    ] {
        assert!(
            toml::from_str::<sidecar::SidecarConfig>(config).is_err(),
            "superseded Sidecar scalar must be rejected: {config}"
        );
    }

    for config in [
        "[defaults.capability]\ngrace_seconds = 30\n",
        "[defaults.sidecar_local_exec]\ntimeout_ms = 500\n",
        "[defaults.sidecar_local_exec]\nhitl_max_wait_ms = 300000\n",
        "[profiles.unselected.capability]\ngrace_seconds = 45\n",
        "[profiles.unselected.sidecar_local_exec]\ntimeout_ms = 750\n",
        "[profiles.unselected.sidecar_local_exec]\nhitl_max_wait_ms = 600000\n",
    ] {
        assert!(
            toml::from_str::<run::FileConfig>(config).is_err(),
            "superseded Run scalar must be rejected: {config}"
        );
    }
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
