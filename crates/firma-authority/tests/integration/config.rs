use std::path::Path;

use anyhow::{Context as _, anyhow};
use firma_authority::config::{AuthorityConfigError, ConfigError};
use firma_authority::{AuthorityConfig, AuthorityConfigBuilder, AuthorityTlsMaterial, TlsRequest};
use firma_config_loader::{CONFIG_FILE_NAME, ConfigResolver, ResolvedConfig};
use firma_config_schema::authority as schema;
use firma_config_utils::NonZeroDuration;
use firma_runtime_state::RuntimeLayout;
use fs_err as fs;

#[test]
fn relative_flag_config_rebases_authority_resources_from_an_absolute_dir() -> anyhow::Result<()> {
    let current_dir = std::env::current_dir()?;
    let tmp = tempfile::tempdir_in(&current_dir)?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        r#"[authority]
           mapping_rules_paths = ["mapping-rules.toml"]
           policy_dir = "custom-policies"
           key_file = "authority.key"
        "#,
    )?;

    let relative_config_path = config_path.strip_prefix(&current_dir)?;
    let resolved = resolved_config(relative_config_path)?;
    let state = tempfile::tempdir()?;
    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?
    .ok_or_else(|| anyhow!("authority section should be present"))?;

    assert_eq!(resolved.config_file(), config_path);
    assert!(resolved.config_dir().is_absolute());
    assert_eq!(
        config.policy_dir(),
        tmp.path().join("custom-policies").as_path()
    );
    assert_eq!(
        config.key_file(),
        tmp.path().join("authority.key").as_path()
    );
    Ok(())
}

#[test]
fn missing_authority_section_returns_none() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        r#"[sidecar]
           listen_addr = "127.0.0.1:0"
        "#,
    )?;

    let resolved = resolved_config(&config_path)?;
    let state = tempfile::tempdir()?;
    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?;

    assert!(config.is_none());

    Ok(())
}

#[test]
fn duration_env_overrides_use_the_schema_contract() -> anyhow::Result<()> {
    assert_eq!(
        std::env::var("NEXTEST").as_deref(),
        Ok("1"),
        "this test mutates process environment and must run under cargo nextest"
    );
    let tmp = tempfile::tempdir()?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        r#"[authority]
max_ttl = "11s"
mapping_rules_paths = ["mapping-rules.toml"]
bundle_ttl = "12s"
"#,
    )?;
    let resolved = resolved_config(&config_path)?;
    let state = tempfile::tempdir()?;

    set_ttl_env(None, None, None, None);
    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?
    .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 11);
    assert_eq!(config.bundle_ttl_seconds().get(), 12);

    for (value, expected) in [
        ("1m", 60),
        ("2h 30m", 9_000),
        ("2147483647s", i32::MAX.unsigned_abs()),
    ] {
        set_ttl_env(Some(value), None, None, None);
        let config = AuthorityConfig::from_resolved_section(
            &resolved,
            &state_layout(&state),
            TlsRequest::Disabled,
        )?
        .ok_or_else(|| anyhow!("authority section should be present"))?;
        assert_eq!(
            config.max_ttl_seconds().get(),
            expected,
            "unexpected max TTL override result for {value:?}"
        );
        assert_eq!(config.bundle_ttl_seconds().get(), 12);
    }

    for (value, expected) in [("1m", 60), ("2h 30m", 9_000), ("4294967295s", u32::MAX)] {
        set_ttl_env(None, Some(value), None, None);
        let config = AuthorityConfig::from_resolved_section(
            &resolved,
            &state_layout(&state),
            TlsRequest::Disabled,
        )?
        .ok_or_else(|| anyhow!("authority section should be present"))?;
        assert_eq!(config.max_ttl_seconds().get(), 11);
        assert_eq!(
            config.bundle_ttl_seconds().get(),
            expected,
            "unexpected bundle TTL override result for {value:?}"
        );
    }

    set_ttl_env(Some("13s"), Some("14s"), None, None);
    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?
    .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 13);
    assert_eq!(config.bundle_ttl_seconds().get(), 14);

    set_ttl_env(None, None, Some("21"), Some("22"));
    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?
    .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 11);
    assert_eq!(config.bundle_ttl_seconds().get(), 12);

    Ok(())
}

#[test]
fn invalid_duration_env_overrides_fail_closed() -> anyhow::Result<()> {
    assert_eq!(
        std::env::var("NEXTEST").as_deref(),
        Ok("1"),
        "this test mutates process environment and must run under cargo nextest"
    );
    let tmp = tempfile::tempdir()?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nmax_ttl = \"11s\"\nbundle_ttl = \"12s\"\n",
    )?;
    let resolved = resolved_config(&config_path)?;
    let state = tempfile::tempdir()?;

    for (name, max_ttl, bundle_ttl, expected) in [
        (
            "malformed maximum TTL",
            Some("invalid"),
            None,
            "invalid FIRMA_AUTHORITY_MAX_TTL for authority.max_ttl",
        ),
        (
            "negative maximum TTL",
            Some("-1s"),
            None,
            "invalid FIRMA_AUTHORITY_MAX_TTL for authority.max_ttl",
        ),
        (
            "zero maximum TTL",
            Some("0s"),
            None,
            "duration must be greater than zero",
        ),
        (
            "fractional maximum TTL",
            Some("1500ms"),
            None,
            "authority.max_ttl must be a whole number of seconds",
        ),
        (
            "overflowing maximum TTL",
            Some("2147483648s"),
            None,
            "authority.max_ttl exceeds the supported whole-second range",
        ),
        (
            "malformed bundle TTL",
            None,
            Some("invalid"),
            "invalid FIRMA_AUTHORITY_BUNDLE_TTL for authority.bundle_ttl",
        ),
        (
            "negative bundle TTL",
            None,
            Some("-1s"),
            "invalid FIRMA_AUTHORITY_BUNDLE_TTL for authority.bundle_ttl",
        ),
        (
            "zero bundle TTL",
            None,
            Some("0s"),
            "duration must be greater than zero",
        ),
        (
            "fractional bundle TTL",
            None,
            Some("1500ms"),
            "authority.bundle_ttl must be a whole number of seconds",
        ),
        (
            "overflowing bundle TTL",
            None,
            Some("4294967296s"),
            "authority.bundle_ttl exceeds the supported whole-second range",
        ),
    ] {
        set_ttl_env(max_ttl, bundle_ttl, None, None);
        let error = AuthorityConfig::from_resolved_section(
            &resolved,
            &state_layout(&state),
            TlsRequest::Disabled,
        )
        .expect_err(name);
        assert!(
            error.to_string().contains(expected),
            "unexpected error for {name}: {error}"
        );
    }

    Ok(())
}

#[cfg(unix)]
#[test]
#[expect(
    unsafe_code,
    reason = "nextest gives this environment-mutating integration test its own process"
)]
fn non_unicode_duration_env_overrides_follow_the_general_env_contract() -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStringExt as _;

    assert_eq!(
        std::env::var("NEXTEST").as_deref(),
        Ok("1"),
        "this test mutates process environment and must run under cargo nextest"
    );
    let tmp = tempfile::tempdir()?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nmax_ttl = \"11s\"\nbundle_ttl = \"12s\"\n",
    )?;
    let resolved = resolved_config(&config_path)?;
    let state = tempfile::tempdir()?;

    // SAFETY: nextest executes this test in an isolated process.
    unsafe {
        std::env::set_var(
            "FIRMA_AUTHORITY_MAX_TTL",
            std::ffi::OsString::from_vec(vec![0xfe]),
        );
        std::env::set_var(
            "FIRMA_AUTHORITY_BUNDLE_TTL",
            std::ffi::OsString::from_vec(vec![0xff]),
        );
    }
    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?
    .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 11);
    assert_eq!(config.bundle_ttl_seconds().get(), 12);

    Ok(())
}

#[expect(
    unsafe_code,
    reason = "nextest gives this environment-mutating integration test its own process"
)]
fn set_ttl_env(
    max_ttl: Option<&str>,
    bundle_ttl: Option<&str>,
    removed_max_ttl: Option<&str>,
    removed_bundle_ttl: Option<&str>,
) {
    const MAX_TTL: &str = "FIRMA_AUTHORITY_MAX_TTL";
    const BUNDLE_TTL: &str = "FIRMA_AUTHORITY_BUNDLE_TTL";
    const REMOVED_MAX_TTL: &str = "FIRMA_AUTHORITY_MAX_TTL_SECONDS";
    const REMOVED_BUNDLE_TTL: &str = "FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS";

    // SAFETY: the test verifies `NEXTEST=1` before calling this helper;
    // nextest executes each test in an isolated process.
    unsafe {
        std::env::remove_var(MAX_TTL);
        std::env::remove_var(BUNDLE_TTL);
        std::env::remove_var(REMOVED_MAX_TTL);
        std::env::remove_var(REMOVED_BUNDLE_TTL);
        if let Some(value) = max_ttl {
            std::env::set_var(MAX_TTL, value);
        }
        if let Some(value) = bundle_ttl {
            std::env::set_var(BUNDLE_TTL, value);
        }
        if let Some(value) = removed_max_ttl {
            std::env::set_var(REMOVED_MAX_TTL, value);
        }
        if let Some(value) = removed_bundle_ttl {
            std::env::set_var(REMOVED_BUNDLE_TTL, value);
        }
    }
}

/// The runtime layout a builder resolves unset artifact paths against.
///
/// Tests that assert nothing about those paths still need one, because a
/// builder cannot be constructed without it.
fn state_layout(dir: &tempfile::TempDir) -> RuntimeLayout {
    RuntimeLayout::from_root(dir.path())
}

fn configured_schema() -> schema::AuthorityConfig {
    schema::AuthorityConfig {
        mapping_rules_paths: vec!["mapping-rules.toml".into()],
        ..schema::AuthorityConfig::default()
    }
}

#[test]
fn mapping_sources_are_required_before_resource_resolution() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    for text in ["", "mapping_rules_paths = []"] {
        let error = AuthorityConfigBuilder::from_toml_str(text, &state_layout(&root))?
            .build()
            .expect_err("missing mapping inputs");
        assert_eq!(error, AuthorityConfigError::MissingMappingPaths);
        insta::allow_duplicates! { insta::assert_snapshot!(error.to_string(), @"authority.mapping_rules_paths must contain at least one mapping file"); }
    }
    let error = AuthorityConfigBuilder::from_toml_str(
        "mapping_rules_paths = ['valid.toml', '']",
        &state_layout(&root),
    )?
    .rebase_defaults(root.path())
    .build()
    .expect_err("empty source must survive rebasing for validation");
    assert_eq!(error, AuthorityConfigError::EmptyMappingPath { index: 1 });
    insta::assert_snapshot!(error.to_string(), @"authority.mapping_rules_paths[1] must not be empty");
    Ok(())
}

fn resolved_config(path: &Path) -> anyhow::Result<ResolvedConfig> {
    ConfigResolver::default()
        .resolve_config(Some(path))?
        .with_context(|| format!("resolve config at {}", path.display()))
}

/// A fully-populated schema fragment, including TLS, so conversions and
/// accessors are exercised on non-default values.
fn schema_with_tls() -> anyhow::Result<schema::AuthorityConfig> {
    Ok(schema::AuthorityConfig {
        listen_addr: "127.0.0.1:9443".to_string(),
        policy_dir: "/srv/policies".into(),
        issuance_policy_dir: "/srv/issuance".into(),
        schema_path: Some("/srv/schema.cedarschema".into()),
        mapping_rules_paths: vec!["/srv/mappings.toml".into()],
        revocation_file: Some("/srv/revocations.txt".into()),
        max_ttl: NonZeroDuration::new(std::time::Duration::from_mins(20))?,
        key_file: Some("/srv/authority.key".into()),
        bundle_ttl: NonZeroDuration::new(std::time::Duration::from_secs(45))?,
        tls_cert_path: Some("/srv/tls.crt".into()),
        tls_key_path: Some("/srv/tls.key".into()),
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        mtls_client_ca_key_path: Some("/srv/ca.key".into()),
        authorized_clients_path: Some("/srv/clients.toml".into()),
    })
}

#[test]
fn accessors_expose_built_values() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let config = AuthorityConfigBuilder::new(schema_with_tls()?, &state_layout(&state)).build()?;

    assert_eq!(config.listen_addr(), "127.0.0.1:9443");
    assert_eq!(config.policy_dir(), Path::new("/srv/policies"));
    assert_eq!(
        config.schema_path(),
        Some(Path::new("/srv/schema.cedarschema"))
    );
    assert_eq!(config.revocation_file(), Path::new("/srv/revocations.txt"));
    assert_eq!(config.max_ttl_seconds().get(), 1200);
    assert_eq!(config.key_file(), Path::new("/srv/authority.key"));
    assert_eq!(config.bundle_ttl_seconds().get(), 45);
    let mtls = config
        .tls()
        .material()
        .and_then(AuthorityTlsMaterial::mtls)
        .expect("schema_with_tls configures mTLS");
    assert_eq!(mtls.client_ca_cert(), Path::new("/srv/ca.crt"));
    assert_eq!(mtls.client_ca_key(), Some(Path::new("/srv/ca.key")));
    Ok(())
}

#[test]
fn to_schema_round_trips_through_builder() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let original =
        AuthorityConfigBuilder::new(schema_with_tls()?, &state_layout(&state)).build()?;

    // `to_schema` maps the validated config back to the wire shape; rebuilding
    // from it must reproduce the same validated config.
    let rebuilt =
        AuthorityConfigBuilder::new(original.to_schema()?, &state_layout(&state)).build()?;

    assert_eq!(rebuilt.listen_addr(), original.listen_addr());
    assert_eq!(rebuilt.policy_dir(), original.policy_dir());
    assert_eq!(rebuilt.max_ttl_seconds(), original.max_ttl_seconds());
    let rebuilt_mtls = rebuilt
        .tls()
        .material()
        .and_then(AuthorityTlsMaterial::mtls)
        .expect("round trip keeps mTLS");
    let original_mtls = original
        .tls()
        .material()
        .and_then(AuthorityTlsMaterial::mtls)
        .expect("schema_with_tls configures mTLS");
    assert_eq!(
        rebuilt_mtls.client_ca_cert(),
        original_mtls.client_ca_cert()
    );
    assert_eq!(rebuilt_mtls.client_ca_key(), original_mtls.client_ca_key());
    Ok(())
}

#[test]
fn without_tls_and_listen_addr_setters_apply() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let config = AuthorityConfigBuilder::new(schema_with_tls()?, &state_layout(&state))
        .without_tls()
        .listen_addr("[::1]:7000")
        .build()?;

    assert_eq!(config.listen_addr(), "[::1]:7000");
    assert!(config.tls().material().is_none());
    // The posture alone cannot show that every wire key was cleared, and
    // those keys are what a re-read of the serialized section resolves from.
    let cleared = config.to_schema()?;
    assert_eq!(cleared.tls_cert_path, None);
    assert_eq!(cleared.tls_key_path, None);
    assert_eq!(cleared.mtls_client_ca_cert_path, None);
    assert_eq!(cleared.mtls_client_ca_key_path, None);
    assert_eq!(cleared.authorized_clients_path, None);
    Ok(())
}

#[test]
fn build_rejects_half_configured_server_tls() -> anyhow::Result<()> {
    let schema = schema::AuthorityConfig {
        tls_cert_path: Some("/srv/tls.crt".into()),
        ..configured_schema()
    };
    let state = tempfile::tempdir()?;

    let Err(error) = AuthorityConfigBuilder::new(schema, &state_layout(&state)).build() else {
        anyhow::bail!("a lone tls_cert_path must fail validation");
    };

    assert_eq!(error, AuthorityConfigError::TlsPairMismatch);
    Ok(())
}

#[test]
fn build_rejects_unpaired_mtls() -> anyhow::Result<()> {
    let schema = schema::AuthorityConfig {
        tls_cert_path: Some("/srv/tls.crt".into()),
        tls_key_path: Some("/srv/tls.key".into()),
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        ..configured_schema()
    };
    let state = tempfile::tempdir()?;

    let Err(error) = AuthorityConfigBuilder::new(schema, &state_layout(&state)).build() else {
        anyhow::bail!("an mTLS CA without an allow-list must fail validation");
    };

    assert_eq!(error, AuthorityConfigError::MtlsPairMismatch);
    Ok(())
}

/// The client CA signing key is part of the mTLS group: accepting it alone
/// would drop it on the way to the runtime type and leave `issue-client-cert`
/// reporting a key the operator did configure as missing.
#[test]
fn build_rejects_an_issuer_key_without_its_client_ca() -> anyhow::Result<()> {
    let schema = schema::AuthorityConfig {
        tls_cert_path: Some("/srv/tls.crt".into()),
        tls_key_path: Some("/srv/tls.key".into()),
        mtls_client_ca_key_path: Some("/srv/ca.key".into()),
        ..configured_schema()
    };
    let state = tempfile::tempdir()?;

    let Err(error) = AuthorityConfigBuilder::new(schema, &state_layout(&state)).build() else {
        anyhow::bail!("an issuer key without its client CA must fail validation");
    };

    assert_eq!(error, AuthorityConfigError::MtlsIssuerKeyWithoutClientCa);
    Ok(())
}

#[test]
fn build_rejects_mtls_without_server_tls() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let tls_dir = state.path().join("tls");
    fs::create_dir_all(&tls_dir)?;

    let schema = schema::AuthorityConfig {
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        authorized_clients_path: Some("/srv/clients.toml".into()),
        ..configured_schema()
    };
    // `without_tls` would clear the mTLS trio too, so the plaintext request has
    // to come from a state directory that holds no pair to adopt.
    assert_eq!(
        AuthorityConfigBuilder::new(schema, &state_layout(&state))
            .build()
            .expect_err("the config is invalid"),
        AuthorityConfigError::TlsMaterialMissing {
            dir: tls_dir.display().to_string(),
        }
    );
    Ok(())
}

#[test]
#[expect(
    unsafe_code,
    reason = "nextest gives this environment-mutating integration test its own process"
)]
fn environment_tls_overrides_are_validated_after_merge() -> anyhow::Result<()> {
    assert_eq!(
        std::env::var("NEXTEST").as_deref(),
        Ok("1"),
        "this test mutates process environment and must run under cargo nextest"
    );

    let tmp = tempfile::tempdir()?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\n",
    )?;
    let resolved = resolved_config(&config_path)?;
    let state = tempfile::tempdir()?;
    let tls_env_keys = [
        "FIRMA_AUTHORITY_TLS_CERT_PATH",
        "FIRMA_AUTHORITY_TLS_KEY_PATH",
        "FIRMA_AUTHORITY_MTLS_CLIENT_CA_CERT_PATH",
        "FIRMA_AUTHORITY_MTLS_CLIENT_CA_KEY_PATH",
        "FIRMA_AUTHORITY_AUTHORIZED_CLIENTS_PATH",
    ];

    for (key, expected_reason) in [
        (
            "FIRMA_AUTHORITY_TLS_CERT_PATH",
            "tls_cert_path and tls_key_path must both be set or both be unset",
        ),
        (
            "FIRMA_AUTHORITY_MTLS_CLIENT_CA_CERT_PATH",
            "mtls_client_ca_cert_path and authorized_clients_path must both be set or both be unset",
        ),
    ] {
        // SAFETY: nextest executes each test in an isolated process.
        unsafe {
            for env_key in tls_env_keys {
                std::env::remove_var(env_key);
            }
            std::env::set_var(key, "override.pem");
        }

        // Not `TlsRequest::Disabled`: that clears the very overrides under
        // test, so the pairing rules would never be reached.
        let Err(error) = AuthorityConfig::from_resolved_section(
            &resolved,
            &state_layout(&state),
            TlsRequest::Required,
        ) else {
            anyhow::bail!("an unpaired TLS environment override must fail validation");
        };
        let ConfigError::ParseError { path, reason } = error else {
            anyhow::bail!("unexpected error: {error}");
        };
        assert_eq!(path, config_path);
        assert_eq!(reason, expected_reason);
    }

    Ok(())
}

/// The scaffolded flow generates `tls/authority.crt` and `tls/authority.key`
/// under the state directory. Finding both there turns TLS on for a config that
/// names neither, which is what `firma config` achieved by writing the paths.
#[test]
fn a_complete_tls_pair_in_the_state_dir_enables_tls() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let tls_dir = state.path().join("tls");
    fs::create_dir_all(&tls_dir)?;
    fs::write(tls_dir.join("authority.crt"), "cert")?;
    fs::write(tls_dir.join("authority.key"), "key")?;

    let config = AuthorityConfigBuilder::new(configured_schema(), &state_layout(&state))
        .build()
        .map_err(|error| anyhow!("{error}"))?;

    let material = config.tls().material().expect("state-dir pair enables TLS");
    assert_eq!(material.cert(), tls_dir.join("authority.crt"));
    assert_eq!(material.key(), tls_dir.join("authority.key"));
    Ok(())
}

/// Half a pair is a broken install, not a request for plaintext: starting
/// without TLS there would silently downgrade a deployment that had it.
#[test]
fn a_partial_tls_pair_in_the_state_dir_is_rejected() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let tls_dir = state.path().join("tls");
    fs::create_dir_all(&tls_dir)?;
    fs::write(tls_dir.join("authority.crt"), "cert")?;

    let Err(error) =
        AuthorityConfigBuilder::new(configured_schema(), &state_layout(&state)).build()
    else {
        anyhow::bail!("a half-generated TLS pair must fail validation");
    };

    assert_eq!(
        error.to_string(),
        format!(
            "{} holds only one of authority.crt / authority.key; generate both with `firma config` or set tls_cert_path and tls_key_path explicitly",
            tls_dir.display()
        )
    );
    Ok(())
}

/// `FIRMA_AUTHORITY_TLS_*` is folded in after the opt-out is recorded, so the
/// clearing has to happen on `build`. Doing it in `without_tls` would let the
/// environment hand a caller that asked for plaintext a TLS listener. Every
/// field the server selects a TLS or mTLS listener from is overridden here, so
/// dropping any one of them from the clearing fails this test.
#[test]
#[expect(
    unsafe_code,
    reason = "nextest gives this environment-mutating integration test its own process"
)]
fn environment_tls_overrides_do_not_defeat_the_plaintext_opt_out() -> anyhow::Result<()> {
    assert_eq!(
        std::env::var("NEXTEST").as_deref(),
        Ok("1"),
        "this test mutates process environment and must run under cargo nextest"
    );
    let state = tempfile::tempdir()?;
    let config_path = state.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\n",
    )?;
    let resolved = resolved_config(&config_path)?;

    // SAFETY: nextest executes this test in an isolated process.
    unsafe {
        std::env::set_var("FIRMA_AUTHORITY_TLS_CERT_PATH", "override.crt");
        std::env::set_var("FIRMA_AUTHORITY_TLS_KEY_PATH", "override.key");
        std::env::set_var(
            "FIRMA_AUTHORITY_MTLS_CLIENT_CA_CERT_PATH",
            "override-ca.crt",
        );
        std::env::set_var("FIRMA_AUTHORITY_MTLS_CLIENT_CA_KEY_PATH", "override-ca.key");
        std::env::set_var(
            "FIRMA_AUTHORITY_AUTHORIZED_CLIENTS_PATH",
            "override-clients.toml",
        );
    }

    let config = AuthorityConfig::from_resolved_section(
        &resolved,
        &state_layout(&state),
        TlsRequest::Disabled,
    )?
    .ok_or_else(|| anyhow!("authority section should be present"))?;

    assert!(config.tls().material().is_none());
    // The allow-list has no accessor, but it is one of the fields the server
    // matches on to demand client certificates, so the wire form is checked
    // instead of leaving it uncovered.
    assert_eq!(config.to_schema()?.authorized_clients_path, None);
    Ok(())
}

/// `without_tls()` has to beat the state-directory default. Clearing the paths leaves
/// the same field state as "never set", which is exactly what the default fills
/// in — so autostart would serve TLS to a client dialling `http://`.
#[test]
fn without_tls_suppresses_a_complete_state_dir_pair() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let tls_dir = state.path().join("tls");
    fs::create_dir_all(&tls_dir)?;
    fs::write(tls_dir.join("authority.crt"), "cert")?;
    fs::write(tls_dir.join("authority.key"), "key")?;

    let config = AuthorityConfigBuilder::new(configured_schema(), &state_layout(&state))
        .without_tls()
        .build()
        .map_err(|error| anyhow!("{error}"))?;

    assert!(config.tls().material().is_none());
    Ok(())
}

/// The opt-out must survive serialization to the synthesized `[authority]`
/// section an autostarted Authority reads back, which is why the child is
/// launched with `--no-tls` rather than relying on absent keys.
#[test]
fn a_serialized_plaintext_config_still_adopts_state_dir_tls_without_the_opt_out()
-> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let tls_dir = state.path().join("tls");
    fs::create_dir_all(&tls_dir)?;
    fs::write(tls_dir.join("authority.crt"), "cert")?;
    fs::write(tls_dir.join("authority.key"), "key")?;
    let plaintext = AuthorityConfigBuilder::new(configured_schema(), &state_layout(&state))
        .without_tls()
        .build()
        .map_err(|error| anyhow!("{error}"))?;

    let round_tripped = AuthorityConfigBuilder::new(plaintext.to_schema()?, &state_layout(&state))
        .build()
        .map_err(|error| anyhow!("{error}"))?;

    assert!(
        round_tripped.tls().material().is_some(),
        "the wire form carries no record of the opt-out; the caller must pass it again"
    );
    Ok(())
}
