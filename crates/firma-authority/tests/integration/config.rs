use std::path::Path;

use anyhow::{Context as _, anyhow};
use firma_authority::config::ConfigError;
use firma_authority::{AuthorityConfig, AuthorityConfigBuilder};
use firma_config_loader::{CONFIG_FILE_NAME, ConfigResolver, ResolvedConfig};
use firma_config_schema::authority as schema;
use fs_err as fs;

#[test]
fn relative_flag_config_rebases_authority_resources_from_an_absolute_dir() -> anyhow::Result<()> {
    let current_dir = std::env::current_dir()?;
    let tmp = tempfile::tempdir_in(&current_dir)?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        r#"[authority]
           policy_dir = "custom-policies"
           key_file = "authority.key"
        "#,
    )?;

    let relative_config_path = config_path.strip_prefix(&current_dir)?;
    let resolved = resolved_config(relative_config_path)?;
    let config = AuthorityConfig::from_resolved_section(&resolved)?
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
    let config = AuthorityConfig::from_resolved_section(&resolved)?;

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
bundle_ttl = "12s"
"#,
    )?;
    let resolved = resolved_config(&config_path)?;

    set_ttl_env(None, None, None, None);
    let config = AuthorityConfig::from_resolved_section(&resolved)?
        .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 11);
    assert_eq!(config.bundle_ttl_seconds(), 12);

    for (value, expected) in [
        ("1m", 60),
        ("2h 30m", 9_000),
        ("2147483647s", i32::MAX.unsigned_abs()),
    ] {
        set_ttl_env(Some(value), None, None, None);
        let config = AuthorityConfig::from_resolved_section(&resolved)?
            .ok_or_else(|| anyhow!("authority section should be present"))?;
        assert_eq!(
            config.max_ttl_seconds().get(),
            expected,
            "unexpected max TTL override result for {value:?}"
        );
        assert_eq!(config.bundle_ttl_seconds(), 12);
    }

    for (value, expected) in [("1m", 60), ("2h 30m", 9_000), ("4294967295s", u32::MAX)] {
        set_ttl_env(None, Some(value), None, None);
        let config = AuthorityConfig::from_resolved_section(&resolved)?
            .ok_or_else(|| anyhow!("authority section should be present"))?;
        assert_eq!(config.max_ttl_seconds().get(), 11);
        assert_eq!(
            config.bundle_ttl_seconds(),
            expected,
            "unexpected bundle TTL override result for {value:?}"
        );
    }

    set_ttl_env(Some("13s"), Some("14s"), None, None);
    let config = AuthorityConfig::from_resolved_section(&resolved)?
        .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 13);
    assert_eq!(config.bundle_ttl_seconds(), 14);

    set_ttl_env(None, None, Some("21"), Some("22"));
    let config = AuthorityConfig::from_resolved_section(&resolved)?
        .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 11);
    assert_eq!(config.bundle_ttl_seconds(), 12);

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
        "[authority]\nmax_ttl = \"11s\"\nbundle_ttl = \"12s\"\n",
    )?;
    let resolved = resolved_config(&config_path)?;

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
        let error = AuthorityConfig::from_resolved_section(&resolved).expect_err(name);
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
        "[authority]\nmax_ttl = \"11s\"\nbundle_ttl = \"12s\"\n",
    )?;
    let resolved = resolved_config(&config_path)?;

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
    let config = AuthorityConfig::from_resolved_section(&resolved)?
        .ok_or_else(|| anyhow!("authority section should be present"))?;
    assert_eq!(config.max_ttl_seconds().get(), 11);
    assert_eq!(config.bundle_ttl_seconds(), 12);

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
        revocation_file: "/srv/revocations.txt".into(),
        max_ttl: firma_config_schema::utils::NonZeroDuration::new(std::time::Duration::from_mins(
            20,
        ))?,
        key_file: "/srv/authority.key".into(),
        bundle_ttl: firma_config_schema::utils::NonZeroDuration::new(
            std::time::Duration::from_secs(45),
        )?,
        tls_cert_path: Some("/srv/tls.crt".into()),
        tls_key_path: Some("/srv/tls.key".into()),
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        mtls_client_ca_key_path: Some("/srv/ca.key".into()),
        authorized_clients_path: Some("/srv/clients.toml".into()),
    })
}

#[test]
fn accessors_expose_built_values() -> anyhow::Result<()> {
    let config = AuthorityConfigBuilder::new(schema_with_tls()?).build()?;

    assert_eq!(config.listen_addr(), "127.0.0.1:9443");
    assert_eq!(config.policy_dir(), Path::new("/srv/policies"));
    assert_eq!(
        config.schema_path(),
        Some(Path::new("/srv/schema.cedarschema"))
    );
    assert_eq!(config.revocation_file(), Path::new("/srv/revocations.txt"));
    assert_eq!(config.max_ttl_seconds().get(), 1200);
    assert_eq!(config.key_file(), Path::new("/srv/authority.key"));
    assert_eq!(config.bundle_ttl_seconds(), 45);
    assert_eq!(
        config.tls().mtls_client_ca_cert_path(),
        Some(Path::new("/srv/ca.crt"))
    );
    assert_eq!(
        config.tls().mtls_client_ca_key_path(),
        Some(Path::new("/srv/ca.key"))
    );
    Ok(())
}

#[test]
fn to_schema_round_trips_through_builder() -> anyhow::Result<()> {
    let original = AuthorityConfigBuilder::new(schema_with_tls()?).build()?;

    // `to_schema` maps the validated config back to the wire shape; rebuilding
    // from it must reproduce the same validated config.
    let rebuilt = AuthorityConfigBuilder::new(original.to_schema()?).build()?;

    assert_eq!(rebuilt.listen_addr(), original.listen_addr());
    assert_eq!(rebuilt.policy_dir(), original.policy_dir());
    assert_eq!(rebuilt.max_ttl_seconds(), original.max_ttl_seconds());
    assert_eq!(
        rebuilt.tls().mtls_client_ca_cert_path(),
        original.tls().mtls_client_ca_cert_path()
    );
    assert_eq!(
        rebuilt.tls().mtls_client_ca_key_path(),
        original.tls().mtls_client_ca_key_path()
    );
    Ok(())
}

#[test]
fn without_tls_and_listen_addr_setters_apply() -> anyhow::Result<()> {
    let config = AuthorityConfigBuilder::new(schema_with_tls()?)
        .without_tls()
        .listen_addr("[::1]:7000")
        .build()?;

    assert_eq!(config.listen_addr(), "[::1]:7000");
    assert_eq!(config.tls().mtls_client_ca_cert_path(), None);
    assert_eq!(config.tls().mtls_client_ca_key_path(), None);
    Ok(())
}

#[test]
fn build_rejects_half_configured_server_tls() {
    let schema = schema::AuthorityConfig {
        tls_cert_path: Some("/srv/tls.crt".into()),
        ..schema::AuthorityConfig::default()
    };
    assert!(AuthorityConfigBuilder::new(schema).build().is_err());
}

#[test]
fn build_rejects_unpaired_mtls() {
    let schema = schema::AuthorityConfig {
        tls_cert_path: Some("/srv/tls.crt".into()),
        tls_key_path: Some("/srv/tls.key".into()),
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        ..schema::AuthorityConfig::default()
    };
    assert!(AuthorityConfigBuilder::new(schema).build().is_err());
}

#[test]
fn build_rejects_mtls_without_server_tls() {
    let schema = schema::AuthorityConfig {
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        authorized_clients_path: Some("/srv/clients.toml".into()),
        ..schema::AuthorityConfig::default()
    };
    assert!(AuthorityConfigBuilder::new(schema).build().is_err());
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
    fs::write(&config_path, "[authority]\n")?;
    let resolved = resolved_config(&config_path)?;
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

        let Err(error) = AuthorityConfig::from_resolved_section(&resolved) else {
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
