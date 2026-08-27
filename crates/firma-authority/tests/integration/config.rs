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
fn legacy_seconds_env_overrides_preserve_the_compatibility_matrix() -> anyhow::Result<()> {
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

    for (value, expected) in [
        ("60", 60),
        ("invalid", 11),
        ("-1", 11),
        ("0", 0),
        ("2147483648", 11),
    ] {
        set_legacy_seconds_env(Some(value), None);
        let config = AuthorityConfig::from_resolved_section(&resolved)?
            .ok_or_else(|| anyhow!("authority section should be present"))?;
        assert_eq!(
            config.max_ttl_seconds(),
            expected,
            "unexpected max TTL override result for {value:?}"
        );
        assert_eq!(config.bundle_ttl_seconds(), 12);
    }

    for (value, expected) in [
        ("60", 60),
        ("invalid", 12),
        ("-1", 12),
        ("0", 0),
        ("4294967296", 12),
    ] {
        set_legacy_seconds_env(None, Some(value));
        let config = AuthorityConfig::from_resolved_section(&resolved)?
            .ok_or_else(|| anyhow!("authority section should be present"))?;
        assert_eq!(config.max_ttl_seconds(), 11);
        assert_eq!(
            config.bundle_ttl_seconds(),
            expected,
            "unexpected bundle TTL override result for {value:?}"
        );
    }

    Ok(())
}

#[expect(
    unsafe_code,
    reason = "nextest gives this environment-mutating integration test its own process"
)]
fn set_legacy_seconds_env(max_ttl: Option<&str>, bundle_ttl: Option<&str>) {
    const MAX_TTL: &str = "FIRMA_AUTHORITY_MAX_TTL_SECONDS";
    const BUNDLE_TTL: &str = "FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS";

    // SAFETY: the test verifies `NEXTEST=1` before calling this helper;
    // nextest executes each test in an isolated process.
    unsafe {
        std::env::remove_var(MAX_TTL);
        std::env::remove_var(BUNDLE_TTL);
        if let Some(value) = max_ttl {
            std::env::set_var(MAX_TTL, value);
        }
        if let Some(value) = bundle_ttl {
            std::env::set_var(BUNDLE_TTL, value);
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
fn schema_with_tls() -> schema::AuthorityConfig {
    schema::AuthorityConfig {
        listen_addr: "127.0.0.1:9443".to_string(),
        policy_dir: "/srv/policies".into(),
        issuance_policy_dir: "/srv/issuance".into(),
        schema_path: Some("/srv/schema.cedarschema".into()),
        revocation_file: "/srv/revocations.txt".into(),
        max_ttl: std::time::Duration::from_mins(20),
        key_file: "/srv/authority.key".into(),
        bundle_ttl: std::time::Duration::from_secs(45),
        tls_cert_path: Some("/srv/tls.crt".into()),
        tls_key_path: Some("/srv/tls.key".into()),
        mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
        mtls_client_ca_key_path: Some("/srv/ca.key".into()),
        authorized_clients_path: Some("/srv/clients.toml".into()),
    }
}

#[test]
fn accessors_expose_built_values() -> anyhow::Result<()> {
    let config = AuthorityConfigBuilder::new(schema_with_tls()).build()?;

    assert_eq!(config.listen_addr(), "127.0.0.1:9443");
    assert_eq!(config.policy_dir(), Path::new("/srv/policies"));
    assert_eq!(
        config.schema_path(),
        Some(Path::new("/srv/schema.cedarschema"))
    );
    assert_eq!(config.revocation_file(), Path::new("/srv/revocations.txt"));
    assert_eq!(config.max_ttl_seconds(), 1200);
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
    let original = AuthorityConfigBuilder::new(schema_with_tls()).build()?;

    // `to_schema` maps the validated config back to the wire shape; rebuilding
    // from it must reproduce the same validated config.
    let rebuilt = AuthorityConfigBuilder::new(original.to_schema()).build()?;

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
    let config = AuthorityConfigBuilder::new(schema_with_tls())
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
