use std::path::Path;

use anyhow::{Context as _, anyhow};
use firma_authority::{AuthorityConfig, AuthorityConfigBuilder};
use firma_config_loader::{CONFIG_FILE_NAME, ConfigResolver, ResolvedConfig};
use firma_config_schema::authority as schema;
use fs_err as fs;

#[test]
fn loads_authority_config_from_resolved_section() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &config_path,
        r#"[authority]
           policy_dir = "custom-policies"
           key_file = "authority.key"
        "#,
    )?;

    let resolved = resolved_config(&config_path)?;
    let config = AuthorityConfig::from_resolved_section(&resolved)?
        .ok_or_else(|| anyhow!("authority section should be present"))?;

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
        max_ttl_seconds: 1200,
        key_file: "/srv/authority.key".into(),
        bundle_ttl_seconds: 45,
        tls: schema::AuthorityTlsConfig {
            tls_cert_path: Some("/srv/tls.crt".into()),
            tls_key_path: Some("/srv/tls.key".into()),
            mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
            mtls_client_ca_key_path: Some("/srv/ca.key".into()),
            authorized_clients_path: Some("/srv/clients.toml".into()),
        },
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
        tls: schema::AuthorityTlsConfig {
            tls_cert_path: Some("/srv/tls.crt".into()),
            ..schema::AuthorityTlsConfig::default()
        },
        ..schema::AuthorityConfig::default()
    };
    assert!(AuthorityConfigBuilder::new(schema).build().is_err());
}

#[test]
fn build_rejects_unpaired_mtls() {
    let schema = schema::AuthorityConfig {
        tls: schema::AuthorityTlsConfig {
            tls_cert_path: Some("/srv/tls.crt".into()),
            tls_key_path: Some("/srv/tls.key".into()),
            mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
            ..schema::AuthorityTlsConfig::default()
        },
        ..schema::AuthorityConfig::default()
    };
    assert!(AuthorityConfigBuilder::new(schema).build().is_err());
}

#[test]
fn build_rejects_mtls_without_server_tls() {
    let schema = schema::AuthorityConfig {
        tls: schema::AuthorityTlsConfig {
            mtls_client_ca_cert_path: Some("/srv/ca.crt".into()),
            authorized_clients_path: Some("/srv/clients.toml".into()),
            ..schema::AuthorityTlsConfig::default()
        },
        ..schema::AuthorityConfig::default()
    };
    assert!(AuthorityConfigBuilder::new(schema).build().is_err());
}
