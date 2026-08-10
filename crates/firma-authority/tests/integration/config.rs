use anyhow::{Context as _, anyhow};
use firma_authority::AuthorityConfig;
use firma_config_loader::{CONFIG_FILE_NAME, resolve_config};
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

    let resolved = resolve_config(Some(&config_path))?
        .with_context(|| format!("resolve config at {}", config_path.display()))?;
    let config = AuthorityConfig::from_resolved_section(&resolved)?
        .ok_or_else(|| anyhow!("authority section should be present"))?;

    assert_eq!(config.policy_dir, tmp.path().join("custom-policies"));
    assert_eq!(config.key_file, tmp.path().join("authority.key"));
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

    let resolved = resolve_config(Some(&config_path))?
        .with_context(|| format!("resolve config at {}", config_path.display()))?;
    let config = AuthorityConfig::from_resolved_section(&resolved)?;

    assert!(config.is_none());

    Ok(())
}
