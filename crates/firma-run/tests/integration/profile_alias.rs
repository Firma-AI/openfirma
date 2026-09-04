use std::path::PathBuf;

use firma_run::config::{read_configured_profile, resolve_profile};
use firma_run::runtime::RunInput;

fn run_input(profile: &str, config: PathBuf) -> RunInput {
    RunInput {
        profile: profile.to_string(),
        config: Some(config),
        backend: None,
        sidecar_cli: firma_run::sidecar::SidecarCli::Unset,
        capability_file: None,
        identity_mode: None,
        preserve_host_user: false,
        print_effective_config: false,
        no_autostart: false,
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
fn code_alias_uses_canonical_vscode_profile_config() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let config_path = tmpdir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.profiles.vscode]
env_passthrough = ["FIRMA_ALIAS_CANARY"]
"#,
    )?;

    let resolved = resolve_profile(&run_input("code", config_path))?;

    assert_eq!(resolved.id, "vscode");
    assert!(resolved.env_passthrough.contains("FIRMA_ALIAS_CANARY"));
    assert_eq!(
        resolved
            .env_set
            .get("FIRMA_RUN_PROFILE")
            .map(String::as_str),
        Some("vscode")
    );
    Ok(())
}

#[test]
fn configured_code_alias_uses_canonical_vscode_profile_config()
-> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let config_path = tmpdir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run]
profile = "code"

[run.profiles.vscode]
env_passthrough = ["FIRMA_ALIAS_CANARY"]
"#,
    )?;

    let configured_profile =
        read_configured_profile(&config_path)?.ok_or("expected configured profile")?;
    let resolved = resolve_profile(&run_input(&configured_profile, config_path))?;

    assert_eq!(resolved.id, "vscode");
    assert!(resolved.env_passthrough.contains("FIRMA_ALIAS_CANARY"));
    assert_eq!(
        resolved
            .env_set
            .get("FIRMA_RUN_PROFILE")
            .map(String::as_str),
        Some("vscode")
    );
    Ok(())
}
