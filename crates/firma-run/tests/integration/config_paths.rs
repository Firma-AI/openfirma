use std::path::PathBuf;

use firma_run::config::{CapabilitySource, resolve_profile};
use firma_run::error::RunError;
use firma_run::runtime::RunInput;

fn run_input(config: PathBuf) -> RunInput {
    RunInput {
        profile: "generic".to_string(),
        config: Some(config),
        backend: None,
        sidecar_cli: firma_run::sidecar::SidecarCli::Unset,
        capability_file: None,
        identity_mode: None,
        preserve_host_user: false,
        print_effective_config: false,
        no_autostart: false,
        sidecar_template_path: None,
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
fn relative_config_path_rebases_resources_from_an_absolute_config_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let current_dir = std::env::current_dir()?;
    let tmpdir = tempfile::tempdir_in(&current_dir)?;
    let config_dir = tmpdir.path().join("config");
    fs_err::create_dir_all(&config_dir)?;
    let capability_path = config_dir.join("capability.toml");
    fs_err::write(&capability_path, "token = 'test'\n")?;
    let config_path = config_dir.join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.profiles.generic.capability]
kind = "file"
path = "capability.toml"
"#,
    )?;
    let relative_config = config_path.strip_prefix(&current_dir)?.to_path_buf();

    let resolved = resolve_profile(&run_input(relative_config))?;

    let CapabilitySource::File { path } = resolved.capability.source else {
        return Err("expected file capability source".into());
    };
    assert!(path.is_absolute(), "resolved path was relative: {path:?}");
    assert_eq!(
        fs_err::canonicalize(path)?,
        fs_err::canonicalize(capability_path)?
    );
    Ok(())
}

#[test]
fn executable_allowlist_rejects_directories() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let directory = tmpdir.path().join("not-an-executable-file");
    fs_err::create_dir(&directory)?;
    let config_path = tmpdir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    let sidecar_endpoint = if cfg!(unix) {
        "unix:///tmp/firma-sidecar.sock"
    } else {
        "tcp://127.0.0.1:18080"
    };
    let mediator_endpoint = if cfg!(unix) {
        "unix:///tmp/firma-sidecar-tools.sock"
    } else {
        "tcp://127.0.0.1:18081"
    };
    fs_err::write(
        &config_path,
        format!(
            r#"
[run.profiles.generic]
sidecar_endpoint = "{sidecar_endpoint}"

[run.profiles.generic.sidecar_local_exec]
endpoint = "{mediator_endpoint}"
allowed_executables = ['{}']
"#,
            directory.display()
        ),
    )?;

    let error = resolve_profile(&run_input(config_path))
        .expect_err("an allowlist directory must fail validation");

    let RunError::ConfigValidation(message) = error else {
        return Err(format!("expected ConfigValidation, got {error:?}").into());
    };
    assert_eq!(
        message,
        format!(
            "sidecar_local_exec.allowed_executables entries must point to existing regular files: {}",
            directory.display()
        )
    );
    Ok(())
}
