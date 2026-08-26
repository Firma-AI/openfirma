#![cfg(target_os = "linux")]

use std::path::PathBuf;

use firma_run::backend::BackendKind;
use firma_run::backend::platform::detect_wsl;
use firma_run::config::resolve_profile;
use firma_run::error::RunError;
use firma_run::runtime::RunInput;

fn run_input(backend: Option<BackendKind>) -> RunInput {
    run_input_inner(backend, None)
}

fn run_input_inner(backend: Option<BackendKind>, config: Option<PathBuf>) -> RunInput {
    RunInput {
        profile: "generic".to_string(),
        config,
        backend,
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

fn expected_linux_default() -> BackendKind {
    if detect_wsl().is_wsl() {
        BackendKind::Wsl2
    } else {
        BackendKind::Bwrap
    }
}

#[test]
fn implicit_backend_uses_the_runtime_linux_default() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = resolve_profile(&run_input(None))?;

    assert_eq!(resolved.backend, expected_linux_default());
    Ok(())
}

#[test]
fn unsupported_backend_falls_back_to_the_runtime_linux_default()
-> Result<(), Box<dyn std::error::Error>> {
    let resolved = resolve_profile(&run_input(Some(BackendKind::Vz)))?;

    assert_eq!(resolved.backend, expected_linux_default());
    Ok(())
}

#[test]
fn explicit_wsl2_is_supported_only_inside_wsl() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = resolve_profile(&run_input(Some(BackendKind::Wsl2)))?;

    assert_eq!(resolved.backend, expected_linux_default());
    Ok(())
}

#[test]
fn backend_kind_parses_every_supported_name() -> Result<(), Box<dyn std::error::Error>> {
    for (name, expected) in [
        ("bwrap", BackendKind::Bwrap),
        ("vz", BackendKind::Vz),
        ("wsl2", BackendKind::Wsl2),
        ("firecracker", BackendKind::Firecracker),
    ] {
        assert_eq!(name.parse::<BackendKind>()?, expected);
        // round-trips through `Display`
        assert_eq!(expected.to_string(), name);
    }
    Ok(())
}

#[test]
fn unknown_backend_in_selected_profile_fails_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let config_path = tmpdir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.profiles.generic]
backend = "does-not-exist"
"#,
    )?;

    let error = resolve_profile(&run_input_inner(None, Some(config_path)))
        .expect_err("unknown backend string must fail resolution");

    let RunError::ConfigParse { reason, .. } = error else {
        return Err(format!("expected ConfigParse, got {error:?}").into());
    };
    assert!(
        reason.contains("does-not-exist"),
        "error names rejected backend: {reason}"
    );
    Ok(())
}

#[test]
fn unknown_backend_in_unselected_profile_fails_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let config_path = tmpdir.path().join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.profiles.generic]
backend = "bwrap"

[run.profiles.unselected]
backend = "does-not-exist"
"#,
    )?;

    let error = resolve_profile(&run_input_inner(None, Some(config_path)))
        .expect_err("unknown backend in any profile must fail parsing");

    let RunError::ConfigParse { reason, .. } = error else {
        return Err(format!("expected ConfigParse, got {error:?}").into());
    };
    assert!(
        reason.contains("does-not-exist"),
        "error names rejected backend: {reason}"
    );
    Ok(())
}
