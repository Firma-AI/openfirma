#![cfg(target_os = "linux")]

use firma_run::backend::BackendKind;
use firma_run::backend::platform::detect_wsl;
use firma_run::config::resolve_profile;
use firma_run::runtime::RunInput;

fn run_input(backend: Option<BackendKind>) -> RunInput {
    RunInput {
        profile: "generic".to_string(),
        config: None,
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
