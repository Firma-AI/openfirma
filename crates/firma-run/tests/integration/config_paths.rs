use std::path::PathBuf;

use firma_run::config::{CapabilitySource, resolve_profile};
use firma_run::runtime::RunInput;

fn run_input(config: PathBuf, profile: &str) -> RunInput {
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
#[expect(
    clippy::too_many_lines,
    reason = "one fixture must cover defaults plus selected and unselected profile resource paths"
)]
fn relative_config_anchors_selected_resources_without_selecting_other_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let current_dir = std::env::current_dir()?;
    let tmpdir = tempfile::tempdir_in(&current_dir)?;
    let config_dir = tmpdir.path().join("config");
    fs_err::create_dir_all(&config_dir)?;
    fs_err::create_dir_all(config_dir.join("seccomp"))?;
    fs_err::write(config_dir.join("seccomp/selected.toml"), "version = 1\n")?;
    fs_err::write(config_dir.join("seccomp/unselected.toml"), "version = 1\n")?;
    let config_path = config_dir.join(firma_config_loader::CONFIG_FILE_NAME);
    fs_err::write(
        &config_path,
        r#"
[run.defaults.capability]
public_key_path = "keys/default.pub"

[run.profiles.generic]
backend = "bwrap"

[[run.profiles.generic.mounts]]
source = "selected-workspace"
target = "/sandbox/selected"

[run.profiles.generic.seccomp_policy]
source_policy_path = "seccomp/selected.toml"
artifact_dir = "artifacts/selected"

[run.profiles.generic.capability.source]
kind = "file"
path = "capabilities/selected.toml"

[run.profiles.codex]
backend = "bwrap"

[[run.profiles.codex.mounts]]
source = "unselected-workspace"
target = "/sandbox/unselected"

[run.profiles.codex.seccomp_policy]
source_policy_path = "seccomp/unselected.toml"
artifact_dir = "artifacts/unselected"

[run.profiles.codex.capability]
kind = "file"
path = "capabilities/unselected.toml"
"#,
    )?;
    let relative_config = config_path.strip_prefix(&current_dir)?.to_path_buf();

    let selected = resolve_profile(&run_input(relative_config.clone(), "generic"))?;

    assert_eq!(
        selected.capability.source,
        CapabilitySource::File {
            path: config_dir.join("capabilities/selected.toml")
        }
    );
    assert_eq!(
        selected.capability.public_key_path,
        Some(config_dir.join("keys/default.pub"))
    );
    let selected_json = serde_json::to_value(selected)?;
    assert_eq!(
        selected_json["mounts"][0]["source"],
        config_dir
            .join("selected-workspace")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(selected_json["mounts"][0]["target"], "/sandbox/selected");
    assert_eq!(
        selected_json["seccomp_policy"]["source_policy_path"],
        config_dir
            .join("seccomp/selected.toml")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(
        selected_json["seccomp_policy"]["artifact_dir"],
        config_dir
            .join("artifacts/selected")
            .to_string_lossy()
            .as_ref()
    );

    let unselected = resolve_profile(&run_input(relative_config, "codex"))?;
    assert_eq!(
        unselected.capability.source,
        CapabilitySource::File {
            path: config_dir.join("capabilities/unselected.toml")
        }
    );
    let unselected_json = serde_json::to_value(unselected)?;
    assert_eq!(
        unselected_json["mounts"][0]["source"],
        config_dir
            .join("unselected-workspace")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(
        unselected_json["seccomp_policy"]["source_policy_path"],
        config_dir
            .join("seccomp/unselected.toml")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(
        unselected_json["seccomp_policy"]["artifact_dir"],
        config_dir
            .join("artifacts/unselected")
            .to_string_lossy()
            .as_ref()
    );
    Ok(())
}
