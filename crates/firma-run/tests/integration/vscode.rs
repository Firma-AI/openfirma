use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use firma_run::runtime::vscode::testing;
use tempfile::TempDir;

fn host_bin_with_code(tmpdir: &TempDir) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let host_bin = tmpdir.path().join("host-bin");
    fs::create_dir(&host_bin)?;
    fs::write(host_bin.join("code"), "#!/bin/sh\nexit 0\n")?;
    Ok(host_bin)
}

#[test]
fn prepare_shim_preserves_existing_user_settings() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_bin = host_bin_with_code(&tmpdir)?;
    let runtime_dir = tmpdir.path().join("runtime");
    let state_dir = tmpdir.path().join("state");
    let settings_path = state_dir
        .join("user-data")
        .join("User")
        .join("settings.json");
    fs::create_dir_all(
        settings_path
            .parent()
            .ok_or("settings path has no parent")?,
    )?;
    fs::write(&settings_path, r#"{"editor.fontSize": 16}"#)?;
    let mut env = BTreeMap::from([("PATH".to_string(), host_bin.display().to_string())]);

    let (executable, args) = testing::prepare_vscode_shim(
        &runtime_dir,
        &state_dir,
        "code",
        vec![".".to_string()],
        &mut env,
        Some(&host_bin),
    )?;

    assert_eq!(args, ["."]);
    assert!(executable.is_file());
    let settings: serde_json::Value = serde_json::from_slice(&fs::read(settings_path)?)?;
    assert_eq!(settings["editor.fontSize"], 16);
    assert_eq!(settings["github-authentication.preferDeviceCodeFlow"], true);
    assert!(
        env.get("PATH")
            .is_some_and(|path| path.starts_with(&runtime_dir.join("bin").display().to_string()))
    );
    Ok(())
}

#[test]
fn prepare_shim_rejects_malformed_existing_settings() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_bin = host_bin_with_code(&tmpdir)?;
    let runtime_dir = tmpdir.path().join("runtime");
    let state_dir = tmpdir.path().join("state");
    let settings_path = state_dir
        .join("user-data")
        .join("User")
        .join("settings.json");
    fs::create_dir_all(
        settings_path
            .parent()
            .ok_or("settings path has no parent")?,
    )?;
    fs::write(settings_path, "not JSON")?;

    let error = testing::prepare_vscode_shim(
        &runtime_dir,
        &state_dir,
        "code",
        Vec::new(),
        &mut BTreeMap::new(),
        Some(&host_bin),
    )
    .expect_err("malformed existing settings must fail closed");

    assert!(error.to_string().contains("parse VS Code settings file"));
    Ok(())
}

#[test]
fn prepare_shim_reports_user_data_directory_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_bin = host_bin_with_code(&tmpdir)?;
    let state_dir = tmpdir.path().join("state");
    fs::create_dir_all(&state_dir)?;
    fs::write(state_dir.join("user-data"), "not a directory")?;

    let error = testing::prepare_vscode_shim(
        &tmpdir.path().join("runtime"),
        &state_dir,
        "code",
        Vec::new(),
        &mut BTreeMap::new(),
        Some(&host_bin),
    )
    .expect_err("a state file must not be accepted as the user-data directory");

    assert!(error.to_string().contains("create VS Code user-data dir"));
    Ok(())
}

#[test]
fn prepare_shim_reports_shim_write_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_bin = host_bin_with_code(&tmpdir)?;
    let runtime_dir = tmpdir.path().join("runtime");
    let shim_name = if cfg!(windows) { "code.cmd" } else { "code" };
    fs::create_dir_all(runtime_dir.join("bin").join(shim_name))?;

    let error = testing::prepare_vscode_shim(
        &runtime_dir,
        &tmpdir.path().join("state"),
        "code",
        Vec::new(),
        &mut BTreeMap::new(),
        Some(&host_bin),
    )
    .expect_err("a directory must not be accepted as a shim file");

    assert!(error.to_string().contains("write VS Code shim"));
    Ok(())
}

#[test]
fn executable_resolution_rejects_missing_host_command() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_bin = tmpdir.path().join("host-bin");
    fs::create_dir(&host_bin)?;

    let error = testing::resolve_host_executable("code", Some(&host_bin))
        .expect_err("an absent host launcher must fail closed");

    assert!(
        error
            .to_string()
            .contains("cannot resolve executable 'code' on host PATH")
    );
    Ok(())
}

#[test]
fn executable_resolution_rejects_missing_explicit_path() {
    let error = testing::resolve_host_executable("/definitely/not/a/code-launcher", None)
        .expect_err("a missing explicit path must fail closed");

    assert!(
        error
            .to_string()
            .contains("cannot resolve executable '/definitely/not/a/code-launcher' at")
    );
}

#[test]
fn executable_resolution_accepts_existing_explicit_path() -> Result<(), Box<dyn std::error::Error>>
{
    let tmpdir = tempfile::tempdir()?;
    let executable = tmpdir.path().join("code");
    fs::write(&executable, "#!/bin/sh\nexit 0\n")?;

    let resolved = testing::resolve_host_executable(&executable.display().to_string(), None)?;

    assert_eq!(resolved, executable);
    Ok(())
}

#[test]
fn recognizes_supported_code_launcher_names() {
    assert!(testing::is_vscode_code_launcher("code"));
    assert!(testing::is_vscode_code_launcher("CODE.CMD"));
    assert!(testing::is_vscode_code_launcher("Code.ExE"));
    assert!(!testing::is_vscode_code_launcher("code-insiders"));
}

#[test]
fn state_dir_defaults_to_runtime_when_config_is_absent() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let runtime_dir = tmpdir.path().join("runtime");

    let state_dir = testing::resolve_state_dir(None, &runtime_dir)?;

    assert_eq!(state_dir, runtime_dir.join("vscode"));
    Ok(())
}

#[test]
fn managed_arguments_allow_non_conflicting_values() -> Result<(), Box<dyn std::error::Error>> {
    testing::reject_conflicting_args(&["--verbose".to_string(), "workspace".to_string()])?;
    Ok(())
}

#[test]
fn private_directory_is_created() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let directory = tmpdir.path().join("private");

    testing::create_private_dir(&directory, "test private directory")?;

    assert!(directory.is_dir());
    Ok(())
}

#[test]
fn prepend_path_uses_host_path_when_execution_path_is_absent() {
    let shim_dir = Path::new("/tmp/firma-shim");
    let host_path = Path::new("/usr/local/bin");
    let mut env = BTreeMap::new();

    testing::prepend_path(&mut env, shim_dir, Some(host_path.as_os_str()));
    let expected_path = std::env::join_paths([shim_dir, host_path])
        .expect("test paths must be valid PATH entries")
        .to_string_lossy()
        .into_owned();

    assert_eq!(env.get("PATH"), Some(&expected_path));
}

#[test]
fn prepend_path_uses_only_shim_directory_without_existing_path() {
    let shim_dir = Path::new("/tmp/firma-shim");
    let mut env = BTreeMap::new();

    testing::prepend_path(&mut env, shim_dir, None);

    assert_eq!(env.get("PATH"), Some(&shim_dir.display().to_string()));
}

#[cfg(not(windows))]
#[test]
fn shell_quoting_escapes_embedded_single_quotes() {
    assert_eq!(testing::shell_single_quote("a'b"), "'a'\\''b'");
}

#[cfg(unix)]
#[test]
fn replace_symlink_replaces_existing_link() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let source = tmpdir.path().join("source");
    let old_source = tmpdir.path().join("old-source");
    let target = tmpdir.path().join("target");
    fs::write(&source, "source")?;
    fs::write(&old_source, "old source")?;
    std::os::unix::fs::symlink(&old_source, &target)?;

    testing::replace_symlink(&source, &target)?;

    assert_eq!(fs::read_link(target)?, source);
    Ok(())
}

#[cfg(unix)]
#[test]
fn replace_symlink_rejects_directory_target() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let source = tmpdir.path().join("source");
    let target = tmpdir.path().join("target");
    fs::write(&source, "source")?;
    fs::create_dir(&target)?;

    let error = testing::replace_symlink(&source, &target)
        .expect_err("a directory cannot be replaced with a socket link");

    assert!(
        error
            .to_string()
            .contains("remove stale VS Code desktop socket link")
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn wayland_configuration_links_relative_host_socket() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_runtime_dir = tmpdir.path().join("host-runtime");
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir_all(&host_runtime_dir)?;
    fs::create_dir_all(&desktop_runtime_dir)?;
    let source = host_runtime_dir.join("wayland-0");
    fs::write(&source, "socket")?;
    let env = BTreeMap::from([("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string())]);

    testing::configure_wayland_socket(&desktop_runtime_dir, &env, Some(&host_runtime_dir))?;

    assert_eq!(
        fs::read_link(desktop_runtime_dir.join("wayland-0"))?,
        source
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn wayland_configuration_ignores_absolute_display_path() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;
    let env = BTreeMap::from([("WAYLAND_DISPLAY".to_string(), "/tmp/wayland-0".to_string())]);

    testing::configure_wayland_socket(&desktop_runtime_dir, &env, None)?;

    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn wayland_configuration_ignores_missing_display_name() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;

    testing::configure_wayland_socket(&desktop_runtime_dir, &BTreeMap::new(), None)?;

    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn wayland_configuration_ignores_relative_display_without_host_runtime_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;
    let env = BTreeMap::from([("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string())]);

    testing::configure_wayland_socket(&desktop_runtime_dir, &env, None)?;

    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn wayland_configuration_ignores_missing_host_socket() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let host_runtime_dir = tmpdir.path().join("host-runtime");
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&host_runtime_dir)?;
    fs::create_dir(&desktop_runtime_dir)?;
    let env = BTreeMap::from([("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string())]);

    testing::configure_wayland_socket(&desktop_runtime_dir, &env, Some(&host_runtime_dir))?;

    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn dbus_configuration_links_unix_socket_and_rewrites_address()
-> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;
    let source = tmpdir.path().join("host-bus");
    fs::write(&source, "socket")?;
    let mut env = BTreeMap::new();
    let address = format!("unix:path={}", source.display());

    testing::configure_dbus_socket(&desktop_runtime_dir, &mut env, Some(&address))?;

    let target = desktop_runtime_dir.join("bus");
    assert_eq!(fs::read_link(&target)?, source);
    assert_eq!(
        env.get("DBUS_SESSION_BUS_ADDRESS"),
        Some(&format!("unix:path={}", target.display()))
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn dbus_configuration_ignores_non_unix_address() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;
    let mut env = BTreeMap::new();

    testing::configure_dbus_socket(&desktop_runtime_dir, &mut env, Some("tcp:host=localhost"))?;

    assert!(env.is_empty());
    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn dbus_configuration_ignores_absent_address() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;
    let mut env = BTreeMap::new();

    testing::configure_dbus_socket(&desktop_runtime_dir, &mut env, None)?;

    assert!(env.is_empty());
    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn dbus_configuration_ignores_missing_host_socket() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let desktop_runtime_dir = tmpdir.path().join("desktop-runtime");
    fs::create_dir(&desktop_runtime_dir)?;
    let missing_socket = tmpdir.path().join("missing-bus");
    let mut env = BTreeMap::new();
    let address = format!("unix:path={}", missing_socket.display());

    testing::configure_dbus_socket(&desktop_runtime_dir, &mut env, Some(&address))?;

    assert!(env.is_empty());
    assert!(fs::read_dir(desktop_runtime_dir)?.next().is_none());
    Ok(())
}
