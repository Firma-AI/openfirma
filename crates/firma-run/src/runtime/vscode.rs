//! Implements the VS Code runtime integration.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use crate::backend::SandboxHandle;
use crate::config::MountSpec;
use crate::config::ResolvedProfile;
use crate::error::RunError;

pub(super) fn should_apply_vscode_shim(profile: &ResolvedProfile, executable: &str) -> bool {
    profile.id == "vscode"
        && Path::new(executable)
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(is_vscode_code_launcher)
}

fn is_vscode_code_launcher(name: &str) -> bool {
    name == "code" || name.eq_ignore_ascii_case("code.cmd") || name.eq_ignore_ascii_case("code.exe")
}

#[derive(Debug)]
pub(super) struct PreparedVscodeShim {
    pub(super) executable: PathBuf,
    pub(super) args: Vec<String>,
}

pub(super) fn prepare_vscode_shim(
    runtime_dir: &Path,
    state_dir: &Path,
    executable: &str,
    args: Vec<String>,
    env: &mut BTreeMap<String, String>,
    host_path: Option<&OsStr>,
) -> Result<PreparedVscodeShim, RunError> {
    reject_vscode_conflicting_args(&args)?;
    let real_code = resolve_host_executable(executable, host_path)?;
    let user_data_dir = state_dir.join("user-data");
    let extensions_dir = state_dir.join("extensions");
    let desktop_runtime_dir = runtime_dir.join("vscode").join("xdg-runtime");
    let shim_dir = runtime_dir.join("bin");
    let shim_path = vscode_shim_path(&shim_dir);

    std::fs::create_dir_all(&user_data_dir).map_err(|error| {
        RunError::Internal(format!(
            "create VS Code user-data dir {}: {error}",
            user_data_dir.display()
        ))
    })?;
    std::fs::create_dir_all(&extensions_dir).map_err(|error| {
        RunError::Internal(format!(
            "create VS Code extensions dir {}: {error}",
            extensions_dir.display()
        ))
    })?;
    create_private_dir(&desktop_runtime_dir, "VS Code desktop runtime dir")?;
    std::fs::create_dir_all(&shim_dir).map_err(|error| {
        RunError::Internal(format!(
            "create VS Code shim dir {}: {error}",
            shim_dir.display()
        ))
    })?;

    let script = vscode_shim_script(&real_code);
    std::fs::write(&shim_path, script).map_err(|error| {
        RunError::Internal(format!(
            "write VS Code shim {}: {error}",
            shim_path.display()
        ))
    })?;
    #[cfg(unix)]
    set_executable_permissions(&shim_path)?;
    seed_vscode_user_settings(&user_data_dir)?;

    env.insert(
        "FIRMA_RUN_VSCODE_USER_DATA_DIR".to_string(),
        user_data_dir.display().to_string(),
    );
    env.insert(
        "FIRMA_RUN_VSCODE_EXTENSIONS_DIR".to_string(),
        extensions_dir.display().to_string(),
    );
    env.insert(
        "TMPDIR".to_string(),
        desktop_runtime_dir.display().to_string(),
    );
    env.insert(
        "XDG_RUNTIME_DIR".to_string(),
        desktop_runtime_dir.display().to_string(),
    );
    #[cfg(unix)]
    configure_vscode_desktop_sockets(&desktop_runtime_dir, env)?;
    prepend_path(env, &shim_dir, host_path);

    tracing::info!(
        shim = %shim_path.display(),
        real_code = %real_code.display(),
        "prepared VS Code runtime shim"
    );

    Ok(PreparedVscodeShim {
        executable: shim_path,
        args,
    })
}

pub(super) fn resolve_vscode_state_dir(
    config_path: Option<&Path>,
    runtime_dir: &Path,
) -> Result<PathBuf, RunError> {
    let state_dir = config_path
        .and_then(Path::parent)
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(
            || runtime_dir.join("vscode"),
            |config_dir| config_dir.join("vscode"),
        );
    std::path::absolute(&state_dir).map_err(|error| {
        RunError::Internal(format!(
            "resolve VS Code state dir {}: {error}",
            state_dir.display()
        ))
    })
}

pub(super) fn ensure_vscode_state_mount(handle: &mut SandboxHandle, state_dir: &Path) {
    let already_mounted = handle
        .mounts
        .iter()
        .any(|mount| mount.source == state_dir && mount.target == state_dir && !mount.read_only);
    if already_mounted {
        return;
    }
    handle.mounts.push(MountSpec {
        source: state_dir.to_path_buf(),
        target: state_dir.to_path_buf(),
        read_only: false,
    });
}

fn seed_vscode_user_settings(user_data_dir: &Path) -> Result<(), RunError> {
    let user_settings_dir = user_data_dir.join("User");
    std::fs::create_dir_all(&user_settings_dir).map_err(|error| {
        RunError::Internal(format!(
            "create VS Code settings dir {}: {error}",
            user_settings_dir.display()
        ))
    })?;
    let settings_path = user_settings_dir.join("settings.json");
    let mut settings = if settings_path.exists() {
        let bytes = std::fs::read(&settings_path).map_err(|error| {
            RunError::Internal(format!(
                "read VS Code settings file {}: {error}",
                settings_path.display()
            ))
        })?;
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&bytes).map_err(
            |error| {
                RunError::Internal(format!(
                    "parse VS Code settings file {}: {error}",
                    settings_path.display()
                ))
            },
        )?
    } else {
        serde_json::Map::new()
    };
    settings.insert(
        "github-authentication.preferDeviceCodeFlow".to_string(),
        serde_json::Value::Bool(true),
    );
    let serialized = serde_json::to_vec_pretty(&settings).map_err(|error| {
        RunError::Internal(format!(
            "serialize VS Code settings file {}: {error}",
            settings_path.display()
        ))
    })?;
    std::fs::write(&settings_path, serialized).map_err(|error| {
        RunError::Internal(format!(
            "write VS Code settings file {}: {error}",
            settings_path.display()
        ))
    })
}

fn reject_vscode_conflicting_args(args: &[String]) -> Result<(), RunError> {
    for arg in args {
        let conflict = matches!(
            arg.as_str(),
            "--reuse-window" | "-r" | "--user-data-dir" | "--extensions-dir"
        ) || arg.starts_with("--user-data-dir=")
            || arg.starts_with("--extensions-dir=");
        if conflict {
            return Err(RunError::ConfigValidation(format!(
                "vscode profile manages VS Code process lifetime and isolated state; remove conflicting argument '{arg}'"
            )));
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path, label: &str) -> Result<(), RunError> {
    std::fs::create_dir_all(path).map_err(|error| {
        RunError::Internal(format!("create {label} {}: {error}", path.display()))
    })?;
    #[cfg(unix)]
    set_private_dir_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<(), RunError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .map_err(|error| RunError::Internal(format!("stat {}: {error}", path.display())))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| RunError::Internal(format!("chmod {}: {error}", path.display())))
}

#[cfg(unix)]
fn configure_vscode_desktop_sockets(
    desktop_runtime_dir: &Path,
    env: &mut BTreeMap<String, String>,
) -> Result<(), RunError> {
    configure_vscode_wayland_socket(desktop_runtime_dir, env)?;
    configure_vscode_dbus_socket(desktop_runtime_dir, env)?;
    Ok(())
}

#[cfg(unix)]
fn configure_vscode_wayland_socket(
    desktop_runtime_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Result<(), RunError> {
    let Some(wayland_display) = env.get("WAYLAND_DISPLAY").cloned() else {
        tracing::debug!("VS Code Wayland socket not configured because WAYLAND_DISPLAY is unset");
        return Ok(());
    };
    let display_path = Path::new(&wayland_display);
    if display_path.is_absolute() {
        tracing::debug!(
            wayland_display = %wayland_display,
            "VS Code Wayland socket not configured because WAYLAND_DISPLAY is already absolute"
        );
        return Ok(());
    }
    let Some(host_runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") else {
        tracing::debug!(
            wayland_display = %wayland_display,
            "VS Code Wayland socket not configured because host XDG_RUNTIME_DIR is unset"
        );
        return Ok(());
    };
    let source = PathBuf::from(host_runtime_dir).join(&wayland_display);
    if source.exists() {
        let target = desktop_runtime_dir.join(&wayland_display);
        replace_symlink(&source, &target)?;
        tracing::debug!(
            source = %source.display(),
            target = %target.display(),
            "VS Code Wayland socket linked into runtime"
        );
    } else {
        tracing::debug!(
            source = %source.display(),
            "VS Code Wayland socket not configured because host socket is missing"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn configure_vscode_dbus_socket(
    desktop_runtime_dir: &Path,
    env: &mut BTreeMap<String, String>,
) -> Result<(), RunError> {
    let Some(address) = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok() else {
        tracing::debug!(
            "VS Code D-Bus socket not configured because DBUS_SESSION_BUS_ADDRESS is unset"
        );
        return Ok(());
    };
    let Some(path) = address.strip_prefix("unix:path=") else {
        tracing::debug!(
            "VS Code D-Bus socket not configured because DBUS_SESSION_BUS_ADDRESS is not a unix:path address"
        );
        return Ok(());
    };
    let source = PathBuf::from(path);
    if source.exists() {
        let target = desktop_runtime_dir.join("bus");
        replace_symlink(&source, &target)?;
        env.insert(
            "DBUS_SESSION_BUS_ADDRESS".to_string(),
            format!("unix:path={}", target.display()),
        );
        tracing::debug!(
            source = %source.display(),
            target = %target.display(),
            "VS Code D-Bus socket linked into runtime"
        );
    } else {
        tracing::debug!(
            source = %source.display(),
            "VS Code D-Bus socket not configured because host socket is missing"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn replace_symlink(source: &Path, target: &Path) -> Result<(), RunError> {
    match std::fs::remove_file(target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(RunError::Internal(format!(
                "remove stale VS Code desktop socket link {}: {error}",
                target.display()
            )));
        }
    }
    std::os::unix::fs::symlink(source, target).map_err(|error| {
        RunError::Internal(format!(
            "link VS Code desktop socket {} -> {}: {error}",
            target.display(),
            source.display()
        ))
    })
}

pub(super) fn resolve_host_executable(
    executable: &str,
    host_path: Option<&OsStr>,
) -> Result<PathBuf, RunError> {
    let candidate = PathBuf::from(executable);
    if candidate
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return require_file(candidate, executable);
    }

    let path_value = host_path
        .map(std::ffi::OsString::from)
        .or_else(|| std::env::var_os("PATH"))
        .ok_or_else(|| {
            RunError::ConfigValidation(format!(
                "cannot resolve executable '{executable}' because host PATH is not set"
            ))
        })?;
    for dir in std::env::split_paths(&path_value) {
        for candidate in executable_search_candidates(&dir, executable) {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(RunError::ConfigValidation(format!(
        "cannot resolve executable '{executable}' on host PATH"
    )))
}

#[cfg(windows)]
fn executable_search_candidates(dir: &Path, executable: &str) -> Vec<PathBuf> {
    let direct = dir.join(executable);
    if Path::new(executable).extension().is_some() {
        return vec![direct];
    }

    let mut candidates = vec![direct];
    let path_ext = std::env::var_os("PATHEXT").map_or_else(
        || ".COM;.EXE;.BAT;.CMD".to_string(),
        |value| value.to_string_lossy().into_owned(),
    );
    candidates.extend(
        path_ext
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| dir.join(format!("{executable}{extension}"))),
    );
    candidates
}

#[cfg(not(windows))]
fn executable_search_candidates(dir: &Path, executable: &str) -> Vec<PathBuf> {
    vec![dir.join(executable)]
}

fn require_file(candidate: PathBuf, executable: &str) -> Result<PathBuf, RunError> {
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(RunError::ConfigValidation(format!(
            "cannot resolve executable '{executable}' at {}",
            candidate.display()
        )))
    }
}

#[cfg(windows)]
pub(super) fn vscode_shim_path(shim_dir: &Path) -> PathBuf {
    shim_dir.join("code.cmd")
}

#[cfg(not(windows))]
pub(super) fn vscode_shim_path(shim_dir: &Path) -> PathBuf {
    shim_dir.join("code")
}

#[cfg(windows)]
fn vscode_shim_script(real_code: &Path) -> String {
    let quoted_real_code = batch_quote(&real_code.display().to_string());
    format!(
        "@echo off\r\n\
         setlocal\r\n\
         if \"%FIRMA_RUN_VSCODE_USER_DATA_DIR%\"==\"\" exit /b 2\r\n\
         if \"%FIRMA_RUN_VSCODE_EXTENSIONS_DIR%\"==\"\" exit /b 2\r\n\
         call {quoted_real_code} --no-sandbox --wait --new-window \
         --user-data-dir \"%FIRMA_RUN_VSCODE_USER_DATA_DIR%\" \
         --extensions-dir \"%FIRMA_RUN_VSCODE_EXTENSIONS_DIR%\" %*\r\n\
         exit /b %ERRORLEVEL%\r\n"
    )
}

#[cfg(not(windows))]
fn vscode_shim_script(real_code: &Path) -> String {
    let quoted_real_code = shell_single_quote(&real_code.display().to_string());
    format!(
        "#!/bin/sh\n\
         set -eu\n\
         exec {quoted_real_code} --no-sandbox --wait --new-window \
         --user-data-dir \"${{FIRMA_RUN_VSCODE_USER_DATA_DIR:?}}\" \
         --extensions-dir \"${{FIRMA_RUN_VSCODE_EXTENSIONS_DIR:?}}\" \"$@\"\n"
    )
}

#[cfg(windows)]
fn batch_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(not(windows))]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn prepend_path(env: &mut BTreeMap<String, String>, shim_dir: &Path, host_path: Option<&OsStr>) {
    let previous = env
        .get("PATH")
        .cloned()
        .or_else(|| host_path.map(|value| value.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let separator = if cfg!(windows) { ";" } else { ":" };
    let next = if previous.is_empty() {
        shim_dir.display().to_string()
    } else {
        format!("{}{separator}{previous}", shim_dir.display())
    };
    env.insert("PATH".to_string(), next);
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> Result<(), RunError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .map_err(|error| RunError::Internal(format!("stat {}: {error}", path.display())))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| RunError::Internal(format!("chmod {}: {error}", path.display())))
}
