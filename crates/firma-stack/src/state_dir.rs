//! State directory resolution.

use std::path::PathBuf;

use tracing::debug;

use crate::error::Result;

/// Resolve the stack runtime state directory.
///
/// # Errors
///
/// Returns an error on Windows when no supported fallback environment variable exists.
pub fn resolve_state_dir(flag: Option<PathBuf>) -> Result<PathBuf> {
    let firma_state_dir = std::env::var("FIRMA_STATE_DIR").ok();
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok();
    let local_app_data = std::env::var("LOCALAPPDATA").ok();
    let temp = std::env::var("TEMP").ok();
    let resolved =
        resolve_state_dir_from(flag, firma_state_dir, xdg_runtime_dir, local_app_data, temp)?;
    debug!(path = %resolved.display(), "resolved state_dir");
    Ok(resolved)
}

#[doc(hidden)]
#[cfg_attr(windows, allow(clippy::needless_pass_by_value))]
pub fn resolve_state_dir_from(
    flag: Option<PathBuf>,
    firma_state_dir: Option<String>,
    xdg_runtime_dir: Option<String>,
    local_app_data: Option<String>,
    temp: Option<String>,
) -> Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path);
    }
    if let Some(env) = firma_state_dir.filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(env));
    }

    #[cfg(unix)]
    {
        let _ = (local_app_data, temp);
        if let Some(xdg) = xdg_runtime_dir.filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(xdg).join("firma"));
        }
        Ok(PathBuf::from(format!("/tmp/firma-{}", unix_uid())))
    }

    #[cfg(windows)]
    {
        let _ = xdg_runtime_dir;
        if let Some(local) = local_app_data.filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(local).join("firma").join("runtime"));
        }
        if let Some(tmp) = temp.filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(tmp).join("firma"));
        }
        Err(crate::StackError::StateDir(
            "neither LOCALAPPDATA nor TEMP is set".into(),
        ))
    }
}

#[cfg(unix)]
fn unix_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}
