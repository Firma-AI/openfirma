//! Resolution of firma runtime directories.
//!
//! Linux uses `XDG_RUNTIME_DIR`. macOS and Windows have no XDG equivalent;
//! the fallback path is `/tmp/firma-$UID` (Unix) or `%LOCALAPPDATA%\firma\runtime`
//! (Windows).

use std::path::{Path, PathBuf};

/// Return `<runtime>/firma`. Pure resolver with no I/O. Reads
/// `FIRMA_STATE_DIR` / `XDG_RUNTIME_DIR` / `LOCALAPPDATA` from the current
/// process environment.
#[must_use]
pub fn default_runtime_dir() -> PathBuf {
    let firma_state_dir = std::env::var("FIRMA_STATE_DIR").ok();
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let local = std::env::var("LOCALAPPDATA").ok();
    let uid = current_uid();
    default_runtime_dir_from(xdg, firma_state_dir, local, uid)
}

/// Compute the runtime dir from explicit inputs. Exposed for tests and
/// internal callers that need to inject environment overrides.
#[doc(hidden)]
#[cfg_attr(
    unix,
    expect(
        clippy::needless_pass_by_value,
        reason = "the pure helper takes owned env overrides so tests and callers can pass them through directly"
    )
)]
#[must_use]
pub fn default_runtime_dir_from(
    xdg_runtime_dir: Option<String>,
    firma_state_dir: Option<String>,
    local_app_data: Option<String>,
    uid: u32,
) -> PathBuf {
    if let Some(env) = firma_state_dir.filter(|value| !value.is_empty()) {
        return PathBuf::from(env);
    }
    #[cfg(unix)]
    {
        let _ = local_app_data;
        if let Some(xdg) = xdg_runtime_dir.filter(|value| !value.is_empty()) {
            return PathBuf::from(xdg).join("firma");
        }
        PathBuf::from(format!("/tmp/firma-{uid}"))
    }
    #[cfg(windows)]
    {
        let _ = (xdg_runtime_dir, uid);
        local_app_data
            .filter(|value| !value.is_empty())
            .map_or_else(
                || PathBuf::from(r"C:\Temp\firma"),
                |path| PathBuf::from(path).join("firma").join("runtime"),
            )
    }
}

/// `<runtime>/capabilities` — directory holding per-sandbox capability
/// seed files written by `firma run`.
#[must_use]
pub fn capabilities_dir_from(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("capabilities")
}

/// `<runtime>/run` — directory that contains one subdirectory per
/// autostarted per-run sidecar.
#[must_use]
pub fn run_dir_from(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("run")
}

/// `<runtime>/run/<sandbox_id>` — marker directory for a single
/// per-run sidecar.
#[must_use]
pub fn run_entry_from(runtime_dir: &Path, sandbox_id: impl AsRef<Path>) -> PathBuf {
    run_dir_from(runtime_dir).join(sandbox_id)
}

#[cfg(unix)]
fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}

#[cfg(windows)]
fn current_uid() -> u32 {
    0
}

/// `<runtime>/capabilities/<name>.toml` — the per-sandbox capability seed
/// file written by `firma run`.
#[must_use]
pub fn capability_seed_path(name: impl AsRef<str>) -> PathBuf {
    let runtime_dir = default_runtime_dir();
    let cap_dir = capabilities_dir_from(&runtime_dir);
    cap_dir.join(format!("{}.toml", name.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_dir_is_runtime_subdir() {
        let dir = capabilities_dir_from(std::path::Path::new("/run/firma"));
        assert_eq!(dir, std::path::PathBuf::from("/run/firma/capabilities"));
    }
}
