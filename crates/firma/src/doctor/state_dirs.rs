//! Check 7: state and data directory presence + permissions.

use std::path::{Path, PathBuf};

use crate::doctor::report::Check;

/// Resolve `$XDG_DATA_HOME/firma` / platform fallback.
#[must_use]
pub fn resolve_data_dir(
    xdg_data_home: Option<&str>,
    home: Option<&str>,
    appdata: Option<&str>,
) -> Option<PathBuf> {
    if let Some(value) = xdg_data_home.filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(value).join("firma"));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = appdata;
        home.filter(|v| !v.is_empty())
            .map(|h| PathBuf::from(h).join(".local/share/firma"))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = appdata;
        home.filter(|v| !v.is_empty())
            .map(|h| PathBuf::from(h).join("Library/Application Support/firma"))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        appdata
            .filter(|v| !v.is_empty())
            .map(|a| PathBuf::from(a).join("firma\\data"))
    }
}

/// Run checks for the runtime state dir and the data dir.
#[must_use]
pub fn check(state_dir: &Path, data_dir: Option<&Path>) -> Vec<Check> {
    let mut out = Vec::with_capacity(2);
    out.push(check_one("state dir", state_dir));
    match data_dir {
        Some(p) => out.push(check_one("data dir", p)),
        None => out.push(Check::warn(
            "data dir",
            "could not resolve XDG_DATA_HOME / fallback",
        )),
    }
    out
}

fn check_one(label: &'static str, path: &Path) -> Check {
    let display = path.display().to_string();
    if !path.exists() {
        return Check::warn(label, format!("{display}: not present")).with_detail("path", display);
    }
    #[cfg(unix)]
    {
        match permission_mode(path) {
            Ok(0o700) => Check::ok(label, format!("{display}: mode 0700"))
                .with_detail("path", display)
                .with_detail("mode", "0700"),
            Ok(mode) => Check::fail(label, format!("{display}: mode {mode:o}; expected 0700"))
                .with_detail("path", display)
                .with_detail("mode", format!("{mode:o}")),
            Err(error) => {
                Check::fail(label, format!("{display}: stat: {error}")).with_detail("path", display)
            }
        }
    }
    #[cfg(not(unix))]
    {
        Check::ok(label, format!("{display}: present")).with_detail("path", display)
    }
}

#[cfg(unix)]
fn permission_mode(path: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path)?;
    Ok(meta.permissions().mode() & 0o777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::Status;

    #[test]
    fn resolve_data_dir_prefers_xdg_data_home() {
        let p = resolve_data_dir(Some("/x/data"), Some("/home/u"), None);
        assert_eq!(p, Some(PathBuf::from("/x/data/firma")));
    }

    #[test]
    fn state_dir_warn_when_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("does-not-exist");
        let checks = check(&missing, None);
        assert_eq!(checks[0].status, Status::Warn);
        assert!(checks[0].reason.contains("not present"));
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_ok_when_mode_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("s");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut perms = std::fs::metadata(&dir).expect("meta").permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&dir, perms).expect("chmod");
        let checks = check(&dir, None);
        assert_eq!(checks[0].status, Status::Ok);
        assert!(checks[0].reason.contains("mode 0700"));
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_fail_when_mode_wider_than_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("s");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut perms = std::fs::metadata(&dir).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dir, perms).expect("chmod");
        let checks = check(&dir, None);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(checks[0].reason.contains("mode 755"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_data_dir_falls_back_to_home_local_share_on_linux() {
        let p = resolve_data_dir(None, Some("/home/u"), None);
        assert_eq!(p, Some(PathBuf::from("/home/u/.local/share/firma")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_data_dir_falls_back_to_home_library_on_macos() {
        let p = resolve_data_dir(None, Some("/Users/u"), None);
        assert_eq!(
            p,
            Some(PathBuf::from("/Users/u/Library/Application Support/firma"))
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn resolve_data_dir_falls_back_to_appdata_on_windows() {
        let p = resolve_data_dir(None, None, Some("C:\\Users\\u\\AppData"));
        assert_eq!(p, Some(PathBuf::from("C:\\Users\\u\\AppData\\firma\\data")));
    }

    #[test]
    fn resolve_data_dir_returns_none_when_no_inputs() {
        let p = resolve_data_dir(None, None, None);
        assert!(p.is_none());
    }
}
