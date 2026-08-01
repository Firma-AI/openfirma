//! Host-platform probes used by sandbox backend selection and preflight checks.
//!
//! All probes are read-only and side-effect-free. On non-Linux targets the
//! functions return safe "not applicable" values so callers don't need
//! per-platform gating.

/// Characterises the WSL environment, if any, detected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslKind {
    /// Not running inside WSL; native Linux or another OS.
    NotWsl,
    /// Running inside WSL (version indeterminate or WSL 1).
    Wsl,
    /// Running inside WSL 2 specifically.
    Wsl2,
}

impl WslKind {
    /// Returns `true` for any WSL environment.
    #[must_use]
    pub fn is_wsl(self) -> bool {
        !matches!(self, Self::NotWsl)
    }
}

/// Detect whether the process is running inside WSL by reading
/// `/proc/sys/kernel/osrelease`.
///
/// Fails open: if the file cannot be read the function returns [`WslKind::NotWsl`]
/// so non-Linux or restricted environments do not produce false positives.
#[must_use]
pub fn detect_wsl() -> WslKind {
    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    classify_osrelease(&osrelease)
}

/// Pure inner function so tests can supply arbitrary osrelease strings.
fn classify_osrelease(osrelease: &str) -> WslKind {
    let lower = osrelease.to_ascii_lowercase();
    if lower.contains("microsoft") || lower.contains("wsl") {
        if lower.contains("wsl2") {
            WslKind::Wsl2
        } else {
            WslKind::Wsl
        }
    } else {
        WslKind::NotWsl
    }
}

/// Check whether unprivileged user namespace creation is blocked by a kernel
/// sysctl.
///
/// Returns `Some(sysctl_path)` naming the restricting knob when user namespaces
/// are disabled, `None` when they appear to be available or the check is
/// inconclusive (file absent ⟹ restriction not applicable on this kernel).
///
/// Two knobs are probed in order:
/// - `/proc/sys/kernel/unprivileged_userns_clone` — Debian/Ubuntu explicit
///   disable flag; value `"0"` means disabled.
/// - `/proc/sys/user/max_user_namespaces` — generic Linux (≥ 4.15); value
///   `"0"` means disabled.
#[must_use]
pub fn userns_restricted() -> Option<String> {
    check_sysctl_blocked(
        "/proc/sys/kernel/unprivileged_userns_clone",
        "/proc/sys/user/max_user_namespaces",
    )
}

/// Returns `true` when nested user-namespace creation (bwrap inside bwrap) is blocked.
///
/// Probes by running the exact nesting codex performs inside firma's outer sandbox,
/// catching `AppArmor` sysctls, per-binary profiles, setuid bwrap restrictions, and
/// any other mechanism. Always returns `false` on non-Linux.
#[must_use]
pub(crate) fn nested_userns_restricted() -> bool {
    #[cfg(not(target_os = "linux"))]
    return false;

    #[cfg(target_os = "linux")]
    !std::process::Command::new("bwrap")
        .args([
            "--unshare-user",
            "--ro-bind",
            "/",
            "/",
            "bwrap",
            "--unshare-user",
            "--ro-bind",
            "/",
            "/",
            "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Testable inner function that accepts explicit sysctl paths.
fn check_sysctl_blocked(
    unprivileged_clone_path: &str,
    max_namespaces_path: &str,
) -> Option<String> {
    for path in [unprivileged_clone_path, max_namespaces_path] {
        if let Ok(content) = std::fs::read_to_string(path)
            && content.trim() == "0"
        {
            return Some(path.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // ── WSL detection ────────────────────────────────────────────────────────

    #[test]
    fn wsl2_kernel_is_detected() {
        assert_eq!(
            classify_osrelease("5.15.90.1-microsoft-standard-WSL2"),
            WslKind::Wsl2
        );
    }

    #[test]
    fn wsl1_style_kernel_is_detected() {
        assert_eq!(classify_osrelease("4.4.0-22000-Microsoft"), WslKind::Wsl);
    }

    #[test]
    fn generic_wsl_without_version_suffix_is_detected() {
        assert_eq!(
            classify_osrelease("5.10.16.3-microsoft-standard"),
            WslKind::Wsl
        );
    }

    #[test]
    fn native_linux_is_not_wsl() {
        assert_eq!(classify_osrelease("6.8.0-52-generic"), WslKind::NotWsl);
    }

    #[test]
    fn empty_osrelease_is_not_wsl() {
        assert_eq!(classify_osrelease(""), WslKind::NotWsl);
    }

    #[test]
    fn wsl_kind_is_wsl_for_wsl_variants() {
        assert!(WslKind::Wsl.is_wsl());
        assert!(WslKind::Wsl2.is_wsl());
        assert!(!WslKind::NotWsl.is_wsl());
    }

    // ── User namespace restriction ───────────────────────────────────────────

    fn write_temp_sysctl(dir: &tempfile::TempDir, name: &str, value: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).expect("create temp sysctl");
        f.write_all(value.as_bytes()).expect("write temp sysctl");
        path
    }

    #[test]
    fn userns_restricted_when_unprivileged_clone_is_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clone_path = write_temp_sysctl(&dir, "unprivileged_userns_clone", "0\n");
        let max_path = write_temp_sysctl(&dir, "max_user_namespaces", "7340\n");
        let result = check_sysctl_blocked(
            clone_path.to_str().expect("path utf8"),
            max_path.to_str().expect("path utf8"),
        );
        assert!(result.is_some());
        assert!(result.unwrap().contains("unprivileged_userns_clone"));
    }

    #[test]
    fn userns_restricted_when_max_namespaces_is_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clone_path = dir.path().join("absent_clone");
        let max_path = write_temp_sysctl(&dir, "max_user_namespaces", "0\n");
        let result = check_sysctl_blocked(
            clone_path.to_str().expect("path utf8"),
            max_path.to_str().expect("path utf8"),
        );
        assert!(result.is_some());
        assert!(result.unwrap().contains("max_user_namespaces"));
    }

    #[test]
    fn userns_not_restricted_when_both_knobs_are_nonzero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clone_path = write_temp_sysctl(&dir, "unprivileged_userns_clone", "1\n");
        let max_path = write_temp_sysctl(&dir, "max_user_namespaces", "7340\n");
        let result = check_sysctl_blocked(
            clone_path.to_str().expect("path utf8"),
            max_path.to_str().expect("path utf8"),
        );
        assert!(result.is_none());
    }

    #[test]
    fn userns_not_restricted_when_sysctl_files_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = check_sysctl_blocked(
            dir.path().join("absent1").to_str().expect("path utf8"),
            dir.path().join("absent2").to_str().expect("path utf8"),
        );
        assert!(result.is_none());
    }

    #[test]
    fn userns_unprivileged_clone_checked_before_max_namespaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clone_path = write_temp_sysctl(&dir, "unprivileged_userns_clone", "0\n");
        let max_path = write_temp_sysctl(&dir, "max_user_namespaces", "0\n");
        let result = check_sysctl_blocked(
            clone_path.to_str().expect("path utf8"),
            max_path.to_str().expect("path utf8"),
        );
        // First matching path is returned
        assert!(result.unwrap().contains("unprivileged_userns_clone"));
    }
}
