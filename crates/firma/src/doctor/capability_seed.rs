//! Check 6: capability seed presence.

use std::path::Path;

use crate::doctor::report::Check;

/// Check whether `<state_dir>/capabilities/` exists and is non-empty.
///
/// The seed directory is optional: with the default profile capabilities are
/// disabled (`CapabilitySource::Disabled`) so it is never created, and even
/// when enabled it is created on first use. Its absence on a healthy install
/// is therefore expected and must not be alarming.
///
/// - Non-empty directory → `OK` with file count.
/// - Empty directory → `OK` (created/populated on first use).
/// - Missing directory → `OK` (optional; capabilities disabled by default).
/// - I/O error during read → `FAIL`.
#[must_use]
pub fn check(state_dir: &Path) -> Check {
    let dir = firma_runtime_state::RuntimeLayout::from_root(state_dir).capabilities_dir();
    let display = dir.display().to_string();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            let files: Vec<_> = entries.filter_map(Result::ok).collect();
            if files.is_empty() {
                Check::ok(
                    "capability seed",
                    format!("{display}: empty (populated on first use)"),
                )
                .with_detail("path", display)
            } else {
                Check::ok(
                    "capability seed",
                    format!("{display}: {} file(s)", files.len()),
                )
                .with_detail("path", display)
                .with_detail("count", files.len().to_string())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Check::ok(
            "capability seed",
            format!("{display}: not present (optional; capabilities disabled by default)"),
        )
        .with_detail("path", display),
        Err(error) => Check::fail("capability seed", format!("{display}: {error}"))
            .with_detail("path", display),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::Status;

    #[test]
    fn ok_when_directory_missing_because_optional() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let c = check(tmp.path());
        // Absence is expected on a healthy install (capabilities disabled by
        // default; seed created on first use). Must not be alarming.
        assert_eq!(c.status, Status::Ok);
        assert!(c.reason.contains("not present"));
    }

    #[test]
    fn ok_when_directory_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("capabilities")).expect("mkdir");
        let c = check(tmp.path());
        assert_eq!(c.status, Status::Ok);
        assert!(c.reason.contains("empty"));
    }

    #[test]
    fn ok_when_directory_has_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("capabilities");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("a.toml"), "").expect("touch");
        std::fs::write(dir.join("b.toml"), "").expect("touch");
        let c = check(tmp.path());
        assert_eq!(c.status, Status::Ok);
        assert_eq!(c.detail.get("count").map(String::as_str), Some("2"));
    }
}
