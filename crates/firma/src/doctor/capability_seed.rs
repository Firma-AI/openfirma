//! Check 6: capability seed presence.

use std::path::Path;

use crate::doctor::report::Check;

/// Check whether `<state_dir>/capabilities/` exists and is non-empty.
///
/// - Non-empty directory → `OK` with file count.
/// - Empty directory → `WARN`.
/// - Missing directory → `WARN`.
/// - I/O error during read → `FAIL`.
#[must_use]
pub fn check(state_dir: &Path) -> Check {
    let dir = state_dir.join("capabilities");
    let display = dir.display().to_string();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            let files: Vec<_> = entries.filter_map(Result::ok).collect();
            if files.is_empty() {
                Check::warn("capability seed", format!("{display}: empty"))
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Check::warn(
            "capability seed",
            format!("{display}: directory does not exist"),
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
    fn warn_when_directory_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let c = check(tmp.path());
        assert_eq!(c.status, Status::Warn);
        assert!(c.reason.contains("does not exist"));
    }

    #[test]
    fn warn_when_directory_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("capabilities")).expect("mkdir");
        let c = check(tmp.path());
        assert_eq!(c.status, Status::Warn);
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
