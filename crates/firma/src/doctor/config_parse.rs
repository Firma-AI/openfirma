//! Check 5: locate and parse `firma-stack.toml`.

use std::path::{Path, PathBuf};

use crate::doctor::report::Check;

/// Walk up from `start` looking for `firma-stack.toml`. Stops at root.
#[must_use]
pub fn find_stack_config(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join("firma-stack.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

/// Run the check with an optional explicit path override (`--config`).
#[must_use]
pub fn check(explicit: Option<&Path>, cwd: &Path) -> Check {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => find_stack_config(cwd),
    };
    let Some(path) = path else {
        return Check::warn(
            "config parsed",
            "no firma-stack.toml found (walked up from cwd)",
        );
    };
    let display = path.display().to_string();
    match firma_stack::load_stack_config(&path) {
        Ok(_cfg) => Check::ok("config parsed", display.clone()).with_detail("path", display),
        Err(error) => {
            Check::fail("config parsed", format!("{display}: {error}")).with_detail("path", display)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::Status;

    #[test]
    fn find_returns_none_when_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(find_stack_config(tmp.path()).is_none());
    }

    #[test]
    fn find_locates_file_in_ancestor() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let cfg_path = tmp.path().join("firma-stack.toml");
        std::fs::write(&cfg_path, "").expect("touch");
        let found = find_stack_config(&nested).expect("found");
        assert_eq!(found, cfg_path);
    }

    #[test]
    fn check_warn_when_no_config_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let c = check(None, tmp.path());
        assert_eq!(c.status, Status::Warn);
        assert!(c.reason.contains("no firma-stack.toml"));
    }

    #[test]
    fn check_fail_when_config_invalid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = tmp.path().join("firma-stack.toml");
        std::fs::write(&cfg_path, "@@not toml@@").expect("write bad toml");
        let c = check(Some(&cfg_path), tmp.path());
        assert_eq!(c.status, Status::Fail);
    }

    #[test]
    fn check_ok_when_config_parses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = tmp.path().join("firma-stack.toml");
        let authority = tmp.path().join("authority.toml");
        let sidecar = tmp.path().join("sidecar.toml");
        std::fs::write(
            &authority,
            "listen_addr = \"127.0.0.1:0\"\nkey_file = \"k\"\n",
        )
        .expect("authority.toml");
        std::fs::write(&sidecar, "").expect("sidecar.toml");
        let body = format!(
            "state_dir = '{state}'\nauthority_config = '{a}'\nsidecar_config = '{s}'\n",
            state = tmp.path().display(),
            a = authority.display(),
            s = sidecar.display(),
        );
        std::fs::write(&cfg_path, body).expect("stack.toml");
        let c = check(Some(&cfg_path), tmp.path());
        assert_eq!(c.status, Status::Ok, "got {c:?}");
    }
}
