//! Check 1: `firma` binary discovery + version.

use std::path::PathBuf;

use crate::doctor::report::Check;

/// Inspect the path of the running `firma` binary and its version.
///
/// Always `Ok`: this can only fail if `current_exe()` itself fails, which
/// is essentially impossible on Unix and very rare on Windows. We report
/// `Fail` in that pathological case.
#[must_use]
pub fn check(current_exe: std::io::Result<PathBuf>, version: &str) -> Check {
    match current_exe {
        Ok(path) => {
            let display = path.display().to_string();
            Check::ok("firma binary", format!("{display} (v{version})"))
                .with_detail("path", display)
                .with_detail("version", version)
        }
        Err(error) => Check::fail("firma binary", format!("current_exe failed: {error}")),
    }
}

/// Public entry point used by the orchestrator.
#[must_use]
pub fn run() -> Check {
    check(std::env::current_exe(), env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::path::Path;

    use super::*;
    use crate::doctor::report::Status;

    #[test]
    fn reports_ok_with_path_and_version() {
        let c = check(Ok(Path::new("/usr/local/bin/firma").to_path_buf()), "0.1.0");
        assert_eq!(c.status, Status::Ok);
        assert_eq!(c.reason, "/usr/local/bin/firma (v0.1.0)");
        assert_eq!(
            c.detail.get("path").map(String::as_str),
            Some("/usr/local/bin/firma")
        );
        assert_eq!(c.detail.get("version").map(String::as_str), Some("0.1.0"));
    }

    #[test]
    fn reports_fail_when_current_exe_errors() {
        let err = Error::new(ErrorKind::PermissionDenied, "denied");
        let c = check(Err(err), "0.1.0");
        assert_eq!(c.status, Status::Fail);
        assert!(c.reason.contains("current_exe failed"));
    }
}
