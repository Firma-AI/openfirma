//! Best-effort removal of the per-session capability seed file on drop.
//!
//! The seed lives at `$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`
//! and must not outlive the run that minted it.

use std::path::{Path, PathBuf};

/// Removes its file when dropped.
#[derive(Debug)]
pub struct CapabilityFileGuard {
    path: PathBuf,
}

impl CapabilityFileGuard {
    /// Guard the given seed file path.
    #[must_use]
    #[cfg(any(unix, test))]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The guarded path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CapabilityFileGuard {
    fn drop(&mut self) {
        // Honor the run marker keep-markers escape hatch.
        if std::env::var_os("FIRMA_RUN_KEEP_MARKERS").is_some() {
            return;
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_test_helpers::process_fixture;

    #[test]
    fn drop_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandbox.toml");
        std::fs::write(&path, "x").unwrap();
        {
            let _guard = CapabilityFileGuard::new(path.clone());
            assert!(path.exists());
        }
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn present_non_unicode_keep_markers_value_retains_file() {
        use std::os::unix::ffi::OsStringExt as _;

        let status = keep_markers_fixture()
            .env(
                "FIRMA_RUN_KEEP_MARKERS",
                std::ffi::OsString::from_vec(vec![0xFF]),
            )
            .status()
            .unwrap();

        assert!(status.success());
    }

    process_fixture! {
        #[cfg(unix)]
        fn keep_markers_fixture() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sandbox.toml");
            std::fs::write(&path, "x").unwrap();
            drop(CapabilityFileGuard::new(path.clone()));

            assert!(path.exists());
        }
    }
}
