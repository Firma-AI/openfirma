//! Best-effort removal of the per-session capability seed file on drop.
//!
//! Mirrors the kill-on-Drop discipline used by `SidecarSupervisor` (FIR-102):
//! the seed lives at `$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`
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
        // Honor the same keep-markers escape hatch as the sidecar supervisor.
        if std::env::var("FIRMA_RUN_KEEP_MARKERS").is_ok() {
            return;
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
