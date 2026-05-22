//! Directory sources for config discovery.
//!
//! The trait is injected so resolution is unit-testable without
//! mutating the real environment or the filesystem.

use std::path::PathBuf;

/// Supplies the candidate config locations.
pub trait DirProvider {
    /// `$FIRMA_CONFIG` if set — direct path to the config file.
    fn env_config_file(&self) -> Option<PathBuf>;
    /// Current working directory for the `.firma/firma.toml` walk-up.
    fn cwd(&self) -> Option<PathBuf>;
}

/// Production [`DirProvider`] backed by the real environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDirs;

impl DirProvider for SystemDirs {
    fn env_config_file(&self) -> Option<PathBuf> {
        std::env::var_os("FIRMA_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }

    fn cwd(&self) -> Option<PathBuf> {
        std::env::current_dir().ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    struct Fake {
        env: Option<PathBuf>,
        cwd: Option<PathBuf>,
    }

    impl DirProvider for Fake {
        fn env_config_file(&self) -> Option<PathBuf> {
            self.env.clone()
        }
        fn cwd(&self) -> Option<PathBuf> {
            self.cwd.clone()
        }
    }

    #[test]
    fn fake_provider_exposes_tiers() {
        let f = Fake {
            env: Some(PathBuf::from("/env/firma.toml")),
            cwd: Some(PathBuf::from("/cwd")),
        };
        assert_eq!(f.env_config_file(), Some(PathBuf::from("/env/firma.toml")));
        assert_eq!(f.cwd(), Some(PathBuf::from("/cwd")));
    }
}
