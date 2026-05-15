//! Directory sources for config discovery.
//!
//! The trait is injected so resolution is unit-testable without
//! mutating the real environment or `$HOME`.

use std::path::PathBuf;

/// Supplies the candidate config directories, one method per tier.
pub trait DirProvider {
    /// `$FIRMA_CONFIG_DIR` if set.
    fn env_config_dir(&self) -> Option<PathBuf>;
    /// `$XDG_CONFIG_HOME` if set (all platforms honor it).
    fn xdg_config_home(&self) -> Option<PathBuf>;
    /// The home-convention `firma` config dir, platform-shaped and
    /// self-complete (no `firma` subdir is appended by callers):
    /// Unix `~/.config/firma`; Windows `%USERPROFILE%\.firma` (bare
    /// home dotdir, matching agent CLIs like `.claude`/`.codex`;
    /// `%APPDATA%` is reserved for the platform tier).
    fn dot_config_dir(&self) -> Option<PathBuf>;
    /// Platform default from `dirs::config_dir()` (macOS Library,
    /// Windows `%APPDATA%`; Linux duplicates `~/.config` and is deduped).
    fn platform_config_dir(&self) -> Option<PathBuf>;
    /// System-wide config dirs, highest priority first.
    fn system_config_dirs(&self) -> Vec<PathBuf>;
    /// Current working directory (legacy back-compat tier).
    fn cwd(&self) -> Option<PathBuf>;
}

/// Production [`DirProvider`] backed by the real environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDirs;

impl DirProvider for SystemDirs {
    fn env_config_dir(&self) -> Option<PathBuf> {
        std::env::var_os("FIRMA_CONFIG_DIR").map(PathBuf::from)
    }

    fn xdg_config_home(&self) -> Option<PathBuf> {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }

    fn dot_config_dir(&self) -> Option<PathBuf> {
        // Self-complete, platform-shaped home-convention dir.
        //  - Unix: ~/.config/firma (XDG-style dotdir).
        //  - Windows: %USERPROFILE%\.firma — bare home dotdir, matching
        //    agent/dev CLIs (.claude/.codex/.aws/.cargo). %APPDATA% is
        //    left to the platform tier.
        #[cfg(windows)]
        {
            dirs::home_dir().map(|h| h.join(".firma"))
        }
        #[cfg(not(windows))]
        {
            dirs::home_dir().map(|h| h.join(".config").join("firma"))
        }
    }

    fn platform_config_dir(&self) -> Option<PathBuf> {
        dirs::config_dir()
    }

    fn system_config_dirs(&self) -> Vec<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            vec![PathBuf::from("/etc")]
        }
        #[cfg(target_os = "macos")]
        {
            vec![PathBuf::from("/Library/Application Support")]
        }
        #[cfg(target_os = "windows")]
        {
            std::env::var_os("PROGRAMDATA")
                .map(PathBuf::from)
                .into_iter()
                .collect()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Vec::new()
        }
    }

    fn cwd(&self) -> Option<PathBuf> {
        std::env::current_dir().ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fake;
    impl DirProvider for Fake {
        fn env_config_dir(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/env"))
        }
        fn xdg_config_home(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/xdg"))
        }
        fn dot_config_dir(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/home/.config"))
        }
        fn platform_config_dir(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/Library/Application Support"))
        }
        fn system_config_dirs(&self) -> Vec<PathBuf> {
            vec![PathBuf::from("/etc")]
        }
        fn cwd(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/cwd"))
        }
    }

    #[test]
    fn fake_provider_exposes_all_tiers() {
        let f = Fake;
        assert_eq!(f.env_config_dir(), Some(PathBuf::from("/env")));
        assert_eq!(f.xdg_config_home(), Some(PathBuf::from("/xdg")));
        assert_eq!(f.dot_config_dir(), Some(PathBuf::from("/home/.config")));
        assert_eq!(f.system_config_dirs(), vec![PathBuf::from("/etc")]);
    }

    #[cfg(windows)]
    #[test]
    fn system_dot_config_dir_is_bare_dotfirma_on_windows() {
        // Windows uses the bare home dotdir `%USERPROFILE%\.firma`,
        // not `%APPDATA%` and not `.config\firma`.
        if let Some(home) = dirs::home_dir() {
            assert_eq!(SystemDirs.dot_config_dir(), Some(home.join(".firma")));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn system_dot_config_dir_is_home_dot_config_firma_on_unix() {
        // Unix: self-complete `~/.config/firma`.
        if let Some(home) = dirs::home_dir() {
            assert_eq!(
                SystemDirs.dot_config_dir(),
                Some(home.join(".config").join("firma"))
            );
        }
    }
}
