//! Config-file discovery: fixed precedence, first existing file wins.

use std::path::{Path, PathBuf};

use crate::provider::DirProvider;

/// Where the resolved config came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// Explicit `--config` flag — overrides discovery (same sectioned schema).
    Flag,
    /// Project-local `.firma/firma.toml` found by walking up from cwd
    /// (per CLI spec §4 step 1).
    ProjectLocal,
    /// `$FIRMA_CONFIG_DIR`.
    EnvDir,
    /// A platform user config dir.
    UserConfig,
    /// A system-wide config dir.
    SystemConfig,
    /// CWD-relative `firma.toml` (back-compat last fallback).
    CwdFallback,
}

/// Resolved config location plus the dir to re-base defaults against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// The `firma.toml` that won.
    pub config_file: PathBuf,
    /// Its parent — base for unset resource paths.
    pub config_dir: PathBuf,
    /// Provenance, for startup logs and schema selection.
    pub source: ConfigSource,
}

/// Resolution failure. Fail-closed; lists every directory searched.
#[derive(Debug, thiserror::Error)]
pub enum ConfigResolveError {
    #[error(
        "no firma.toml found for `{subcommand}`; searched:\n{}",
        searched.iter().map(|p| format!("  - {}", p.display()))
            .collect::<Vec<_>>().join("\n")
    )]
    NotFound {
        subcommand: String,
        searched: Vec<PathBuf>,
    },
}

use crate::{CONFIG_FILE_NAME as FILE_NAME, CONFIG_SUBDIR as SUBDIR};

/// Ordered config-file candidates (excluding the explicit flag), each
/// the directory's `firma.toml`. `nested` joins `SUBDIR` first; the
/// self-complete `dot`/`env` tiers do not.
fn candidates(p: &dyn DirProvider) -> Vec<(PathBuf, ConfigSource)> {
    let nested = |d: PathBuf| d.join(SUBDIR).join(FILE_NAME);
    let flat = |d: PathBuf| d.join(FILE_NAME);
    let mut out: Vec<(PathBuf, ConfigSource)> = Vec::new();
    // Project-local tier (highest priority, per CLI spec §4 step 1):
    // walk up from cwd looking for `.firma/firma.toml`. Stops at the
    // filesystem root. Each ancestor contributes one candidate.
    if let Some(cwd) = p.cwd() {
        let mut dir: Option<&Path> = Some(cwd.as_path());
        while let Some(d) = dir {
            out.push((d.join(".firma").join(FILE_NAME), ConfigSource::ProjectLocal));
            dir = d.parent();
        }
    }
    out.extend(p.env_config_dir().map(|d| (flat(d), ConfigSource::EnvDir)));
    out.extend(
        p.xdg_config_home()
            .map(|d| (nested(d), ConfigSource::UserConfig)),
    );
    // Self-complete (already includes the `firma` dir / `.firma`).
    out.extend(
        p.dot_config_dir()
            .map(|d| (flat(d), ConfigSource::UserConfig)),
    );
    out.extend(
        p.platform_config_dir()
            .map(|d| (nested(d), ConfigSource::UserConfig)),
    );
    out.extend(
        p.system_config_dirs()
            .into_iter()
            .map(|d| (nested(d), ConfigSource::SystemConfig)),
    );
    out.extend(p.cwd().map(|d| (flat(d), ConfigSource::CwdFallback)));
    out
}

/// Resolve the config file for `subcommand`. `cli_override` always wins.
///
/// # Errors
///
/// Returns [`ConfigResolveError::NotFound`] (listing every searched path)
/// when no file exists in any tier.
pub fn resolve_config(
    subcommand: &str,
    cli_override: Option<&Path>,
    provider: &dyn DirProvider,
) -> Result<ResolvedConfig, ConfigResolveError> {
    if let Some(path) = cli_override {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        return Ok(ResolvedConfig {
            config_file: path.to_path_buf(),
            config_dir: dir,
            source: ConfigSource::Flag,
        });
    }
    // Short-circuit on the first existing file; `searched` is only
    // materialized to feed the fail-closed `NotFound` error.
    let mut searched: Vec<PathBuf> = Vec::new();
    for (file, source) in candidates(provider) {
        if searched.contains(&file) {
            continue; // dedupe overlapping tiers (e.g. Linux dot/platform)
        }
        if file.is_file() {
            let dir = file
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            return Ok(ResolvedConfig {
                config_file: file,
                config_dir: dir,
                source,
            });
        }
        searched.push(file);
    }
    Err(ConfigResolveError::NotFound {
        subcommand: subcommand.to_string(),
        searched,
    })
}

/// The canonical directory to create config in when none is discovered.
///
/// Resolution order: `$FIRMA_CONFIG_DIR` → `$XDG_CONFIG_HOME/firma` →
/// home-convention dir (Unix `~/.config/firma`, Windows
/// `%USERPROFILE%\.firma`) → platform config dir + `/firma`. `None` only
/// if no home/config dir is resolvable on this platform.
#[must_use]
pub fn default_config_dir(provider: &dyn DirProvider) -> Option<PathBuf> {
    if let Some(d) = provider.env_config_dir() {
        return Some(d);
    }
    if let Some(d) = provider.xdg_config_home() {
        return Some(d.join(SUBDIR));
    }
    if let Some(d) = provider.dot_config_dir() {
        // Self-complete (already the final `firma`/`.firma` dir).
        return Some(d);
    }
    provider.platform_config_dir().map(|d| d.join(SUBDIR))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::tempdir;

    struct Fake {
        env: Option<PathBuf>,
        xdg: Option<PathBuf>,
        dot: Option<PathBuf>,
        platform: Option<PathBuf>,
        system: Vec<PathBuf>,
        cwd: Option<PathBuf>,
    }
    impl DirProvider for Fake {
        fn env_config_dir(&self) -> Option<PathBuf> {
            self.env.clone()
        }
        fn xdg_config_home(&self) -> Option<PathBuf> {
            self.xdg.clone()
        }
        fn dot_config_dir(&self) -> Option<PathBuf> {
            self.dot.clone()
        }
        fn platform_config_dir(&self) -> Option<PathBuf> {
            self.platform.clone()
        }
        fn system_config_dirs(&self) -> Vec<PathBuf> {
            self.system.clone()
        }
        fn cwd(&self) -> Option<PathBuf> {
            self.cwd.clone()
        }
    }

    fn empty() -> Fake {
        Fake {
            env: None,
            xdg: None,
            dot: None,
            platform: None,
            system: Vec::new(),
            cwd: None,
        }
    }

    fn touch(dir: &Path, sub: bool) -> PathBuf {
        let d = if sub {
            dir.join(SUBDIR)
        } else {
            dir.to_path_buf()
        };
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join(FILE_NAME);
        std::fs::write(&f, "").unwrap();
        f
    }

    #[test]
    fn flag_wins_over_everything() {
        let tmp = tempdir().unwrap();
        let flag = tmp.path().join("explicit.toml");
        std::fs::write(&flag, "").unwrap();
        let r = resolve_config("sidecar", Some(&flag), &empty()).unwrap();
        assert_eq!(r.source, ConfigSource::Flag);
        assert_eq!(r.config_file, flag);
        assert_eq!(r.config_dir, tmp.path());
    }

    #[test]
    fn project_local_beats_env_dir() {
        let tmp = tempdir().unwrap();
        let cwd = tmp.path().join("project");
        std::fs::create_dir_all(&cwd).unwrap();
        let project_file = touch(&cwd.join(".firma"), false);
        let env = tmp.path().join("env");
        touch(&env, false);
        let mut f = empty();
        f.cwd = Some(cwd);
        f.env = Some(env);
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::ProjectLocal);
        assert_eq!(r.config_file, project_file);
    }

    #[test]
    fn project_local_walks_up_to_ancestor() {
        let tmp = tempdir().unwrap();
        let project = tmp.path().join("project");
        let nested = project.join("sub").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        let project_file = touch(&project.join(".firma"), false);
        let mut f = empty();
        f.cwd = Some(nested);
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::ProjectLocal);
        assert_eq!(r.config_file, project_file);
    }

    #[test]
    fn env_dir_beats_user_dir() {
        let tmp = tempdir().unwrap();
        let env = tmp.path().join("env");
        let dot = tmp.path().join("dot");
        let env_file = touch(&env, false);
        touch(&dot, true);
        let mut f = empty();
        f.env = Some(env);
        f.dot = Some(dot);
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::EnvDir);
        assert_eq!(r.config_file, env_file);
    }

    #[test]
    fn system_tier_when_user_absent() {
        let tmp = tempdir().unwrap();
        let sys = tmp.path().join("etc");
        let sys_file = touch(&sys, true);
        let mut f = empty();
        f.system = vec![sys];
        let r = resolve_config("authority", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::SystemConfig);
        assert_eq!(r.config_file, sys_file);
    }

    #[test]
    fn cwd_legacy_last() {
        let tmp = tempdir().unwrap();
        let f_path = touch(tmp.path(), false);
        let mut f = empty();
        f.cwd = Some(tmp.path().to_path_buf());
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::CwdFallback);
        assert_eq!(r.config_file, f_path);
    }

    #[test]
    fn nothing_found_lists_dirs() {
        let tmp = tempdir().unwrap();
        let mut f = empty();
        f.dot = Some(tmp.path().join("dot"));
        f.system = vec![tmp.path().join("etc")];
        let err = resolve_config("sidecar", None, &f).unwrap_err();
        let ConfigResolveError::NotFound {
            subcommand,
            searched,
        } = err;
        assert_eq!(subcommand, "sidecar");
        let set: HashSet<_> = searched.iter().collect();
        // dot tier is self-complete: no `SUBDIR` appended.
        assert!(set.contains(&tmp.path().join("dot").join(FILE_NAME)));
    }

    #[test]
    fn dedupes_dot_and_platform_on_linux() {
        // Linux: real dot tier is `~/.config/firma` (self-complete);
        // platform base is `~/.config`, which gets `SUBDIR` appended →
        // also `~/.config/firma/firma.toml`. They must collapse to one.
        let tmp = tempdir().unwrap();
        let xdg_base = tmp.path().join(".config");
        let mut f = empty();
        f.dot = Some(xdg_base.join(SUBDIR));
        f.platform = Some(xdg_base);
        let err = resolve_config("run", None, &f).unwrap_err();
        let ConfigResolveError::NotFound { searched, .. } = err;
        let count = searched
            .iter()
            .filter(|p| p.ends_with(format!("{SUBDIR}/{FILE_NAME}")))
            .count();
        assert_eq!(count, 1, "dot/platform must dedupe");
    }

    #[test]
    fn default_config_dir_prefers_env_then_xdg() {
        let mut f = empty();
        f.xdg = Some(PathBuf::from("/xdg"));
        f.dot = Some(PathBuf::from("/home/.config"));
        assert_eq!(
            default_config_dir(&f),
            Some(PathBuf::from("/xdg").join(SUBDIR))
        );
        f.env = Some(PathBuf::from("/envcfg"));
        assert_eq!(default_config_dir(&f), Some(PathBuf::from("/envcfg")));
    }

    #[test]
    fn default_config_dir_uses_dot_tier_verbatim() {
        // dot tier is self-complete: returned as-is, no `SUBDIR` join.
        let mut f = empty();
        f.dot = Some(PathBuf::from("/home/user/.firma"));
        assert_eq!(
            default_config_dir(&f),
            Some(PathBuf::from("/home/user/.firma"))
        );
    }
}
