//! Config-file discovery: fixed precedence, first existing file wins.

use std::path::{Path, PathBuf};

use crate::provider::DirProvider;

/// Where the resolved config came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// Explicit `--config` flag.
    Flag,
    /// `$FIRMA_CONFIG` env var pointing directly to the file.
    EnvVar,
    /// Project-local `.firma/firma.toml` found by walking up from cwd.
    ProjectLocal,
}

/// Resolved config location plus the dir to re-base defaults against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// The `firma.toml` that won.
    pub config_file: PathBuf,
    /// Its parent — base for unset resource paths.
    pub config_dir: PathBuf,
    /// Provenance, for startup logs.
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

use crate::CONFIG_FILE_NAME as FILE_NAME;

fn dir_of(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Resolve the config file for `subcommand`.
///
/// Priority:
/// 1. `cli_override` (`--config` flag) — always wins.
/// 2. `$FIRMA_CONFIG` env var — direct path to the config file.
/// 3. Walk up from cwd looking for `.firma/firma.toml`.
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
        return Ok(ResolvedConfig {
            config_file: path.to_path_buf(),
            config_dir: dir_of(path),
            source: ConfigSource::Flag,
        });
    }

    if let Some(env_path) = provider.env_config_file() {
        return Ok(ResolvedConfig {
            config_dir: dir_of(&env_path),
            config_file: env_path,
            source: ConfigSource::EnvVar,
        });
    }

    let mut searched: Vec<PathBuf> = Vec::new();
    if let Some(cwd) = provider.cwd() {
        for dir in cwd.ancestors() {
            let candidate = dir.join(".firma").join(FILE_NAME);
            if candidate.is_file() {
                return Ok(ResolvedConfig {
                    config_dir: dir_of(&candidate),
                    config_file: candidate,
                    source: ConfigSource::ProjectLocal,
                });
            }
            searched.push(candidate);
        }
    }

    Err(ConfigResolveError::NotFound {
        subcommand: subcommand.to_string(),
        searched,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

    fn empty() -> Fake {
        Fake {
            env: None,
            cwd: None,
        }
    }

    fn touch_project_local(dir: &Path) -> PathBuf {
        let d = dir.join(".firma");
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
    fn env_var_beats_project_local() {
        let tmp = tempdir().unwrap();
        let env_file = tmp.path().join("env.toml");
        std::fs::write(&env_file, "").unwrap();
        let cwd = tmp.path().join("project");
        std::fs::create_dir_all(&cwd).unwrap();
        touch_project_local(&cwd);
        let f = Fake {
            env: Some(env_file.clone()),
            cwd: Some(cwd),
        };
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::EnvVar);
        assert_eq!(r.config_file, env_file);
    }

    #[test]
    fn project_local_found_in_cwd() {
        let tmp = tempdir().unwrap();
        let project_file = touch_project_local(tmp.path());
        let f = Fake {
            env: None,
            cwd: Some(tmp.path().to_path_buf()),
        };
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
        let project_file = touch_project_local(&project);
        let f = Fake {
            env: None,
            cwd: Some(nested),
        };
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::ProjectLocal);
        assert_eq!(r.config_file, project_file);
    }

    #[test]
    fn project_local_closest_ancestor_wins() {
        let tmp = tempdir().unwrap();
        let project = tmp.path().join("project");
        let nested = project.join("sub").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        touch_project_local(&project);
        let nested_file = touch_project_local(project.join("sub").as_path());
        let f = Fake {
            env: None,
            cwd: Some(nested),
        };
        let r = resolve_config("sidecar", None, &f).unwrap();
        assert_eq!(r.source, ConfigSource::ProjectLocal);
        assert_eq!(r.config_file, nested_file);
    }

    #[test]
    fn nothing_found_lists_searched_paths() {
        let tmp = tempdir().unwrap();
        let cwd = tmp.path().join("project");
        std::fs::create_dir_all(&cwd).unwrap();
        let f = Fake {
            env: None,
            cwd: Some(cwd.clone()),
        };
        let err = resolve_config("sidecar", None, &f).unwrap_err();
        let ConfigResolveError::NotFound {
            subcommand,
            searched,
        } = err;
        assert_eq!(subcommand, "sidecar");
        assert!(searched.iter().any(|p| p.starts_with(&cwd)));
    }

    #[test]
    fn nothing_found_when_cwd_none() {
        let err = resolve_config("sidecar", None, &empty()).unwrap_err();
        let ConfigResolveError::NotFound { searched, .. } = err;
        assert!(searched.is_empty());
    }
}
