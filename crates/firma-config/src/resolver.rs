//! Config-file discovery: fixed precedence, first selected file wins.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use fs_err as fs;

use crate::FirmaConfig;

/// Config discovery inputs backed by the real process environment.
#[derive(Debug, Default, Clone)]
pub struct SystemDirs {
    walk_ceiling: Option<PathBuf>,
}

impl SystemDirs {
    /// Create a provider backed by the real process environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the inclusive directory where project-local walk-up stops.
    #[must_use]
    pub fn walk_up_to(mut self, ceiling: impl Into<PathBuf>) -> Self {
        self.walk_ceiling = Some(ceiling.into());
        self
    }

    /// `$FIRMA_CONFIG` if set — direct path to the config file.
    fn env_config_file() -> Option<PathBuf> {
        std::env::var_os("FIRMA_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
}

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
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Provenance, for startup logs.
    pub source: ConfigSource,
    /// Config content loaded during resolution.
    pub config: FirmaConfig,
}

impl ResolvedConfig {
    fn new(source: ConfigSource, config: FirmaConfig) -> Self {
        Self { source, config }
    }

    /// The `firma.toml` that won.
    #[must_use]
    pub fn config_file(&self) -> &Path {
        self.config.origin()
    }

    /// The resolved config file's parent, used to re-base unset resource paths.
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.config_file()
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }
}

/// Resolution failure. Fail-closed; a selected config could not be loaded.
#[derive(Debug, thiserror::Error)]
#[error("failed to load `{path}` from {config_source:?}: {reason:#}")]
pub struct ConfigResolveError {
    pub config_source: ConfigSource,
    pub path: PathBuf,
    pub reason: anyhow::Error,
}

use crate::CONFIG_FILE_NAME as FILE_NAME;

fn load_path(path: &Path, source: ConfigSource) -> Result<ResolvedConfig, ConfigResolveError> {
    FirmaConfig::load(path)
        .map(|config| ResolvedConfig::new(source, config))
        .map_err(|reason| ConfigResolveError {
            config_source: source,
            path: path.to_path_buf(),
            reason,
        })
}

impl SystemDirs {
    /// Resolve and load the config file.
    ///
    /// Priority:
    /// 1. `cli_override` (`--config` flag) — always wins.
    /// 2. `$FIRMA_CONFIG` env var — direct path to the config file.
    /// 3. Walk up from cwd looking for `.firma/firma.toml`.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` when no file exists in any discovery tier. Returns
    /// [`ConfigResolveError`] when a selected file cannot be read or parsed.
    pub fn resolve_config(
        &self,
        cli_override: Option<&Path>,
    ) -> Result<Option<ResolvedConfig>, ConfigResolveError> {
        if let Some(path) = cli_override {
            return load_path(path, ConfigSource::Flag).map(Some);
        }

        if let Some(env_path) = Self::env_config_file() {
            return load_path(&env_path, ConfigSource::EnvVar).map(Some);
        }

        'walk_up: {
            let Some(cwd) = std::env::current_dir().ok() else {
                break 'walk_up;
            };
            let walk_ceiling = self.walk_ceiling.as_deref();
            if walk_ceiling.is_some_and(|ceiling| !cwd.starts_with(ceiling)) {
                break 'walk_up;
            }
            for dir in cwd.ancestors() {
                let candidate = dir.join(".firma").join(FILE_NAME);
                match fs::read_to_string(&candidate) {
                    Ok(text) => {
                        let config = FirmaConfig::parse(&candidate, &text).map_err(|reason| {
                            ConfigResolveError {
                                config_source: ConfigSource::ProjectLocal,
                                path: candidate.clone(),
                                reason,
                            }
                        })?;
                        return Ok(Some(ResolvedConfig::new(
                            ConfigSource::ProjectLocal,
                            config,
                        )));
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(ConfigResolveError {
                            config_source: ConfigSource::ProjectLocal,
                            path: candidate,
                            reason: error.into(),
                        });
                    }
                }
                if walk_ceiling.is_some_and(|ceiling| dir == ceiling) {
                    break;
                }
            }
        }

        Ok(None)
    }
}
