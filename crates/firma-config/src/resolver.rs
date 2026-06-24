//! Config-file discovery: fixed precedence, first selected file wins.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use fs_err as fs;

use crate::{CONFIG_ENV_NAME, FirmaConfig};

/// A helper to determine which configuration should be applied to the
/// `firma` command that's about to execute.
///
/// Refer to [`ConfigResolver::resolve_config`] for more details.
#[derive(Debug, Default, Clone)]
pub struct ConfigResolver {
    #[cfg(feature = "test-utils")]
    walk_ceiling: Option<PathBuf>,
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
    #[source]
    pub reason: anyhow::Error,
}

use crate::CONFIG_FILE_NAME as FILE_NAME;

impl ConfigResolver {
    /// Create a new [`ConfigResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an upper bound for walk-up resolution.
    ///
    /// The upper bound is _inclusive_—i.e. if `ceiling` contains
    /// a configuration file, it'll be used if appropriate.
    ///
    /// # Implementation details
    ///
    /// This method is used in end-to-end tests.
    /// Each test spawns a dedicated process with its current directory
    /// set to a freshly-created temporary directory.
    /// We use that temporary directory as the ceiling for our search
    /// to reduce the risk of test flakiness: e.g. there might be a
    /// valid Firma configuration file above the temporary directory
    /// folder, and we don't want tests to pick it up.
    #[must_use]
    #[cfg(feature = "test-utils")]
    pub fn walk_up_to(mut self, ceiling: impl Into<PathBuf>) -> Self {
        self.walk_ceiling = Some(ceiling.into());
        self
    }

    /// The path to a configuration file specified via the canonical environment
    /// variable.
    ///
    /// We treat the environment variable as unset if empty.
    fn env_config_file() -> Option<PathBuf> {
        std::env::var_os(CONFIG_ENV_NAME)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }

    /// Resolve and load the config file.
    ///
    /// We check these sources, in priority order:
    /// 1. `cli_override` (`--config` flag).
    /// 2. Environment variable ([`CONFIG_ENV_NAME`]).
    /// 3. Filesystem, using the closest configuration file to the current working directory.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` when no file exists in any discovery tier.
    /// Returns [`ConfigResolveError`] when a selected file cannot be read or parsed.
    pub fn resolve_config(
        &self,
        cli_override: Option<&Path>,
    ) -> Result<Option<ResolvedConfig>, ConfigResolveError> {
        fn load_path(
            path: &Path,
            source: ConfigSource,
        ) -> Result<ResolvedConfig, ConfigResolveError> {
            FirmaConfig::load(path)
                .map(|config| ResolvedConfig::new(source, config))
                .map_err(|reason| ConfigResolveError {
                    config_source: source,
                    path: path.to_path_buf(),
                    reason,
                })
        }

        if let Some(path) = cli_override {
            return load_path(path, ConfigSource::Flag).map(Some);
        }

        if let Some(env_path) = Self::env_config_file() {
            return load_path(&env_path, ConfigSource::EnvVar).map(Some);
        }

        'walk_up: {
            let cwd = std::env::current_dir().map_err(|e| ConfigResolveError {
                config_source: ConfigSource::ProjectLocal,
                path: PathBuf::default(),
                reason: e.into(),
            })?;

            #[cfg(feature = "test-utils")]
            let walk_ceiling = {
                let walk_ceiling = self.walk_ceiling.as_deref();
                if walk_ceiling.is_some_and(|ceiling| !cwd.starts_with(ceiling)) {
                    break 'walk_up;
                }
                walk_ceiling
            };

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
                #[cfg(feature = "test-utils")]
                if walk_ceiling.is_some_and(|ceiling| dir == ceiling) {
                    break;
                }
            }
        }

        Ok(None)
    }
}
