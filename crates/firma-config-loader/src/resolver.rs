//! Config-file discovery: fixed precedence, first selected file wins.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use fs_err as fs;

use crate::{CONFIG_DIR_NAME, CONFIG_ENV_NAME, CONFIG_FILE_NAME, FirmaConfig};

/// A candidate `.firma/` location produced while walking up the directory tree.
///
/// Yielded nearest-first by [`FirmaConfigCandidateAncestors`]. Discovery reads
/// [`config_file`](Self::config_file) to find the winning config; the sandbox
/// backend masks [`config_dir`](Self::config_dir) so an agent cannot read or
/// poison it. Paths are constructed by joining, not stat'd — callers decide
/// whether each candidate exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmaConfigCandidate {
    /// The `.firma/` directory for this ancestor (`<dir>/.firma`).
    pub config_dir: PathBuf,
}

impl FirmaConfigCandidate {
    /// The `firma.toml` candidate inside this `.firma/` directory
    /// (`<dir>/.firma/firma.toml`), at its canonical fixed name.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE_NAME)
    }
}

/// Iterator over ancestor `.firma/` candidates, nearest-first.
///
/// Built via [`FirmaConfigCandidateAncestors::new`]. An optional inclusive ceiling stops
/// iteration after the ceiling directory, and yields nothing when the start path
/// is not within the ceiling.
#[derive(Debug, Clone)]
pub struct FirmaConfigCandidateAncestors<'a> {
    ancestors: std::path::Ancestors<'a>,
    ceiling: Option<&'a Path>,
    done: bool,
}

impl<'a> FirmaConfigCandidateAncestors<'a> {
    /// Walk up from `start`, yielding each ancestor's `.firma/` candidate
    /// nearest-first.
    ///
    /// Shared by config discovery ([`ConfigResolver::resolve_config`], which
    /// reads the first existing `firma.toml`) and the Linux sandbox mask (which
    /// hides every candidate directory). Centralizing the walk keeps both in
    /// lockstep: the mask covers exactly the set discovery can select.
    ///
    /// When `ceiling` is `Some`, the walk is bounded to that directory
    /// (inclusive), and yields nothing when `start` is not within it. Pass
    /// `None` for an unbounded walk to the filesystem root.
    #[must_use]
    pub fn new(start: &'a Path, ceiling: Option<&'a Path>) -> Self {
        let out_of_bounds = ceiling.is_some_and(|ceiling| !start.starts_with(ceiling));
        Self {
            ancestors: start.ancestors(),
            ceiling,
            done: out_of_bounds,
        }
    }
}

impl Iterator for FirmaConfigCandidateAncestors<'_> {
    type Item = FirmaConfigCandidate;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let dir = self.ancestors.next()?;
        // Stop after (inclusive) the ceiling so it is still a candidate.
        if self.ceiling.is_some_and(|ceiling| dir == ceiling) {
            self.done = true;
        }
        let config_dir = dir.join(CONFIG_DIR_NAME);
        Some(FirmaConfigCandidate { config_dir })
    }
}

/// A helper to determine which configuration should be applied to the
/// `firma` command that's about to execute.
///
/// Refer to [`ConfigResolver::resolve_config`] for more details.
#[derive(Debug, Clone, Default)]
pub struct ConfigResolver {
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
    reason: anyhow::Error,
}

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
    /// Callers can use this to prevent discovery from escaping an explicit
    /// workspace root.
    #[must_use]
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
            let path = std::path::absolute(path).map_err(|reason| ConfigResolveError {
                config_source: source,
                path: path.to_path_buf(),
                reason: reason.into(),
            })?;
            FirmaConfig::load(&path)
                .map(|config| ResolvedConfig::new(source, config))
                .map_err(|reason| ConfigResolveError {
                    config_source: source,
                    path,
                    reason,
                })
        }

        if let Some(path) = cli_override {
            return load_path(path, ConfigSource::Flag).map(Some);
        }

        if let Some(env_path) = Self::env_config_file() {
            return load_path(&env_path, ConfigSource::EnvVar).map(Some);
        }

        let cwd = std::env::current_dir().map_err(|e| ConfigResolveError {
            config_source: ConfigSource::ProjectLocal,
            path: PathBuf::default(),
            reason: e.into(),
        })?;
        for candidate in FirmaConfigCandidateAncestors::new(&cwd, self.walk_ceiling.as_deref()) {
            let candidate = candidate.config_file();
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
        }

        Ok(None)
    }
}
