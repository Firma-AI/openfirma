//! Config-file discovery: fixed precedence, first selected file wins.
//!
//! The config is a security boundary: it carries enforcement policy, action
//! mappings, allowlists, Authority/Sidecar endpoints and keys, secret
//! providers, sandbox backend selection, and egress/DNS confinement. Whoever
//! controls the selected file controls the guardrails, so discovery must never
//! trust a path an agent or repository can write.
//!
//! Precedence:
//! 1. `--config <path>` — explicit, launcher-controlled escape.
//! 2. `$FIRMA_CONFIG` — explicit, launcher-controlled escape.
//! 3. The [trusted config directory](home_config_dir) — a single,
//!    user-controlled, HOME-rooted location (`~/.firma` on every OS). No
//!    directory-tree walk, no `$XDG_CONFIG_HOME`.
//!
//! There is deliberately no cwd/ancestor walk-up: a nearest-`.firma`-wins scan
//! (borrowed from git/npm/eslint) lets a compromised prompt plant
//! `./.firma/firma.toml` in the workspace or any writable ancestor and weaken
//! its own enforcement. The trust root is a path the user controls, not one the
//! agent/repo controls.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use fs_err as fs;

use crate::{CONFIG_DIR_NAME, CONFIG_ENV_NAME, CONFIG_FILE_NAME, FirmaConfig};

///
/// Fail-closed: when the anchoring environment variable is unset, empty, or
/// relative we refuse to guess a location rather than fall back to an
/// agent-writable path.
#[derive(Debug, thiserror::Error)]
pub enum HomeConfigDirError {
    /// The HOME-anchoring variable (`HOME` on Unix, `USERPROFILE` on Windows)
    /// is unset, empty, or not an absolute path, so no user-controlled
    /// directory can be derived.
    #[error("cannot locate trusted config directory: `{0}` is unset, empty, or not absolute")]
    MissingHome(&'static str),
}

/// The user-controlled trusted config directory: `~/.firma` on every OS.
///
/// | OS      | Trusted config directory  |
/// |---------|---------------------------|
/// | Unix    | `$HOME/.firma`            |
/// | Windows | `%USERPROFILE%\.firma`    |
///
/// A single HOME-rooted directory on all platforms, deliberately **not** the
/// XDG base directory. Firma's config is a security boundary, and like other
/// security-sensitive tools (`~/.ssh`, `~/.aws`, `~/.gnupg`) it lives in one
/// predictable `~/.firma` rather than honoring `$XDG_CONFIG_HOME`. This keeps a
/// single cross-platform mental model and a single directory to reason about
/// (and, later, to mask inside the sandbox).
///
/// This is the discovery trust root: a path the user controls, outside any
/// sandbox-writable mount by construction. Its `firma.toml` is read only when
/// neither `--config` nor `$FIRMA_CONFIG` is set.
///
/// # Errors
///
/// Returns [`HomeConfigDirError::MissingHome`] when the anchoring variable
/// (`HOME` on Unix, `USERPROFILE` on Windows) is unset, empty, or not absolute.
/// We fail closed instead of falling back to a guessable, potentially
/// agent-writable path.
pub fn home_config_dir() -> Result<PathBuf, HomeConfigDirError> {
    #[cfg(unix)]
    let key = "HOME";
    #[cfg(windows)]
    let key = "USERPROFILE";

    std::env::var_os(key)
        // The anchor must be absolute: an empty or relative value would root the
        // trusted dir at the current working directory, reintroducing the exact
        // cwd-dependence (a plantable `./.firma`) this discovery model removes.
        .filter(|value| Path::new(value).is_absolute())
        .map(|home| PathBuf::from(home).join(CONFIG_DIR_NAME))
        .ok_or(HomeConfigDirError::MissingHome(key))
}

/// Where the resolved config came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// Explicit `--config` flag.
    Flag,
    /// `$FIRMA_CONFIG` env var pointing directly to the file.
    EnvVar,
    /// The user-controlled [trusted config directory](home_config_dir)
    /// (`~/.firma`).
    Home,
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
/// 3. The [trusted config directory](home_config_dir)'s `firma.toml`.
///
/// Tiers 1 and 2 are explicit, launcher-controlled escapes: both are read from
/// the launcher's environment, which a sandboxed agent cannot set, so they do
/// not widen the trust surface. Tier 3 is a fixed, user-controlled directory —
/// there is no cwd/ancestor walk, so no agent- or repo-writable path can ever
/// become the config source without explicit user action.
///
/// # Errors
///
/// Returns `Ok(None)` when no file exists in any tier. Returns
/// [`ConfigResolveError`] when a selected file cannot be read or parsed, or when
/// the trusted directory cannot be determined (fail-closed).
pub fn resolve_config(
    cli_override: Option<&Path>,
) -> Result<Option<ResolvedConfig>, ConfigResolveError> {
    fn load_path(path: &Path, source: ConfigSource) -> Result<ResolvedConfig, ConfigResolveError> {
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

    if let Some(env_path) = env_config_file() {
        return load_path(&env_path, ConfigSource::EnvVar).map(Some);
    }

    let trusted_dir = home_config_dir().map_err(|reason| ConfigResolveError {
        config_source: ConfigSource::Home,
        // We never resolved a directory, so name the file we were seeking rather
        // than emitting an empty path in the error's Display.
        path: PathBuf::from(CONFIG_FILE_NAME),
        reason: reason.into(),
    })?;
    let candidate = trusted_dir.join(CONFIG_FILE_NAME);
    match fs::read_to_string(&candidate) {
        Ok(text) => {
            let config =
                FirmaConfig::parse(&candidate, &text).map_err(|reason| ConfigResolveError {
                    config_source: ConfigSource::Home,
                    path: candidate.clone(),
                    reason,
                })?;
            Ok(Some(ResolvedConfig::new(ConfigSource::Home, config)))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ConfigResolveError {
            config_source: ConfigSource::Home,
            path: candidate,
            reason: error.into(),
        }),
    }
}
