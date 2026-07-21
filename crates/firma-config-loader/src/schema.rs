//! Section extraction so one `firma.toml` serves every subcommand.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use fs_err as fs;

/// A `firma.toml` parsed once. Use when more than one `[section]` is
/// needed from the same file (e.g. `doctor` reads both `[authority]`
/// and `[sidecar]`) so the file is read and parsed a single time.
#[derive(Debug, Clone)]
pub struct FirmaConfig {
    table: toml::Table,
    origin: PathBuf,
}

impl FirmaConfig {
    /// Read and parse `path` once.
    ///
    /// # Errors
    ///
    /// Returns the read or parse error.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(path, &text)
    }

    pub(crate) fn parse(origin: impl Into<PathBuf>, text: &str) -> anyhow::Result<Self> {
        let origin = origin.into();
        let table: toml::Table = text
            .parse()
            .with_context(|| format!("parse {}", origin.display()))?;
        Ok(Self { table, origin })
    }

    /// Path where this config was originally loaded from.
    #[must_use]
    pub fn origin(&self) -> &Path {
        &self.origin
    }

    /// Deserialize the named `[section]` directly into `T`, without a TOML
    /// string round-trip. The preferred entrypoint; reach for
    /// [`raw_section`](Self::raw_section) only when the raw TOML body is
    /// needed.
    ///
    /// Supports dotted paths (e.g. `"sidecar.authority"`) to address
    /// sub-tables. A missing section at any level is a hard error
    /// (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns a "missing section" or deserialization error.
    pub fn section<T: serde::de::DeserializeOwned>(&self, section_path: &str) -> anyhow::Result<T> {
        // `toml` only deserializes owned `Value`/`Table` (no borrowing
        // deserializer), so the section subtree is cloned once here.
        let sub = self.section_table(section_path)?.clone();
        sub.try_into().map_err(|e: toml::de::Error| {
            anyhow!(
                "{}: invalid `[{section_path}]` section: {e}",
                self.origin.display()
            )
        })
    }

    /// The named section body re-serialized as standalone TOML.
    ///
    /// Prefer [`section`](Self::section) for typed access; this exists for
    /// callers that need the raw TOML body (e.g. to re-parse or forward it).
    ///
    /// Supports dotted paths (e.g. `"sidecar.authority"`) to address
    /// sub-tables. A missing section at any level is a hard error
    /// (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns a "missing section" or serialization error.
    pub fn raw_section(&self, section_path: &str) -> anyhow::Result<String> {
        let sub = self.section_table(section_path)?;
        toml::to_string(sub).map_err(|e| anyhow!("{}: {e}", self.origin.display()))
    }

    /// Resolve the sub-table addressed by a dotted `section_path`.
    ///
    /// # Errors
    ///
    /// Returns a "missing section" error when any path segment is absent or is
    /// not a table.
    fn section_table(&self, section_path: &str) -> anyhow::Result<&toml::Table> {
        let parts: Vec<&str> = section_path.split('.').collect();
        let mut current = &self.table;
        for &part in &parts[..parts.len() - 1] {
            match current.get(part) {
                Some(toml::Value::Table(t)) => current = t,
                _ => {
                    bail!(
                        "{}: missing required `[{section_path}]` section",
                        self.origin.display()
                    );
                }
            }
        }
        let last = parts.last().copied().unwrap_or(section_path);
        match current.get(last) {
            Some(toml::Value::Table(sub)) => Ok(sub),
            _ => bail!(
                "{}: missing required `[{section_path}]` section",
                self.origin.display()
            ),
        }
    }
}

/// Read `path` and return the named `[section]` body as standalone TOML.
///
/// The unified `firma.toml` is always sectioned. A missing `[section]`
/// is a hard error (fail-closed) — there is no flat-file fallback.
///
/// # Errors
///
/// Returns the read/parse error, or a "missing section" error.
pub fn load_section(path: &Path, section: &str) -> anyhow::Result<String> {
    FirmaConfig::load(path)?.raw_section(section)
}
