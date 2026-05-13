//! Synthesize a sidecar TOML for an autostarted per-run sidecar.
//!
//! Strategy: inherit the operator-supplied sidecar template verbatim, then
//! override the `[interceptor]` section to bind a Unix-domain socket inside
//! the per-sandbox marker directory. When no template is available, write a
//! minimal config (UDS interceptor only — no authority, no policy bundle).
//!
//! The synthesized file is written next to the socket so `firma sidecar
//! status` (FIR-103) can reconstruct context.

use std::path::{Path, PathBuf};

use crate::error::RunError;

/// Inputs for [`synthesize`].
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SynthesizeRequest<'a> {
    /// Highest-priority template path (typically `--sidecar-config`).
    pub explicit_template: Option<&'a Path>,
    /// Fallback template path from `FIRMA_SIDECAR_CONFIG_FILE`.
    pub env_template: Option<PathBuf>,
    /// Fallback template path from the current working directory.
    pub cwd_template: Option<PathBuf>,
    /// UDS path the spawned sidecar must bind.
    pub socket_path: &'a Path,
    /// Destination for the synthesized TOML.
    pub out_path: &'a Path,
}

/// Result of template resolution. Returned for tests; production callers
/// only consume the file written to `out_path`.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateSource {
    Explicit(PathBuf),
    Env(PathBuf),
    Cwd(PathBuf),
    Minimal,
}

/// Synthesize the sidecar TOML at `req.out_path`. Returns which template
/// won the selection so callers can log or test the decision.
///
/// # Errors
///
/// Returns I/O, parse, or serialization errors. All variants are wrapped in
/// [`RunError`] so that callers can fail-closed through the existing path.
#[doc(hidden)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "request struct carries owned PathBufs the function selects between; cloning to keep callers free of borrow plumbing is the simpler API"
)]
pub fn synthesize(req: SynthesizeRequest<'_>) -> Result<TemplateSource, RunError> {
    let source = select_template(&req);
    let mut value = match &source {
        TemplateSource::Explicit(path) | TemplateSource::Env(path) | TemplateSource::Cwd(path) => {
            parse_template(path)?
        }
        TemplateSource::Minimal => toml::Value::Table(toml::value::Table::new()),
    };
    override_interceptor(&mut value, req.socket_path)?;
    write_atomic(req.out_path, &value)?;
    Ok(source)
}

fn select_template(req: &SynthesizeRequest<'_>) -> TemplateSource {
    if let Some(path) = req.explicit_template
        && path.is_file()
    {
        return TemplateSource::Explicit(path.to_path_buf());
    }
    if let Some(path) = req.env_template.as_deref()
        && path.is_file()
    {
        return TemplateSource::Env(path.to_path_buf());
    }
    if let Some(path) = req.cwd_template.as_deref()
        && path.is_file()
    {
        return TemplateSource::Cwd(path.to_path_buf());
    }
    TemplateSource::Minimal
}

fn parse_template(path: &Path) -> Result<toml::Value, RunError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        RunError::Internal(format!("read sidecar template {}: {error}", path.display()))
    })?;
    toml::from_str(&text).map_err(|error| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn override_interceptor(value: &mut toml::Value, socket_path: &Path) -> Result<(), RunError> {
    let root = value
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("sidecar template root is not a table".into()))?;
    let entry = root
        .entry("interceptor".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let table = entry
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[interceptor] is not a table".into()))?;
    table.insert(
        "mode".to_string(),
        toml::Value::String("unix_socket".to_string()),
    );
    table.insert(
        "socket_path".to_string(),
        toml::Value::String(socket_path.display().to_string()),
    );
    Ok(())
}

fn write_atomic(out: &Path, value: &toml::Value) -> Result<(), RunError> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| RunError::Internal(format!("mkdir {}: {error}", parent.display())))?;
    }
    let serialized = toml::to_string_pretty(value)
        .map_err(|error| RunError::Internal(format!("serialize sidecar config: {error}")))?;
    let tmp = out.with_extension("toml.tmp");
    std::fs::write(&tmp, serialized)
        .map_err(|error| RunError::Internal(format!("write {}: {error}", tmp.display())))?;
    std::fs::rename(&tmp, out).map_err(|error| {
        RunError::Internal(format!(
            "rename {} -> {}: {error}",
            tmp.display(),
            out.display()
        ))
    })?;
    Ok(())
}

#[doc(hidden)]
pub mod testing {
    pub use super::{SynthesizeRequest, TemplateSource, synthesize};
}
