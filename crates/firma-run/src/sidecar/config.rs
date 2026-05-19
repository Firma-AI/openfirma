//! Synthesize a sidecar TOML for an autostarted per-run sidecar.
//!
//! Strategy: inherit the operator-supplied sidecar template verbatim, then
//! normalize to the unified sectioned schema and override
//! `[sidecar.interceptor]` to bind a Unix-domain socket inside
//! the per-sandbox marker directory. When no template is available, write a
//! minimal config (UDS interceptor only — no authority, no policy bundle).
//!
//! The synthesized file is written next to the socket so `firma sidecar
//! status` (FIR-103) can reconstruct context.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use sha2::{Digest, Sha256};

use crate::error::RunError;

const MINIMAL_MAPPING_RULES_TOML: &str = "\
[[rules]]
method = \"CONNECT\"
host = \"auth.openai.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"api.openai.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"chatgpt.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.chatgpt.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"api.anthropic.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"platform.claude.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"claude.ai\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"console.anthropic.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.anthropic.com\"
path = \"/\"
action_class = \"communication.external.send\"

[[rules]]
host = \"auth.openai.com\"
path = \"/api/accounts/deviceauth/*\"
action_class = \"communication.external.send\"

[[rules]]
method = \"POST\"
host = \"auth.openai.com\"
path = \"/oauth/token\"
action_class = \"communication.external.send\"

[[rules]]
host = \"auth.openai.com\"
path = \"/oauth/*\"
action_class = \"communication.external.send\"

[[rules]]
host = \"api.openai.com\"
path = \"/v1/*\"
action_class = \"communication.external.send\"

[[rules]]
host = \"chatgpt.com\"
path = \"/backend-api/*\"
action_class = \"communication.external.send\"

[[rules]]
host = \"*.chatgpt.com\"
path = \"/backend-api/*\"
action_class = \"communication.external.send\"

[[rules]]
host = \"api.anthropic.com\"
path = \"/api/*\"
action_class = \"communication.external.send\"

[[rules]]
host = \"platform.claude.com\"
path = \"/v1/*\"
action_class = \"communication.external.send\"

[[rules]]
host = \"*.anthropic.com\"
path = \"/*\"
action_class = \"communication.external.send\"
";

/// Inputs for [`synthesize`].
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SynthesizeRequest<'a> {
    /// Effective run agent/profile id.
    pub agent_id: &'a str,
    /// Effective run session id.
    pub session_id: &'a str,
    /// Highest-priority template path (typically `--sidecar-config`).
    pub explicit_template: Option<&'a Path>,
    /// Fallback template path from `FIRMA_SIDECAR_CONFIG_FILE`.
    pub env_template: Option<PathBuf>,
    /// Fallback template path from the current working directory.
    pub cwd_template: Option<PathBuf>,
    /// UDS path the spawned sidecar must bind.
    pub socket_path: &'a Path,
    /// Optional TCP listen address for autostart proxy mode.
    /// When set, synthesis configures `[sidecar.interceptor]` for
    /// `http_proxy` instead of `unix_socket`.
    pub listen_addr: Option<SocketAddr>,
    /// Destination for the synthesized TOML.
    pub out_path: &'a Path,
    /// Effective Authority URL to inject into `[sidecar.policy].authority_url`.
    /// `None` leaves the value untouched (preserves any value from
    /// the operator template).
    pub authority_url: Option<&'a str>,
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
    normalize_to_sectioned_sidecar(&mut value)?;
    override_interceptor(&mut value, req.socket_path, req.listen_addr)?;
    if let Some(url) = req.authority_url {
        override_authority_url(&mut value, url)?;
    }
    configure_preflight_capability(&mut value, req.out_path, req.agent_id, req.session_id)?;
    ensure_audit_signing_key(&mut value, req.out_path)?;
    ensure_mapping_rules(&mut value, req.out_path)?;
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

fn override_interceptor(
    value: &mut toml::Value,
    socket_path: &Path,
    listen_addr: Option<SocketAddr>,
) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let entry = sidecar
        .entry("interceptor".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let table = entry
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.interceptor] is not a table".into()))?;
    if let Some(addr) = listen_addr {
        table.insert(
            "mode".to_string(),
            toml::Value::String("http_proxy".to_string()),
        );
        table.insert(
            "listen_addr".to_string(),
            toml::Value::String(addr.to_string()),
        );
    } else {
        table.insert(
            "mode".to_string(),
            toml::Value::String("unix_socket".to_string()),
        );
        table.insert(
            "socket_path".to_string(),
            toml::Value::String(socket_path.display().to_string()),
        );
    }
    Ok(())
}

fn override_authority_url(value: &mut toml::Value, url: &str) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let entry = sidecar
        .entry("policy".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let table = entry
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.policy] is not a table".into()))?;
    table.insert(
        "authority_url".to_string(),
        toml::Value::String(url.to_string()),
    );
    Ok(())
}

fn normalize_to_sectioned_sidecar(value: &mut toml::Value) -> Result<(), RunError> {
    let root = value
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("sidecar template root is not a table".into()))?;

    if root.contains_key("sidecar") {
        return Ok(());
    }

    let legacy_flat = std::mem::take(root);
    let mut new_root = toml::value::Table::new();
    new_root.insert("sidecar".to_string(), toml::Value::Table(legacy_flat));
    *root = new_root;
    Ok(())
}

fn sidecar_table_mut(value: &mut toml::Value) -> Result<&mut toml::value::Table, RunError> {
    let root = value
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("sidecar template root is not a table".into()))?;
    let entry = root
        .entry("sidecar".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    entry
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar] is not a table".into()))
}

fn ensure_audit_signing_key(value: &mut toml::Value, out_path: &Path) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let audit = sidecar
        .entry("audit".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.audit] is not a table".into()))?;

    let has_path = audit
        .get("signing_key_path")
        .and_then(toml::Value::as_str)
        .is_some_and(|v| !v.trim().is_empty());
    let has_env = audit
        .get("signing_key_env")
        .and_then(toml::Value::as_str)
        .is_some_and(|v| !v.trim().is_empty());
    if has_path || has_env {
        return Ok(());
    }

    let parent = out_path.parent().ok_or_else(|| {
        RunError::Internal(format!(
            "cannot resolve parent dir for synthesized sidecar config {}",
            out_path.display()
        ))
    })?;
    let key_path = parent.join("audit.key");
    let pem = generate_ephemeral_audit_key_pem()?;
    std::fs::write(&key_path, pem)
        .map_err(|error| RunError::Internal(format!("write {}: {error}", key_path.display())))?;
    audit.insert(
        "signing_key_path".to_string(),
        toml::Value::String(key_path.display().to_string()),
    );
    Ok(())
}

fn generate_ephemeral_audit_key_pem() -> Result<String, RunError> {
    // Derive a fresh P-256 private key per run marker from a per-process UUID.
    // This avoids shipping static PEM key material in source while preserving
    // zero-touch autostart behavior.
    let seed = Sha256::digest(uuid::Uuid::new_v4().as_bytes());
    let signing_key = SigningKey::from_slice(seed.as_ref())
        .map_err(|error| RunError::Internal(format!("generate audit signing key: {error}")))?;
    signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|error| RunError::Internal(format!("encode audit signing key pem: {error}")))
}

fn ensure_mapping_rules(value: &mut toml::Value, out_path: &Path) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let mapping = sidecar
        .entry("mapping".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.mapping] is not a table".into()))?;

    let parent = out_path.parent().ok_or_else(|| {
        RunError::Internal(format!(
            "cannot resolve parent dir for synthesized sidecar config {}",
            out_path.display()
        ))
    })?;
    let rules_path = parent.join("mapping-rules.toml");
    if !rules_path.exists() {
        std::fs::write(&rules_path, MINIMAL_MAPPING_RULES_TOML).map_err(|error| {
            RunError::Internal(format!("write {}: {error}", rules_path.display()))
        })?;
    }

    let has_rules_path = mapping
        .get("rules_path")
        .and_then(toml::Value::as_str)
        .is_some_and(|v| !v.trim().is_empty());
    if !has_rules_path {
        mapping.insert(
            "rules_path".to_string(),
            toml::Value::String(rules_path.display().to_string()),
        );
    }

    if !mapping.contains_key("default_protected") {
        mapping.insert("default_protected".to_string(), toml::Value::Boolean(true));
    }
    Ok(())
}

fn configure_preflight_capability(
    value: &mut toml::Value,
    out_path: &Path,
    agent_id: &str,
    session_id: &str,
) -> Result<(), RunError> {
    let parent = out_path.parent().ok_or_else(|| {
        RunError::Internal(format!(
            "cannot resolve parent dir for synthesized sidecar config {}",
            out_path.display()
        ))
    })?;
    let authority_pub = parent.join("authority").join("keys").join("authority.pub");
    if !authority_pub.is_file() {
        return Ok(());
    }

    let sidecar = sidecar_table_mut(value)?;

    let authority = sidecar
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.authority] is not a table".into()))?;
    if authority
        .get("public_key_path")
        .and_then(toml::Value::as_str)
        .is_none_or(|v| v.trim().is_empty())
    {
        authority.insert(
            "public_key_path".to_string(),
            toml::Value::String(authority_pub.display().to_string()),
        );
    }

    let preflight = sidecar
        .entry("preflight".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.preflight] is not a table".into()))?;
    if !preflight.contains_key("agent_id") {
        preflight.insert(
            "agent_id".to_string(),
            toml::Value::String(agent_id.to_string()),
        );
    }
    if !preflight.contains_key("session_id") {
        preflight.insert(
            "session_id".to_string(),
            toml::Value::String(session_id.to_string()),
        );
    }
    if !preflight.contains_key("requested_actions") {
        preflight.insert(
            "requested_actions".to_string(),
            toml::Value::Array(vec![toml::Value::String(
                "communication.external.send".to_string(),
            )]),
        );
    }
    if !preflight.contains_key("resource_scope") {
        preflight.insert(
            "resource_scope".to_string(),
            toml::Value::String("*".to_string()),
        );
    }
    if !preflight.contains_key("authority_pub_key_path") {
        preflight.insert(
            "authority_pub_key_path".to_string(),
            toml::Value::String(authority_pub.display().to_string()),
        );
    }
    if !preflight.contains_key("ttl_seconds") {
        preflight.insert("ttl_seconds".to_string(), toml::Value::Integer(900));
    }

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
