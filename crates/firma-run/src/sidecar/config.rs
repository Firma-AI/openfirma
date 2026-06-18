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
use firma_sidecar::authority_credentials::SidecarCredentialsConfig;

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
    /// Effective Authority URL to inject into `[sidecar.authority].url`.
    /// `None` leaves the value untouched (preserves any value from
    /// the operator template).
    pub authority_url: Option<&'a str>,
    /// CA cert path to inject into `[sidecar.authority].ca_cert_path`.
    /// `None` leaves any existing template value untouched.
    pub authority_ca_cert: Option<&'a Path>,
    /// Authority pub key path to inject into `[sidecar.authority].public_key_path`.
    /// The sidecar uses it to verify the per-session capability seed.
    /// `None` leaves any existing template value untouched.
    pub authority_pub_key: Option<&'a Path>,
    /// Sidecar credentials to inject into `[sidecar.authority.credentials]`.
    /// `None` leaves any existing template value untouched.
    pub authority_credentials: Option<&'a SidecarCredentialsConfig>,
    /// Path of the per-session capability seed minted by `firma run`, appended
    /// to `[sidecar.capability_seed].paths`. `None` when no seed was minted
    /// (e.g. `--capability-file` was passed).
    pub capability_seed_path: Option<&'a Path>,
    /// Audit log path used as the default `file` sink when the template does
    /// not configure an audit sink. Set to the shared state/runtime dir's
    /// `audit.jsonl` so `firma monitor` can tail the per-run sidecar's
    /// decisions; without it the default `stdout` sink writes to the spawned
    /// sidecar's null stdout and `firma monitor` shows nothing. `None` leaves
    /// the audit sink untouched (used by tests that assert template fidelity).
    pub audit_fallback_path: Option<&'a Path>,
    /// When `true`, override `[sidecar].mode = "monitor"` regardless of the
    /// operator template. Enables `firma run --monitor` for a single-run
    /// observe-only mode without editing firma.toml.
    pub monitor_mode: bool,
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
    let (mut value, template_dir) = match &source {
        TemplateSource::Explicit(path) | TemplateSource::Env(path) | TemplateSource::Cwd(path) => {
            let abs = std::path::absolute(path).unwrap_or_else(|_| path.clone());
            (parse_template(path)?, abs.parent().map(Path::to_path_buf))
        }
        TemplateSource::Minimal => (toml::Value::Table(toml::value::Table::new()), None),
    };
    normalize_to_sectioned_sidecar(&mut value)?;
    // Per FIR-183: relative resource paths in the operator's template are
    // anchored on the template's `config_dir`. The synthesized file is
    // written into a per-run marker directory, so without this rebase
    // the sidecar would resolve relative paths under the marker dir.
    if let Some(dir) = template_dir.as_deref() {
        rebase_template_resource_paths(&mut value, dir)?;
    }
    override_interceptor(&mut value, req.socket_path, req.listen_addr)?;
    if let Some(url) = req.authority_url {
        override_authority_url(&mut value, url)?;
    }
    if let Some(cert) = req.authority_ca_cert {
        override_authority_ca_cert(&mut value, cert)?;
    }
    if let Some(key) = req.authority_pub_key {
        override_authority_pub_key(&mut value, key)?;
    }
    if let Some(credentials) = req.authority_credentials {
        override_authority_credentials(&mut value, credentials)?;
    }
    // Standalone synthesis (no `authority_pub_key` override, e.g. tests or
    // operator templates) may still need `[sidecar.authority].public_key_path`
    // so the sidecar can verify a seed. Fall back to a conventional marker-dir
    // key only when not already set.
    ensure_authority_pub_key_fallback(&mut value, req.out_path)?;
    configure_capability_seed(&mut value, req.capability_seed_path)?;
    if let Some(audit_path) = req.audit_fallback_path {
        ensure_audit_file_sink(&mut value, audit_path)?;
    }
    if req.monitor_mode {
        override_sidecar_mode(&mut value, "monitor")?;
    }
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

fn override_authority_ca_cert(value: &mut toml::Value, cert: &Path) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let entry = sidecar
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let table = entry
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.authority] is not a table".into()))?;
    table.insert(
        "ca_cert_path".to_string(),
        toml::Value::String(cert.display().to_string()),
    );
    Ok(())
}

fn override_authority_pub_key(value: &mut toml::Value, key: &Path) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let authority = sidecar
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.authority] is not a table".into()))?;
    authority.insert(
        "public_key_path".to_string(),
        toml::Value::String(key.display().to_string()),
    );
    Ok(())
}

fn override_authority_url(value: &mut toml::Value, url: &str) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let entry = sidecar
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let table = entry
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.authority] is not a table".into()))?;
    table.insert("url".to_string(), toml::Value::String(url.to_string()));
    Ok(())
}

fn override_authority_credentials(
    value: &mut toml::Value,
    credentials: &SidecarCredentialsConfig,
) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let authority = sidecar
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.authority] is not a table".into()))?;
    let entry = authority
        .entry("credentials".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let table = entry.as_table_mut().ok_or_else(|| {
        RunError::Internal("[sidecar.authority.credentials] is not a table".into())
    })?;
    table.insert(
        "workspace_id".to_string(),
        toml::Value::String(credentials.workspace_id.clone()),
    );
    table.insert(
        "sidecar_id".to_string(),
        toml::Value::String(credentials.sidecar_id.clone()),
    );
    if let Some(env_name) = credentials.pre_shared_key_env.as_ref() {
        table.insert(
            "pre_shared_key_env".to_string(),
            toml::Value::String(env_name.clone()),
        );
        table.remove("pre_shared_key_path");
    }
    if let Some(path) = credentials.pre_shared_key_path.as_ref() {
        table.insert(
            "pre_shared_key_path".to_string(),
            toml::Value::String(path.display().to_string()),
        );
        table.remove("pre_shared_key_env");
    }
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

/// Resource fields that, per `docs/configuration.md`, resolve under the
/// owning config file's directory. Each tuple is `(table, key)` rooted
/// at the `[sidecar]` table.
const REBASE_SCALAR_FIELDS: &[&[&str]] = &[
    &["audit", "signing_key_path"],
    &["audit", "file_path"],
    &["policy", "dir"],
    &["mapping", "rules_path"],
    &["authority", "ca_cert_path"],
    &["authority", "public_key_path"],
    &["authority", "credentials", "pre_shared_key_path"],
];

/// Resource list fields anchored to the template's config dir.
const REBASE_ARRAY_FIELDS: &[&[&str]] =
    &[&["mapping", "rules_paths"], &["capability_seed", "paths"]];

fn rebase_template_resource_paths(
    value: &mut toml::Value,
    template_dir: &Path,
) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    for path in REBASE_SCALAR_FIELDS {
        rebase_scalar_in_table(sidecar, path, template_dir);
    }
    for path in REBASE_ARRAY_FIELDS {
        rebase_array_in_table(sidecar, path, template_dir);
    }
    Ok(())
}

fn rebase_scalar_in_table(sidecar: &mut toml::value::Table, path: &[&str], template_dir: &Path) {
    let Some((field_key, parents)) = path.split_last() else {
        return;
    };
    let Some(table) = nested_table_mut(sidecar, parents) else {
        return;
    };
    let Some(entry) = table.get_mut(*field_key) else {
        return;
    };
    let Some(text) = entry.as_str() else {
        return;
    };
    if let Some(rebased) = rebase_relative(text, template_dir) {
        *entry = toml::Value::String(rebased);
    }
}

fn nested_table_mut<'a>(
    table: &'a mut toml::value::Table,
    path: &[&str],
) -> Option<&'a mut toml::value::Table> {
    let mut current = table;
    for key in path {
        current = current.get_mut(*key)?.as_table_mut()?;
    }
    Some(current)
}

fn rebase_array_in_table(sidecar: &mut toml::value::Table, path: &[&str], template_dir: &Path) {
    let Some((table_key, field_key)) = path.split_first() else {
        return;
    };
    let Some(field_key) = field_key.first() else {
        return;
    };
    let Some(table) = sidecar
        .get_mut(*table_key)
        .and_then(toml::Value::as_table_mut)
    else {
        return;
    };
    let Some(array) = table
        .get_mut(*field_key)
        .and_then(toml::Value::as_array_mut)
    else {
        return;
    };
    for entry in array.iter_mut() {
        let Some(text) = entry.as_str() else {
            continue;
        };
        if let Some(rebased) = rebase_relative(text, template_dir) {
            *entry = toml::Value::String(rebased);
        }
    }
}

/// Returns `Some(absolute)` only when `value` is a non-empty relative
/// path. Absolute paths and empty values are returned as `None` so the
/// caller can skip the rewrite — matching the sidecar's own
/// `rebase_defaults` contract.
fn rebase_relative(value: &str, template_dir: &Path) -> Option<String> {
    if value.trim().is_empty() {
        return None;
    }
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        return None;
    }
    Some(template_dir.join(candidate).display().to_string())
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

fn override_sidecar_mode(value: &mut toml::Value, mode: &str) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    sidecar.insert("mode".to_string(), toml::Value::String(mode.to_string()));
    Ok(())
}

/// Default the audit sink to a file at `audit_path` when the template did not
/// configure one. The per-run sidecar is spawned with a null stdout, so the
/// default `stdout` audit sink would silently discard every decision and
/// `firma monitor` (which tails `<state_dir>/audit.jsonl`) would show nothing.
/// An explicitly configured sink is left untouched.
fn ensure_audit_file_sink(value: &mut toml::Value, audit_path: &Path) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let audit = sidecar
        .entry("audit".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.audit] is not a table".into()))?;

    // Respect any explicitly configured sink.
    if audit
        .get("sink")
        .and_then(toml::Value::as_str)
        .is_some_and(|v| !v.trim().is_empty())
    {
        return Ok(());
    }

    audit.insert("sink".to_string(), toml::Value::String("file".to_string()));
    audit
        .entry("file_path".to_string())
        .or_insert_with(|| toml::Value::String(audit_path.display().to_string()));
    Ok(())
}

fn ensure_audit_signing_key(value: &mut toml::Value, out_path: &Path) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let audit = sidecar
        .entry("audit".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.audit] is not a table".into()))?;

    let configured_path = audit
        .get("signing_key_path")
        .and_then(toml::Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(Path::new);
    let has_env = audit
        .get("signing_key_env")
        .and_then(toml::Value::as_str)
        .is_some_and(|v| !v.trim().is_empty());

    // If an env var source is configured, trust it.
    if has_env {
        return Ok(());
    }
    // If a path is configured AND the file exists, keep it.
    if configured_path.is_some_and(Path::is_file) {
        return Ok(());
    }
    // Either no path or the path doesn't exist: generate an ephemeral key in
    // the marker dir so the synthesized sidecar is self-contained.
    // (Happens when firma.toml references a long-lived key that hasn't been
    // provisioned yet, e.g. on a fresh checkout.)

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

/// Append the per-session capability seed file to `[capability_seed].paths`
/// so the autostarted sidecar loads it through its existing verifier path.
/// No-op when no seed was minted.
fn configure_capability_seed(
    value: &mut toml::Value,
    seed_path: Option<&Path>,
) -> Result<(), RunError> {
    let Some(seed_path) = seed_path else {
        return Ok(());
    };
    let sidecar = sidecar_table_mut(value)?;
    let cap = sidecar
        .entry("capability_seed".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.capability_seed] is not a table".into()))?;
    let paths = cap
        .entry("paths".to_string())
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            RunError::Internal("[sidecar.capability_seed].paths is not an array".into())
        })?;
    let entry = toml::Value::String(seed_path.display().to_string());
    if !paths.contains(&entry) {
        paths.push(entry);
    }
    Ok(())
}

/// Set `[sidecar.authority].public_key_path` from a conventional marker-dir
/// key (`<marker>/authority/keys/authority.pub`) only when no explicit override
/// was applied and the file exists. Preserves the standalone-synthesis behavior
/// the removed preflight scaffolding relied on, without resurrecting any
/// `[preflight]` table. No-op when the key is already set or absent.
fn ensure_authority_pub_key_fallback(
    value: &mut toml::Value,
    out_path: &Path,
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test module"
)]
mod tests {
    use super::{configure_capability_seed, normalize_to_sectioned_sidecar};

    #[test]
    fn capability_seed_path_is_injected_and_no_preflight() {
        let mut value = toml::Value::Table(toml::value::Table::new());
        normalize_to_sectioned_sidecar(&mut value).unwrap();
        let seed = std::path::PathBuf::from("/run/firma/capabilities/sb.toml");
        configure_capability_seed(&mut value, Some(seed.as_path())).unwrap();
        let sidecar = value.get("sidecar").unwrap().as_table().unwrap();
        let paths = sidecar
            .get("capability_seed")
            .and_then(|c| c.get("paths"))
            .and_then(toml::Value::as_array)
            .unwrap();
        assert!(
            paths
                .iter()
                .any(|p| p.as_str() == Some("/run/firma/capabilities/sb.toml"))
        );
        assert!(sidecar.get("preflight").is_none());
    }
}
