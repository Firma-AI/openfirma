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
use firma_config_loader::AgentProfile;
use firma_core::AgentId;
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

const VSCODE_MINIMAL_MAPPING_RULES_TOML: &str = "\
# Visual Studio Code zero-config mapping — CONNECT-level classification for
# core services, marketplace, account sync, and GitHub account flows.

[[rules]]
method = \"CONNECT\"
host = \"update.code.visualstudio.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"code.visualstudio.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.code.visualstudio.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"vscode.dev\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.vscode.dev\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"az764295.vo.msecnd.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"vscodeexperiments.azureedge.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"default.exp-tas.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"marketplace.visualstudio.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.gallerycdn.vsassets.io\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.gallery.vsassets.io\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.vscode-unpkg.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.vscode-cdn.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"vscode-sync.trafficmanager.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.vscode-sync.trafficmanager.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"login.microsoftonline.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"login.live.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.microsoft.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.msauth.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.msftauth.net\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"github.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.github.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"api.github.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"uploads.github.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.githubusercontent.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.ghe.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"accounts.google.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.gstatic.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.googleusercontent.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"appleid.apple.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"idmsa.apple.com\"
action_class = \"communication.external.send\"

[[rules]]
method = \"CONNECT\"
host = \"*.cdn-apple.com\"
action_class = \"communication.external.send\"
";

const VSCODE_GITHUB_MITM_BYPASS_HOSTS: &[&str] =
    &["github.com", "api.github.com", "uploads.github.com"];

/// Inputs for [`synthesize`].
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SynthesizeRequest<'a> {
    /// Authority-registered agent identity.
    pub agent_id: &'a AgentId,
    /// Effective execution profile.
    pub execution_profile: AgentProfile,
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
    /// HTTP-shaped entries from `ResolvedProfile::secret_providers`, written
    /// into `[sidecar].http_secret_providers` so the Sidecar's MITM path can
    /// intercept matching vault responses (`secret.mediate`, HTTP origin).
    /// Deliberately a distinct field name from firma-run's own
    /// `secret_providers` config so the two are never confused — this is a
    /// read-only mirror the Sidecar consumes, not a config surface an
    /// operator edits directly. Empty when no HTTP providers are configured.
    pub http_secret_providers: &'a [firma_secret_provider::HttpIntegrationSpec],
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
#[expect(
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
    // Pin ca.dir to the marker dir so the MITM CA cert lands where
    // sidecar_trust_env_overrides expects it (<marker_dir>/firma-ca/).
    // The default "./firma-ca/" is CWD-relative and would diverge when
    // firma run's CWD differs from the marker dir.
    override_ca_dir(&mut value, req.out_path)?;
    if let Some(url) = req.authority_url {
        override_authority_url(&mut value, url)?;
    }
    override_authority_agent_id(&mut value, req.agent_id)?;
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
    // GitHub is strict-MITM by default, which skips CONNECT enforcement. The
    // VS Code profile classifies its GitHub account traffic at CONNECT level.
    ensure_vscode_github_mitm_bypass(&mut value, req.execution_profile)?;
    ensure_mapping_rules(&mut value, req.out_path, req.execution_profile)?;
    override_http_secret_providers(&mut value, req.http_secret_providers)?;
    write_atomic(req.out_path, &value)?;
    Ok(source)
}

fn ensure_vscode_github_mitm_bypass(
    value: &mut toml::Value,
    execution_profile: AgentProfile,
) -> Result<(), RunError> {
    if execution_profile != AgentProfile::Vscode {
        return Ok(());
    }

    let sidecar = sidecar_table_mut(value)?;
    let interceptor = sidecar
        .entry("interceptor".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.interceptor] is not a table".into()))?;
    let mitm = interceptor
        .entry("https_mitm".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| {
            RunError::Internal("[sidecar.interceptor.https_mitm] is not a table".into())
        })?;
    let bypass_hosts = mitm
        .entry("bypass_hosts".to_string())
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            RunError::Internal("interceptor.https_mitm.bypass_hosts is not an array".into())
        })?;

    for host in VSCODE_GITHUB_MITM_BYPASS_HOSTS {
        if !bypass_hosts
            .iter()
            .any(|configured| configured.as_str() == Some(host))
        {
            bypass_hosts.push(toml::Value::String((*host).to_string()));
        }
    }
    Ok(())
}

fn override_authority_agent_id(
    value: &mut toml::Value,
    agent_id: &AgentId,
) -> Result<(), RunError> {
    let sidecar = sidecar_table_mut(value)?;
    let authority = sidecar
        .entry("authority".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.authority] is not a table".into()))?;
    authority.insert(
        "agent_id".to_string(),
        toml::Value::String(agent_id.to_string()),
    );
    Ok(())
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

/// Mirror the resolved HTTP-shaped `secret_providers` entries into
/// `[sidecar].http_secret_providers`. A no-op when `providers` is empty —
/// most profiles configure no HTTP vaults, and the field's `#[serde(default)]`
/// on the Sidecar side already treats an absent key as empty.
fn override_http_secret_providers(
    value: &mut toml::Value,
    providers: &[firma_secret_provider::HttpIntegrationSpec],
) -> Result<(), RunError> {
    if providers.is_empty() {
        return Ok(());
    }
    let sidecar = sidecar_table_mut(value)?;
    let serialized = toml::Value::try_from(providers).map_err(|error| {
        RunError::Internal(format!(
            "failed to serialize http_secret_providers into sidecar config: {error}"
        ))
    })?;
    sidecar.insert("http_secret_providers".to_string(), serialized);
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

fn override_ca_dir(value: &mut toml::Value, out_path: &Path) -> Result<(), RunError> {
    let marker_dir = out_path.parent().ok_or_else(|| {
        RunError::Internal(format!(
            "cannot resolve marker dir from synthesized config path {}",
            out_path.display()
        ))
    })?;
    let ca_dir = marker_dir.join("firma-ca");
    let sidecar = sidecar_table_mut(value)?;
    let ca_table = sidecar
        .entry("ca".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| RunError::Internal("[sidecar.ca] is not a table".into()))?;
    ca_table.insert(
        "dir".to_string(),
        toml::Value::String(ca_dir.display().to_string()),
    );
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

fn ensure_mapping_rules(
    value: &mut toml::Value,
    out_path: &Path,
    execution_profile: AgentProfile,
) -> Result<(), RunError> {
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
        std::fs::write(
            &rules_path,
            minimal_mapping_rules_for_profile(execution_profile),
        )
        .map_err(|error| RunError::Internal(format!("write {}: {error}", rules_path.display())))?;
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

fn minimal_mapping_rules_for_profile(execution_profile: AgentProfile) -> &'static str {
    if execution_profile == AgentProfile::Vscode {
        VSCODE_MINIMAL_MAPPING_RULES_TOML
    } else {
        MINIMAL_MAPPING_RULES_TOML
    }
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
mod tests {
    use super::{
        SynthesizeRequest, TemplateSource, configure_capability_seed,
        normalize_to_sectioned_sidecar, synthesize,
    };

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

    #[test]
    fn vscode_minimal_synthesis_writes_marketplace_mapping_rules() {
        let tmp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let cfg_path = tmp.path().join("sidecar.toml");
        let source = synthesize(SynthesizeRequest {
            agent_id: &crate::identity::test_agent_id(),
            execution_profile: firma_config_loader::AgentProfile::Vscode,
            session_id: "sess_001",
            explicit_template: None,
            env_template: None,
            cwd_template: None,
            socket_path: &tmp.path().join("sidecar.sock"),
            listen_addr: Some(
                "127.0.0.1:18080"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}")),
            ),
            out_path: &cfg_path,
            authority_url: None,
            authority_ca_cert: None,
            authority_pub_key: None,
            authority_credentials: None,
            capability_seed_path: None,
            audit_fallback_path: None,
            monitor_mode: false,
            http_secret_providers: &[],
        })
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(source, TemplateSource::Minimal);
        let rules_path = tmp.path().join("mapping-rules.toml");
        let rules = std::fs::read_to_string(&rules_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", rules_path.display()));
        assert!(rules.contains("marketplace.visualstudio.com"));
        assert!(rules.contains("vscode-sync.trafficmanager.net"));
        assert!(!rules.contains("api.openai.com"));
    }
}
