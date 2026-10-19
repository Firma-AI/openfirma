//! TOML document builders + mergers for `firma config`.
//!
//! Replaces the previous Jinja-template rendering path. Every output
//! file is built (initial) or merged (when the file already exists) via
//! [`toml_edit::DocumentMut`], so:
//!
//! - hand-edited comments and key ordering survive subsequent `firma config`
//!   runs;
//! - the `merge_*` and `build_*` paths share a single source of truth.
//!
//! Field policy:
//!
//! - **user-driven** fields (the ones surfaced by the interactive prompts)
//!   always overwrite on merge — they are the whole point of re-running
//!   `firma config`.
//! - **static defaults** are only seeded when absent; an operator's manual
//!   tweak (e.g. `max_ttl = "2h"`) survives.
//! - **array selections** replace generated mapping selections and extra-host
//!   rules. Authored mapping paths survive, deduplicated by path identity.
//!   Modes that collect no selection preserve the producer's list.
//! - **MITM interception** is not written at all. The sidecar defaults to
//!   enabled, `intercept_hosts = ["*"]` and `strict_hosts = ["*"]`, so
//!   emitting those keys would pin today's posture into every generated file
//!   and keep a later, wider default from ever reaching it.
//!
//!   A re-run *removes* `enabled`, `intercept_hosts` and `strict_hosts`
//!   whoever wrote them: nothing in the file records its author, so an
//!   operator's hand-written narrowing — including `enabled = false` — does
//!   not survive either. The removal only ever widens interception, which is
//!   the fail-closed direction, but it is not a merge. An operator who needs
//!   a host left uninspected belongs in `bypass_hosts`, which does survive.
//! - **`bypass_hosts`** is the one interception key emitted, and it is
//!   *merged*, not replaced: an operator hand-exempting a pinned-certificate
//!   or mTLS endpoint keeps that entry across re-runs. It is therefore also
//!   the supported way to opt out of interception entirely —
//!   `bypass_hosts = ["*"]` matches every host and is checked before
//!   interception — because neither `enabled = false` nor
//!   `intercept_hosts = []` survives the removal above.

#![allow(
    dead_code,
    reason = "some backend-selection helpers are compiled only for non-test host combinations"
)]

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use firma_config_loader::{CONFIG_FILE_NAME, FirmaConfig};
use firma_identifiers::AgentId;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value, value};

use crate::args::config::Mode;

/// Inputs flattened for document emission. Self-contained — no template
/// engine, no `CollectedInputs` reference, so the doc layer can be unit
/// tested without dragging in the whole `firma config` collection path.
pub struct DocInputs<'a> {
    pub mode: &'a Mode,
    pub keep_local_authority: bool,
    /// No mapping selection was requested; retain the producer's complete list.
    pub preserve_authority_mappings: bool,
    /// Discard remote routing and client identity only during local conversion.
    pub reset_remote_connection: bool,
    pub profile: &'a str,
    pub agent_id: Option<&'a AgentId>,
    pub authority_listen: &'a str,
    pub authority_url: &'a str,
    /// Trust anchors for a remote Authority. Operator-supplied material that
    /// no default can reproduce, so these keys are still written; a local
    /// Authority's anchors are adopted from the state directory instead.
    pub authority_ca_cert: &'a str,
    pub authority_pub_key: &'a str,
    pub mapping_paths: &'a [String],
    /// Hosts the selected mappings need left uninspected — certificate-pinned
    /// or mTLS endpoints that interception would break. There is no
    /// counterpart for hosts to intercept: every host is intercepted by
    /// default, so a selection would only ever narrow that.
    pub mitm_bypass_hosts: &'a [&'a str],
    pub workspace: &'a str,
    /// Directory the rendered `firma.toml` lives in (the project's `.firma/`).
    ///
    /// Used to work out whether `firma run` would derive this workspace on its
    /// own, in which case the mount is left out of the file entirely.
    pub config_dir: &'a Path,
    pub extra_hosts: &'a [String],
}

impl DocInputs<'_> {
    fn has_server(&self) -> bool {
        self.keep_local_authority || matches!(self.mode, Mode::AgentLocal | Mode::Authority)
    }

    fn has_sidecar(&self) -> bool {
        matches!(self.mode, Mode::AgentLocal | Mode::AgentRemote)
    }

    fn has_connect(&self) -> bool {
        // Persist sidecar→authority connect fields for daemon mode
        // (`firma sidecar start`) and remote authority. Per-run autostart
        // may still override the URL with an ephemeral listen address.
        matches!(self.mode, Mode::AgentLocal | Mode::AgentRemote)
    }
}

// ── Public renderers ──────────────────────────────────────────────────────────

/// Parse `text` as a `firma.toml` document, merge `inputs` into it, and
/// return the serialized result. Empty `text` produces an initial document.
///
/// # Errors
///
/// Returns the parse error if `text` is not valid TOML.
pub fn render_firma_toml(text: &str, inputs: &DocInputs<'_>) -> Result<String> {
    validate_firma_toml(text)?;
    let mut doc = parse_or_empty(text)?;
    merge_firma_toml(&mut doc, inputs)?;
    let mut rendered = doc.to_string();
    append_remote_credentials_hint(&mut rendered, inputs);
    validate_firma_toml(&rendered)?;
    Ok(rendered)
}

/// Parse `text` as a `mapping-rules.toml` document, merge `inputs`, and
/// return the serialized result.
///
/// # Errors
///
/// Returns the parse error if `text` is not valid TOML.
pub fn render_mapping_rules_toml(text: &str, inputs: &DocInputs<'_>) -> Result<String> {
    let mut doc = parse_or_empty(text)?;
    merge_mapping_rules_toml(&mut doc, inputs)?;
    Ok(doc.to_string())
}

/// Read an existing TOML file (or get empty text if absent) for merging.
///
/// # Errors
///
/// Surfaces I/O failures other than `NotFound`.
pub fn read_existing_text(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

fn parse_or_empty(text: &str) -> std::result::Result<DocumentMut, toml_edit::TomlError> {
    if text.is_empty() {
        return Ok(DocumentMut::new());
    }
    text.parse::<DocumentMut>()
}

fn validate_firma_toml(text: &str) -> Result<()> {
    let config = FirmaConfig::parse(CONFIG_FILE_NAME, text)?;
    let _: Option<firma_config_schema::authority::AuthorityConfig> =
        config.optional_section("authority")?;
    let _: Option<firma_config_schema::sidecar::SidecarConfig> =
        config.optional_section("sidecar")?;
    let _: Option<firma_config_schema::run::FileConfig> = config.optional_section("run")?;
    Ok(())
}

// ── firma.toml ────────────────────────────────────────────────────────────────

fn merge_firma_toml(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
    if inputs.has_server() {
        ensure_authority_section(doc, inputs)?;
    } else {
        doc.as_table_mut().remove("authority");
    }

    if inputs.has_sidecar() {
        ensure_sidecar_section(doc, inputs)?;
    } else {
        doc.as_table_mut().remove("sidecar");
    }
    ensure_run_profiles_section(doc, inputs)?;
    // [run].profile is user-driven → always overwrite on re-run.
    let run = ensure_table(doc.as_table_mut(), "run")?;
    set_str(run, "profile", inputs.profile);
    Ok(())
}

fn ensure_authority_section(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
    let authored: Vec<String> = doc
        .get("authority")
        .and_then(|authority| authority.get("mapping_rules_paths"))
        .and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml_edit::Value::as_str)
        .filter(|path| super::shipped_mapping_path(inputs.config_dir, path).is_none())
        .map(ToOwned::to_owned)
        .collect();
    let table = ensure_table(doc.as_table_mut(), "authority")?;
    set_str(table, "listen_addr", inputs.authority_listen);
    set_str_if_absent(table, "policy_dir", "policies/");
    set_str_if_absent(table, "issuance_policy_dir", "issuance-policies/");
    set_str_if_absent(table, "max_ttl", "1h");
    set_str_if_absent(table, "bundle_ttl", "30s");
    if !inputs.preserve_authority_mappings || !table.contains_key("mapping_rules_paths") {
        let mut paths = if authored.is_empty() {
            vec!["mapping-rules.toml".to_string()]
        } else {
            authored
        };
        paths.extend_from_slice(inputs.mapping_paths);
        // Different spellings of one file would load its rules twice, which the
        // Authority rejects as duplicate matchers.
        let mut seen = std::collections::HashSet::new();
        paths.retain(|path| seen.insert(super::resolve_mapping_path(inputs.config_dir, path)));
        set_str_array(table, "mapping_rules_paths", &paths);
    }
    if !inputs.extra_hosts.is_empty()
        && let Some(paths) = table
            .get_mut("mapping_rules_paths")
            .and_then(Item::as_array_mut)
    {
        // Extra hosts are emitted into the generated base file, which a custom
        // or empty producer list need not include. Retain the authored list,
        // adding this input only when the operator requests those rules.
        let generated = super::resolve_mapping_path(inputs.config_dir, "mapping-rules.toml");
        let already_loaded = paths
            .iter()
            .filter_map(Value::as_str)
            .any(|path| super::resolve_mapping_path(inputs.config_dir, path) == generated);
        if !already_loaded {
            paths.push("mapping-rules.toml");
        }
    }
    Ok(())
}

fn ensure_sidecar_section(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
    let sidecar = ensure_table(doc.as_table_mut(), "sidecar")?;

    // sidecar.interceptor.{mode, listen_addr} + https_mitm hosts
    {
        let interceptor = ensure_table(sidecar, "interceptor")?;
        set_str_if_absent(interceptor, "mode", "http_proxy");
        set_str_if_absent(interceptor, "listen_addr", "127.0.0.1:8080");
        // Interception is no longer a selection: the sidecar defaults to
        // enabled, intercepting every host and failing closed on every host.
        // Writing those values here would freeze today's defaults into the
        // file, so only `bypass_hosts` is emitted.
        normalize_inline_table(interceptor, "https_mitm");
        if inputs.mitm_bypass_hosts.is_empty() {
            if let Some(https) = interceptor
                .get_mut("https_mitm")
                .and_then(Item::as_table_mut)
            {
                report_dropped_mitm_keys(&drop_managed_mitm_keys(https));
                report_unrequested_bypass_hosts(https, inputs.mitm_bypass_hosts);
                if https.is_empty() {
                    interceptor.remove("https_mitm");
                }
            }
        } else {
            let https = ensure_table(interceptor, "https_mitm")?;
            report_dropped_mitm_keys(&drop_managed_mitm_keys(https));
            report_unrequested_bypass_hosts(https, inputs.mitm_bypass_hosts);
            // Merge (not replace) so operator hand-added bypass hosts survive.
            merge_bypass_hosts(https, inputs.mitm_bypass_hosts);
        }
    }

    {
        let policy = ensure_table(sidecar, "policy")?;
        set_str_if_absent(policy, "dir", ".");
    }

    {
        let conn = ensure_table(sidecar, "connector")?;
        set_str_if_absent(conn, "default_timeout", "2m");
    }

    {
        let audit = ensure_table(sidecar, "audit")?;
        set_str_if_absent(audit, "sink", "file");
    }

    {
        let auth = ensure_table(sidecar, "authority")?;
        let agent_id = inputs
            .agent_id
            .ok_or_else(|| anyhow::anyhow!("agent config requires an agent TypeID"))?;
        set_str(auth, "agent_id", &agent_id.to_string());
        if inputs.has_connect() {
            set_str(auth, "url", inputs.authority_url);
            // A local Authority's anchors sit at their default positions in
            // the state directory, so nothing is written for them. Any existing
            // value is removed rather than left: switching a config from remote
            // to local would otherwise keep pointing the Sidecar at the remote
            // CA and public key it no longer talks to.
            if matches!(inputs.mode, Mode::AgentRemote) {
                set_str(auth, "ca_cert_path", inputs.authority_ca_cert);
                set_str(auth, "public_key_path", inputs.authority_pub_key);
            } else {
                auth.remove("ca_cert_path");
                auth.remove("public_key_path");
                if inputs.reset_remote_connection {
                    auth.remove("connect_addr");
                    auth.remove("tls_client_cert_path");
                    auth.remove("tls_client_key_path");
                }
                // The mini-authority does not use Team PSK authentication.
                // Keeping remote credentials also makes the generated local
                // mapping paths fail credentialed mixed-source validation.
                auth.remove("credentials");
            }
        } else {
            auth.remove("url");
            auth.remove("ca_cert_path");
            auth.remove("public_key_path");
        }
        set_str_if_absent(auth, "connect_timeout", "10s");
        set_str_if_absent(auth, "reconnect_min_backoff", "250ms");
        set_str_if_absent(auth, "reconnect_max_backoff", "30s");
        set_str_if_absent(auth, "revocation_readiness_grace", "500ms");
        set_bool_if_absent(auth, "revocation_fail_closed_on_disconnect", false);
    }

    Ok(())
}

fn append_remote_credentials_hint(rendered: &mut String, inputs: &DocInputs<'_>) {
    if !matches!(inputs.mode, Mode::AgentRemote)
        || rendered.contains("[sidecar.authority.credentials]")
    {
        return;
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered.push_str(
        "\n# Uncomment when connecting to an Authority that requires a Sidecar PSK.\n\
         # The pre-shared key is minted by the Authority operator.\n\
         # [sidecar.authority.credentials]\n\
         # workspace_id = \"ws-acme\"\n\
         # sidecar_id = \"sc-eu-1\"\n\
         # pre_shared_key_env = \"FIRMA_SIDECAR_PSK\"\n\
         # pre_shared_key_path = \"/run/secrets/firma-sidecar-psk\"\n",
    );
}

// ── [run] section ─────────────────────────────────────────────────────────────

fn default_run_backend() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        return "vz";
    }
    #[cfg(target_os = "windows")]
    {
        return "wsl2";
    }
    #[cfg(target_os = "linux")]
    {
        return backend_for_linux(firma_run::backend::platform::detect_wsl());
    }
    #[expect(
        unreachable_code,
        reason = "fallback satisfies exhaustive return typing after cfg-gated platform branches"
    )]
    "bwrap"
}

/// Select the scaffold backend for a Linux host.
///
/// WSL is a Linux build target, so the compile-time `target_os` gating in
/// [`default_run_backend`] cannot distinguish it from native Linux. WSL
/// kernels reject `bwrap` (the run preflight refuses it), so a WSL host must
/// scaffold the `wsl2` backend; native Linux keeps `bwrap`.
//
// Only invoked from the Linux branch of `default_run_backend`; on other
// targets it is exercised solely by unit tests, so silence dead-code there.
fn backend_for_linux(wsl: firma_run::backend::platform::WslKind) -> &'static str {
    if wsl.is_wsl() { "wsl2" } else { "bwrap" }
}

fn ensure_run_profiles_section(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
    let run = ensure_table(doc.as_table_mut(), "run")?;
    let profiles = ensure_table(run, "profiles")?;
    let profile_table = ensure_table(profiles, inputs.profile)?;
    set_str_if_absent(profile_table, "backend", default_run_backend());

    let env_set = ensure_table(profile_table, "env_set")?;
    set_str_if_absent(env_set, "FIRMA_RUN_BWRAP_ROOTFS_MODE", "readonly");
    set_str_if_absent(env_set, "FIRMA_RUN_BWRAP_RUNTIME_HOME", "false");
    set_str_if_absent(
        env_set,
        "FIRMA_RUN_BWRAP_MASK_HOME_PATHS",
        ".ssh,.gnupg,.aws,.config/gcloud,.env",
    );

    let mounts = ensure_array_of_tables(profile_table, "mounts")?;
    // Recorded only when `firma run` would not arrive at it unaided. The
    // default it derives is the directory holding `.firma/`, so an ordinary
    // project layout needs no entry and the file carries no path from this
    // host. `--workspace` elsewhere, or a config in a location
    // `workspace_root` refuses to derive from, is still written out.
    let derived = firma_run::config::workspace_root(
        Some(&inputs.config_dir.join(CONFIG_FILE_NAME)),
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    );
    if derived.as_deref() == Some(Path::new(inputs.workspace)) {
        drop_generated_workspace_mount(mounts);
    } else {
        replace_workspace_mount(mounts, inputs.workspace);
    }

    // No `[run.profiles.<name>.capability] requested_actions` is scaffolded: a
    // run requests every action class by default and the Authority narrows the
    // grant to what its issuance policy authorizes. Users can set
    // `requested_actions` by hand as an opt-in extra-restriction knob.
    Ok(())
}

/// Strip a previously generated workspace mount, leaving user-added entries.
///
/// Used when the run-time default already resolves to this workspace: a config
/// written before that default existed still carries the absolute path, and
/// leaving it would keep pinning one host's checkout.
fn drop_generated_workspace_mount(mounts: &mut ArrayOfTables) {
    let mut kept = ArrayOfTables::new();
    for mount in mounts.iter() {
        if !is_generated_workspace_mount(mount) {
            kept.push(mount.clone());
        }
    }
    *mounts = kept;
}

/// A mount this command generated: read-write with source and target equal.
/// User-added entries differ on one of those and are preserved.
fn is_generated_workspace_mount(mount: &Table) -> bool {
    let source = mount
        .get("source")
        .and_then(Item::as_str)
        .unwrap_or_default();
    let target = mount
        .get("target")
        .and_then(Item::as_str)
        .unwrap_or_default();
    let read_only = mount
        .get("read_only")
        .and_then(Item::as_bool)
        .unwrap_or(true);
    !read_only && !source.is_empty() && source == target
}

/// Record `workspace` as the generated mount, replacing a prior one.
///
/// Used when the run-time default would not arrive at this workspace on its
/// own. Unrelated mounts the user added are preserved.
fn replace_workspace_mount(mounts: &mut ArrayOfTables, workspace: &str) {
    drop_generated_workspace_mount(mounts);
    let mut entry = Table::new();
    entry.insert("source", value(workspace));
    entry.insert("target", value(workspace));
    entry.insert("read_only", value(false));
    mounts.push(entry);
}

// ── mapping-rules.toml ────────────────────────────────────────────────────────

fn merge_mapping_rules_toml(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
    // TOML spells an explicitly empty rule list as an array, not [[rules]].
    if doc
        .get("rules")
        .and_then(Item::as_array)
        .is_some_and(toml_edit::Array::is_empty)
    {
        doc.insert("rules", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let rules = ensure_array_of_tables(doc.as_table_mut(), "rules")?;
    let mut new_rules = ArrayOfTables::new();

    // Preserve user-authored rules. Generated localhost fallthroughs and
    // current extra-host duplicates are regenerated below.
    for rule in rules.iter() {
        if is_generated_localhost_rule(rule) || is_current_extra_host_rule(rule, inputs.extra_hosts)
        {
            continue;
        }
        new_rules.push(rule.clone());
    }

    new_rules.push(make_rule(
        None,
        "localhost:*",
        Some("*"),
        "communication.internal.send",
    ));
    new_rules.push(make_rule(
        None,
        "127.0.0.1:*",
        Some("*"),
        "communication.internal.send",
    ));

    for host in inputs.extra_hosts {
        new_rules.push(make_rule(
            Some("CONNECT"),
            &format!("{host}:443"),
            None,
            "communication.external.send",
        ));
        new_rules.push(make_rule(
            None,
            host,
            Some("*"),
            "communication.external.send",
        ));
    }

    *rules = new_rules;
    Ok(())
}

fn is_generated_localhost_rule(rule: &Table) -> bool {
    let host = rule.get("host").and_then(Item::as_str).unwrap_or("");
    let path = rule.get("path").and_then(Item::as_str);
    let method = rule.get("method").and_then(Item::as_str);
    let action = rule
        .get("action_class")
        .and_then(Item::as_str)
        .unwrap_or("");

    path == Some("*")
        && method.is_none()
        && action == "communication.internal.send"
        && matches!(host, "localhost:*" | "127.0.0.1:*")
}

fn is_current_extra_host_rule(rule: &Table, extra_hosts: &[String]) -> bool {
    let host = rule.get("host").and_then(Item::as_str).unwrap_or("");
    let path = rule.get("path").and_then(Item::as_str);
    let method = rule.get("method").and_then(Item::as_str);
    let action = rule
        .get("action_class")
        .and_then(Item::as_str)
        .unwrap_or("");
    extra_hosts.iter().any(|extra_host| {
        action == "communication.external.send"
            && ((method == Some("CONNECT")
                && path.is_none()
                && host == format!("{extra_host}:443"))
                || (method.is_none() && path == Some("*") && host == extra_host))
    })
}

fn make_rule(method: Option<&str>, host: &str, path: Option<&str>, action: &str) -> Table {
    let mut t = Table::new();
    if let Some(m) = method {
        t.insert("method", value(m));
    }
    t.insert("host", value(host));
    if let Some(p) = path {
        t.insert("path", value(p));
    }
    t.insert("action_class", value(action));
    t
}

// ── toml_edit helpers ─────────────────────────────────────────────────────────

/// Returns `parent[key]` as a standard table, creating it when absent.
///
/// An existing inline table is converted first: `toml_edit` models `key = { … }`
/// as a value, so without that a hand-written `sidecar = { … }` or
/// `interceptor = { … }` would fail the merge outright — and the posture a
/// re-run exists to strip would survive inside it.
///
/// # Errors
///
/// Returns an error when `parent[key]` holds something that is neither a table
/// nor an inline table.
fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    normalize_inline_table(parent, key);
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(false);
        parent.insert(key, Item::Table(t));
    }
    let entry = parent
        .entry(key)
        .or_insert_with(|| Item::Table(Table::new()));
    let Some(table) = entry.as_table_mut() else {
        bail!("`{key}` must be a table");
    };
    Ok(table)
}

fn ensure_array_of_tables<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut ArrayOfTables> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let entry = parent
        .entry(key)
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    let Some(array) = entry.as_array_of_tables_mut() else {
        bail!("`{key}` must be an array of tables");
    };
    Ok(array)
}

fn set_str(table: &mut Table, key: &str, val: &str) {
    table.insert(key, value(val));
}

fn set_str_if_absent(table: &mut Table, key: &str, val: &str) {
    if !table.contains_key(key) {
        table.insert(key, value(val));
    }
}

fn set_bool_if_absent(table: &mut Table, key: &str, val: bool) {
    if !table.contains_key(key) {
        table.insert(key, value(val));
    }
}

fn set_string_array(table: &mut Table, key: &str, items: &[&str]) {
    let mut arr = Array::new();
    for item in items {
        arr.push(Value::from(*item));
    }
    table.insert(key, value(arr));
}

/// Normalizes a host the way the Sidecar does before matching it.
///
/// `interceptor::https_mitm` lowercases and strips the trailing dot, so
/// `API.GitHub.COM.` and `api.github.com` are one host at runtime. Comparing
/// the spellings instead would put both in `bypass_hosts` for one host and make
/// the operator's entry look like one no mapping asked for.
fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Merges `requested` into `bypass_hosts`, preserving existing entries and
/// their order and appending only the hosts not already listed.
///
/// `bypass_hosts` is the one interception key a re-run merges rather than
/// replaces, so an operator hand-exempting a pinned-certificate or mTLS
/// endpoint keeps that entry. Keeping one is fail-*open* — the host stays
/// uninspected — which is why [`report_unrequested_bypass_hosts`] names every
/// entry no selected mapping asked for instead of leaving it silent.
fn merge_bypass_hosts(https: &mut Table, requested: &[&str]) {
    let mut arr = https
        .get("bypass_hosts")
        .and_then(Item::as_array)
        .map_or_else(Array::new, Clone::clone);
    let mut present: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(normalize_host))
        .collect();
    for host in requested {
        let normalized = normalize_host(host);
        if present.contains(&normalized) {
            continue;
        }
        arr.push(Value::from(*host));
        present.push(normalized);
    }
    https.insert("bypass_hosts", value(arr));
}

fn set_str_array(table: &mut Table, key: &str, items: &[String]) {
    let mut arr = Array::new();
    for item in items {
        arr.push(Value::from(item.as_str()));
    }
    table.insert(key, value(arr));
}

/// Rewrites `parent[key]` from an inline table to a standard table.
///
/// `toml_edit` models `key = { … }` as a value rather than a table, so both
/// [`Item::as_table_mut`] and [`ensure_table`] miss it. A hand-written inline
/// table carries the same keys as the block form, and skipping it would leave
/// in place exactly the pinned posture the caller is there to drop.
fn normalize_inline_table(parent: &mut Table, key: &str) {
    let Some(inline) = parent.get(key).and_then(Item::as_inline_table) else {
        return;
    };
    let mut table = inline.clone().into_table();
    table.set_implicit(false);
    parent.insert(key, Item::Table(table));
}

/// Removes the interception keys the sidecar now defaults, so a generated or
/// previously generated file cannot pin a narrower posture than the default.
///
/// This includes the two spellings of "no interception at all" — `enabled =
/// false` and `intercept_hosts = []` — so neither survives a re-run. The
/// supported global opt-out is `bypass_hosts = ["*"]`, which is merged rather
/// than stripped: the pattern is checked before interception and matches every
/// host, so every tunnel stays uninspected across re-runs.
///
/// Returns the keys that were actually present, so the caller can tell the
/// operator what the re-run took away.
fn drop_managed_mitm_keys(https: &mut Table) -> Vec<&'static str> {
    ["enabled", "intercept_hosts", "strict_hosts"]
        .into_iter()
        .filter(|key| https.remove(key).is_some())
        .collect()
}

/// Reports interception keys a re-run removed from an existing file.
///
/// The removal only ever widens interception, but it still discards a decision
/// the operator may have made by hand — including `enabled = false` — and a
/// host that was narrowed out now hard-denies instead of tunnelling, because
/// every host is strict. Saying so here is the difference between that landing
/// as a config change and landing as an unexplained outage.
fn report_dropped_mitm_keys(dropped: &[&'static str]) {
    if dropped.is_empty() {
        return;
    }
    crate::output::warn(format!(
        "removed [sidecar.interceptor.https_mitm] {} — every host is intercepted \
         and strict by default; list a host in bypass_hosts to leave it uninspected, \
         or bypass_hosts = [\"*\"] to turn interception off entirely",
        dropped.join(", ")
    ));
}

/// Reports bypass entries no selected mapping asked for.
///
/// `bypass_hosts` is merged rather than replaced, so an entry survives the
/// mapping selection that introduced it: deselecting `copilot` leaves its three
/// GitHub hosts exempt, and they stay uninspected with nothing in the file
/// recording why. It is also the only narrowing that survives a re-run at all,
/// which makes a stale entry the one way interception silently shrinks.
fn report_unrequested_bypass_hosts(https: &Table, requested: &[&str]) {
    // Compared normalized, like the merge: an entry spelled `API.GitHub.COM`
    // is the host a mapping asked for as `api.github.com`, not a stale one.
    let requested: Vec<String> = requested.iter().copied().map(normalize_host).collect();
    let existing = https
        .get("bypass_hosts")
        .and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml_edit::Value::as_str)
        .filter(|host| !requested.contains(&normalize_host(host)))
        .collect::<Vec<_>>();
    if existing.is_empty() {
        return;
    }
    crate::output::warn(format!(
        "[sidecar.interceptor.https_mitm].bypass_hosts keeps {} that no selected mapping \
         asks for; those hosts stay uninspected until removed by hand",
        existing.join(", ")
    ));
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;

    static TEST_AGENT_ID: LazyLock<AgentId> = LazyLock::new(|| {
        "agt_01j0000000e008000000000001"
            .parse()
            .expect("valid test agent ID")
    });

    fn dummy_inputs(mode: &Mode) -> DocInputs<'_> {
        DocInputs {
            mode,
            keep_local_authority: false,
            preserve_authority_mappings: false,
            reset_remote_connection: false,
            profile: "generic",
            agent_id: Some(&TEST_AGENT_ID),
            authority_listen: "127.0.0.1:50051",
            authority_url: "http://127.0.0.1:50051",
            authority_ca_cert: "/state/tls/authority-ca.crt",
            authority_pub_key: "/state/authority.pub",
            mapping_paths: &[],
            mitm_bypass_hosts: &[],
            workspace: "/workspace",
            config_dir: Path::new("/workspace/.firma"),
            extra_hosts: &[],
        }
    }

    // ── Linux scaffold backend selection ─────────────────────────────────────

    #[test]
    fn native_linux_scaffolds_bwrap() {
        use firma_run::backend::platform::WslKind;
        assert_eq!(backend_for_linux(WslKind::NotWsl), "bwrap");
    }

    #[test]
    fn wsl_scaffolds_wsl2() {
        use firma_run::backend::platform::WslKind;
        assert_eq!(backend_for_linux(WslKind::Wsl), "wsl2");
    }

    #[test]
    fn wsl2_scaffolds_wsl2() {
        use firma_run::backend::platform::WslKind;
        assert_eq!(backend_for_linux(WslKind::Wsl2), "wsl2");
    }

    #[test]
    fn agent_local_emits_both_authority_and_sidecar() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed.get("authority").is_some(), "got: {out}");
        assert!(parsed.get("sidecar").is_some(), "got: {out}");
        assert_eq!(
            parsed["authority"]["listen_addr"].as_str(),
            Some("127.0.0.1:50051")
        );
        assert_eq!(
            parsed["sidecar"]["interceptor"]["mode"].as_str(),
            Some("http_proxy")
        );
        assert_eq!(
            parsed["sidecar"]["interceptor"]["listen_addr"].as_str(),
            Some("127.0.0.1:8080")
        );
    }

    #[test]
    fn authority_mode_drops_sidecar() {
        let inputs = dummy_inputs(&Mode::Authority);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed.get("authority").is_some());
        assert!(parsed.get("sidecar").is_none(), "got: {out}");
    }

    #[test]
    fn agent_local_emits_sidecar_authority_connect() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let auth = &parsed["sidecar"]["authority"];
        assert_eq!(
            auth.get("url").and_then(|v| v.as_str()),
            Some("http://127.0.0.1:50051")
        );
        // Both anchors are adopted from the state directory in local mode.
        assert!(auth.get("ca_cert_path").is_none(), "got: {out}");
        assert!(auth.get("public_key_path").is_none(), "got: {out}");
    }

    #[test]
    fn mode_switch_remote_to_local_drops_stale_connect_keys() {
        let existing = "\
[sidecar.authority]
url = \"https://stale.example.com:9443\"
ca_cert_path = \"/old/ca.crt\"
public_key_path = \"/old/pub.key\"
";
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let auth = &parsed["sidecar"]["authority"];
        assert_eq!(
            auth.get("url").and_then(|v| v.as_str()),
            Some("http://127.0.0.1:50051")
        );
        // The remote anchors must not survive the switch: the local Authority
        // has its own CA and public key at the default positions.
        assert!(auth.get("ca_cert_path").is_none(), "got: {out}");
        assert!(auth.get("public_key_path").is_none(), "got: {out}");
    }

    #[test]
    fn agent_remote_drops_authority_server_section() {
        let inputs = dummy_inputs(&Mode::AgentRemote);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed.get("authority").is_none(), "got: {out}");
        assert!(parsed.get("sidecar").is_some());
        assert_eq!(
            parsed["sidecar"]["authority"]["url"].as_str(),
            Some("http://127.0.0.1:50051")
        );
    }

    #[test]
    fn keep_local_authority_keeps_section_in_remote_mode() {
        let mut inputs = dummy_inputs(&Mode::AgentRemote);
        inputs.keep_local_authority = true;
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed.get("authority").is_some(), "got: {out}");
    }

    #[test]
    fn merge_preserves_current_user_overrides() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "\
[authority]
bundle_ttl = \"10m\"
schema_path = \"custom.cedarschema\"
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        // User override of a static-default key respected.
        assert_eq!(parsed["authority"]["bundle_ttl"].as_str(), Some("10m"));
        assert_eq!(
            parsed["authority"]["schema_path"].as_str(),
            Some("custom.cedarschema")
        );
        // User-driven key still updated.
        assert_eq!(
            parsed["authority"]["listen_addr"].as_str(),
            Some("127.0.0.1:50051")
        );
    }

    #[test]
    fn merge_rejects_invalid_sections_before_mode_changes() {
        for (mode, existing, expected) in [
            (
                Mode::AgentRemote,
                "[authority]\nmax_ttl_seconds = 3600\n",
                "max_ttl_seconds",
            ),
            (
                Mode::Authority,
                "[sidecar.interceptor]\nmax_request_body_size = 4194304\n",
                "max_request_body_size",
            ),
            (
                Mode::AgentLocal,
                "[run.profiles.generic.capability]\ngrace_seconds = 30\n",
                "grace_seconds",
            ),
        ] {
            let error = render_firma_toml(existing, &dummy_inputs(&mode))
                .expect_err("invalid original section must fail before merge");
            assert!(
                error.to_string().contains(expected),
                "unexpected error for {expected}: {error}"
            );
        }
    }

    #[test]
    fn array_fields_fully_replace_on_merge() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let mappings = vec!["mappings/anthropic.toml".to_string()];
        inputs.mapping_paths = &mappings;

        let existing = "\
[authority]
mapping_rules_paths = [\"mapping-rules.toml\", \"mappings/github.toml\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();

        let paths_out: Vec<&str> = parsed["authority"]["mapping_rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            paths_out,
            vec!["mapping-rules.toml", "mappings/anthropic.toml"]
        );
    }

    #[test]
    fn stale_interception_keys_are_cleared_on_merge() {
        // An earlier run pinned a narrow posture. Re-running must drop those
        // keys so the sidecar's intercept-everything default applies, and
        // leave no empty table behind.
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "\
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = [\"api.github.com\"]
strict_hosts = [\"api.github.com\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(
            parsed["sidecar"]["interceptor"].get("https_mitm").is_none(),
            "{out}"
        );
    }

    #[test]
    fn stale_interception_keys_are_cleared_from_an_inline_table() {
        // `toml_edit` models an inline table as a value, not a table, so a
        // hand-written one must be normalized first — otherwise this pinned
        // posture would silently survive the re-run.
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "\
[sidecar.interceptor]
https_mitm = { enabled = false, intercept_hosts = [\"api.github.com\"] }
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(
            parsed["sidecar"]["interceptor"].get("https_mitm").is_none(),
            "{out}"
        );
    }

    #[test]
    fn an_inline_table_keeps_its_unmanaged_keys_and_merged_bypass_hosts() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let bypass = ["api.github.com"];
        inputs.mitm_bypass_hosts = &bypass;
        let existing = "\
[sidecar.interceptor]
https_mitm = { enabled = false, cert_ttl = \"2h\", bypass_hosts = [\"pinned.example.test\"] }
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https = &parsed["sidecar"]["interceptor"]["https_mitm"];
        assert!(https.get("enabled").is_none());
        assert_eq!(https["cert_ttl"].as_str(), Some("2h"));
        let bypass_out: Vec<&str> = https["bypass_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(bypass_out, vec!["pinned.example.test", "api.github.com"]);
    }

    #[test]
    fn stale_interception_keys_are_cleared_from_nested_inline_tables() {
        // `https_mitm` is not the only level that can be hand-written inline.
        // A re-run on this file used to fail with "`interceptor` must be a
        // table", so the pinned posture either survived or broke the command.
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "\
sidecar = { interceptor = { mode = \"http_proxy\", https_mitm = { enabled = false } } }
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let interceptor = &parsed["sidecar"]["interceptor"];
        assert!(interceptor.get("https_mitm").is_none(), "{out}");
        assert_eq!(interceptor["mode"].as_str(), Some("http_proxy"), "{out}");
    }

    #[test]
    fn a_bypass_host_spelled_differently_stays_one_entry() {
        // Host matching lowercases and strips the trailing dot, so these are
        // one host at runtime. Two entries for it would read as an exemption
        // the operator never made.
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let bypass = ["api.github.com"];
        inputs.mitm_bypass_hosts = &bypass;
        let existing = "\
[sidecar.interceptor.https_mitm]
bypass_hosts = [\"API.GitHub.COM\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let got: Vec<&str> = parsed["sidecar"]["interceptor"]["https_mitm"]["bypass_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(got, vec!["API.GitHub.COM"], "{out}");
    }

    #[test]
    fn a_previously_disabled_mitm_is_re_enabled_by_the_default() {
        // `enabled = false` written by an older `firma config` must not
        // survive, or interception would stay off forever.
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "\
[sidecar.interceptor.https_mitm]
enabled = false
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed["sidecar"]["interceptor"].get("https_mitm").is_none());
    }

    #[test]
    fn an_initial_render_emits_no_interception_keys() {
        // Nothing to bypass, so the whole table is left out and the sidecar's
        // intercept-everything default applies untouched.
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed["sidecar"]["interceptor"].get("https_mitm").is_none());
    }

    #[test]
    fn bypass_hosts_are_the_only_interception_keys_emitted() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let bypass = ["github.com", "api.github.com"];
        inputs.mitm_bypass_hosts = &bypass;
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https = &parsed["sidecar"]["interceptor"]["https_mitm"];
        assert!(https.get("enabled").is_none());
        assert!(https.get("intercept_hosts").is_none());
        assert!(https.get("strict_hosts").is_none());
        let got: Vec<&str> = https["bypass_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(got, vec!["github.com", "api.github.com"]);
    }

    #[test]
    fn hand_added_bypass_host_survives_rerun() {
        // An operator exempted a pinned-certificate endpoint by hand. A re-run
        // merges the profile's bypass hosts without dropping that entry.
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let bypass = ["api.github.com"];
        inputs.mitm_bypass_hosts = &bypass;
        let existing = "\
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = [\"api.github.com\"]
bypass_hosts = [\"pinned.example.test\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https_mitm = &parsed["sidecar"]["interceptor"]["https_mitm"];
        assert!(https_mitm.get("enabled").is_none());
        assert!(https_mitm.get("intercept_hosts").is_none());
        let bypass_out: Vec<&str> = https_mitm["bypass_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(bypass_out, vec!["pinned.example.test", "api.github.com"]);
    }

    #[test]
    fn run_profiles_workspace_mount_replaced_on_merge() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        inputs.workspace = "/new/ws";
        let existing = "\
[authority]
listen_addr = \"[::1]:0\"

[run.profiles.generic]
backend = \"bwrap\"

[[run.profiles.generic.mounts]]
source = \"/old/ws\"
target = \"/old/ws\"
read_only = false

[[run.profiles.generic.mounts]]
source = \"/some/read-only/lib\"
target = \"/some/read-only/lib\"
read_only = true
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let mounts = parsed["run"]["profiles"]["generic"]["mounts"]
            .as_array()
            .unwrap();
        let sources: Vec<&str> = mounts
            .iter()
            .map(|m| m["source"].as_str().unwrap_or_default())
            .collect();
        // Old workspace mount dropped; read-only user mount preserved; new ws appended.
        assert_eq!(sources, vec!["/some/read-only/lib", "/new/ws"]);
    }

    #[test]
    fn mapping_rules_regenerates_localhost_and_extra_hosts() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let extra = vec!["api.example.com".to_string()];
        inputs.extra_hosts = &extra;
        let existing = "\
[[rules]]
host = \"localhost:*\"
path = \"*\"
action_class = \"communication.internal.send\"

[[rules]]
host = \"127.0.0.1:*\"
path = \"*\"
action_class = \"communication.internal.send\"

[[rules]]
host = \"user-kept.example.com\"
path = \"*\"
action_class = \"data.read\"

[[rules]]
host = \"stale.example.com:443\"
method = \"CONNECT\"
action_class = \"communication.external.send\"

[[rules]]
host = \"api.example.com:443\"
method = \"CONNECT\"
action_class = \"communication.external.send\"
";
        let out = render_mapping_rules_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let rules = parsed["rules"].as_array().unwrap();
        let hosts: Vec<&str> = rules
            .iter()
            .map(|r| r["host"].as_str().unwrap_or_default())
            .collect();

        assert!(hosts.contains(&"localhost:*"));
        assert!(hosts.contains(&"127.0.0.1:*"));
        // User-added rule preserved.
        assert!(hosts.contains(&"user-kept.example.com"));
        // External user rules that only look like generated extra-host rules survive.
        assert!(hosts.contains(&"stale.example.com:443"));
        // New extra-host rules emitted (CONNECT + wildcard).
        assert!(hosts.contains(&"api.example.com:443"));
        assert!(hosts.contains(&"api.example.com"));
        assert_eq!(
            hosts
                .iter()
                .filter(|host| **host == "api.example.com:443")
                .count(),
            1,
            "current extra-host CONNECT should be replaced, not duplicated"
        );
    }

    #[test]
    fn merge_reports_type_conflicts_without_panicking() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let err = render_firma_toml("sidecar = \"not a table\"\n", &inputs).unwrap_err();
        assert!(
            err.to_string().contains("sidecar"),
            "error should name conflicting key: {err}"
        );
    }

    #[test]
    fn merge_initial_doc_is_pure_function() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let a = render_firma_toml("", &inputs).unwrap();
        let b = render_firma_toml("", &inputs).unwrap();
        assert_eq!(a, b);
    }
}
