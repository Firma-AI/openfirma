//! TOML document builders + mergers for `firma config`.
//!
//! Replaces the previous Jinja-template rendering path. Every output
//! file is built (initial) or merged (when the file already exists) via
//! [`toml_edit::DocumentMut`], so:
//!
//! - hand-edited comments, key ordering, and unknown sections survive
//!   subsequent `firma config` runs;
//! - the `merge_*` and `build_*` paths share a single source of truth.
//!
//! Field policy:
//!
//! - **user-driven** fields (the ones surfaced by the interactive prompts)
//!   always overwrite on merge — they are the whole point of re-running
//!   `firma config`.
//! - **static defaults** are only seeded when absent; an operator's manual
//!   tweak (e.g. `max_ttl = "2h"`) survives.
//! - **array selections** (intercept hosts, mapping paths, extra-host
//!   rules) are fully replaced because they reflect the *current*
//!   selection — keeping stale entries would silently widen the policy
//!   surface.
//! - **`strict_hosts`** is the exception: it is *merged*, not replaced.
//!   Newly intercepted hosts are appended, but existing operator-edited
//!   entries are preserved. It is decoupled from `intercept_hosts` so an
//!   operator can add a single strict host by hand without re-listing the
//!   whole set, and a re-run of `firma config` will not wipe that edit.
//!   Keeping a strict entry only *narrows* the egress surface (fail-closed),
//!   so preserving it is safe.

#![allow(
    dead_code,
    reason = "some backend-selection helpers are compiled only for non-test host combinations"
)]

use std::path::Path;

use anyhow::{Result, bail};
use firma_identifiers::AgentId;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Key, Table, TableLike, Value, value};

use crate::args::config::Mode;

/// Inputs flattened for document emission. Self-contained — no template
/// engine, no `CollectedInputs` reference, so the doc layer can be unit
/// tested without dragging in the whole `firma config` collection path.
pub struct DocInputs<'a> {
    pub mode: &'a Mode,
    pub keep_local_authority: bool,
    pub profile: &'a str,
    pub agent_id: Option<&'a AgentId>,
    pub authority_listen: &'a str,
    pub authority_url: &'a str,
    pub authority_ca_cert: &'a str,
    pub authority_pub_key: &'a str,
    pub revocation_file: &'a str,
    pub key_file: &'a str,
    pub ca_dir: &'a str,
    pub audit_file: &'a str,
    pub audit_key: &'a str,
    pub tls_cert_path: &'a str,
    pub tls_key_path: &'a str,
    pub mapping_paths: &'a [String],
    pub mitm_hosts: &'a [&'a str],
    pub mitm_bypass_hosts: &'a [&'a str],
    pub workspace: &'a str,
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
    let mut doc = parse_or_empty(text)?;
    merge_firma_toml(&mut doc, inputs)?;
    let mut rendered = doc.to_string();
    append_remote_credentials_hint(&mut rendered, inputs);
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
    let table = ensure_table(doc.as_table_mut(), "authority")?;
    migrate_integer_duration(table, "max_ttl_seconds", "max_ttl", "s");
    migrate_integer_duration(table, "bundle_ttl_seconds", "bundle_ttl", "s");
    set_str(table, "listen_addr", inputs.authority_listen);
    set_str_if_absent(table, "policy_dir", "policies/");
    set_str_if_absent(table, "issuance_policy_dir", "issuance-policies/");
    set_str(table, "revocation_file", inputs.revocation_file);
    set_str(table, "key_file", inputs.key_file);
    set_str_if_absent(table, "max_ttl", "1h");
    set_str_if_absent(table, "bundle_ttl", "30s");
    set_str(table, "tls_cert_path", inputs.tls_cert_path);
    set_str(table, "tls_key_path", inputs.tls_key_path);
    Ok(())
}

fn ensure_sidecar_section(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
    let sidecar = ensure_table(doc.as_table_mut(), "sidecar")?;

    if let Some(local_exec) = optional_table_mut(sidecar, "local_exec")? {
        migrate_integer_duration(local_exec, "token_ttl_secs", "token_ttl", "s");
        migrate_integer_duration(local_exec, "retry_after_ms", "retry_after", "ms");
    }

    if let Some(authority) = optional_table_mut(sidecar, "authority")? {
        migrate_integer_duration(authority, "connect_timeout_secs", "connect_timeout", "s");
        migrate_integer_duration(
            authority,
            "reconnect_min_backoff_ms",
            "reconnect_min_backoff",
            "ms",
        );
        migrate_integer_duration(
            authority,
            "reconnect_max_backoff_secs",
            "reconnect_max_backoff",
            "s",
        );
        migrate_integer_duration(
            authority,
            "revocation_readiness_grace_ms",
            "revocation_readiness_grace",
            "ms",
        );
    }

    set_str_if_absent(sidecar, "mode", "enforce");

    // sidecar.interceptor.{mode, listen_addr} + https_mitm hosts
    {
        let interceptor = ensure_table(sidecar, "interceptor")?;
        migrate_integer_duration(interceptor, "drain_timeout_secs", "drain_timeout", "s");
        if let Some(relay) = optional_table_mut(interceptor, "connect_relay")? {
            migrate_integer_duration(relay, "setup_timeout_secs", "setup_timeout", "s");
            migrate_integer_duration(relay, "session_max_secs", "session_max", "s");
        }
        set_str_if_absent(interceptor, "mode", "http_proxy");
        set_str_if_absent(interceptor, "listen_addr", "127.0.0.1:8080");
        let https = ensure_table(interceptor, "https_mitm")?;
        migrate_integer_duration(https, "cert_ttl_secs", "cert_ttl", "s");
        let has_intercept = !inputs.mitm_hosts.is_empty();
        let has_bypass = !inputs.mitm_bypass_hosts.is_empty();
        if !has_intercept && !has_bypass {
            // No MITM mappings selected and nothing to bypass: disable MITM and
            // clear any stale host lists from a previous run. Writing empty
            // arrays would leave `enabled = true` (the sidecar default) with no
            // hosts — invalid.
            https.insert("enabled", value(false));
            https.remove("intercept_hosts");
            https.remove("strict_hosts");
            https.remove("bypass_hosts");
        } else {
            https.insert("enabled", value(true));
            if has_intercept {
                // intercept_hosts reflects the current selection → full replace.
                set_string_array(https, "intercept_hosts", inputs.mitm_hosts);
                // strict_hosts is decoupled: merge (not replace) so operator
                // hand-added hosts survive while newly intercepted hosts are
                // still seeded. Adding a single strict host never requires
                // re-listing the whole set. See the module-level field-policy note.
                merge_string_array(https, "strict_hosts", inputs.mitm_hosts);
            } else {
                https.remove("intercept_hosts");
                https.remove("strict_hosts");
            }
            if has_bypass {
                // Merge (not replace) so operator hand-added bypass hosts survive.
                merge_string_array(https, "bypass_hosts", inputs.mitm_bypass_hosts);
            }
        }
    }

    {
        let policy = ensure_table(sidecar, "policy")?;
        set_str_if_absent(policy, "dir", ".");
    }

    {
        let ca = ensure_table(sidecar, "ca")?;
        set_str(ca, "dir", inputs.ca_dir);
    }

    {
        let mapping = ensure_table(sidecar, "mapping")?;
        set_str_if_absent(mapping, "rules_path", "mapping-rules.toml");
        set_str_array(mapping, "rules_paths", inputs.mapping_paths);
        set_bool_if_absent(mapping, "default_protected", true);
    }

    {
        let cap = ensure_table(sidecar, "capability_validation")?;
        migrate_integer_duration(
            cap,
            "clock_skew_tolerance_seconds",
            "clock_skew_tolerance",
            "s",
        );
        set_str_if_absent(cap, "clock_skew_tolerance", "0s");
    }

    {
        let conn = ensure_table(sidecar, "connector")?;
        set_str_if_absent(conn, "default_timeout", "2m");
    }

    {
        let audit = ensure_table(sidecar, "audit")?;
        set_str_if_absent(audit, "sink", "file");
        set_str(audit, "file_path", inputs.audit_file);
        set_str(audit, "signing_key_path", inputs.audit_key);
    }

    {
        let auth = ensure_table(sidecar, "authority")?;
        let agent_id = inputs
            .agent_id
            .ok_or_else(|| anyhow::anyhow!("agent config requires an agent TypeID"))?;
        set_str(auth, "agent_id", &agent_id.to_string());
        if inputs.has_connect() {
            set_str(auth, "url", inputs.authority_url);
            set_str(auth, "ca_cert_path", inputs.authority_ca_cert);
            set_str(auth, "public_key_path", inputs.authority_pub_key);
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
/// kernels reject `bwrap` (FIR-184 preflight refuses it), so a WSL host must
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
    replace_workspace_mount(mounts, inputs.workspace);

    // No `[run.profiles.<name>.capability] requested_actions` is scaffolded: a
    // run requests every action class by default and the Authority narrows the
    // grant to what its issuance policy authorizes. Users can set
    // `requested_actions` by hand as an opt-in extra-restriction knob.
    Ok(())
}

fn migrate_run_profile_scalars(profile: &mut Table) -> Result<()> {
    if let Some(capability) = optional_table_mut(profile, "capability")? {
        migrate_integer_duration(capability, "grace_seconds", "grace", "s");
    }
    if let Some(local_exec) = optional_table_mut(profile, "sidecar_local_exec")? {
        migrate_integer_duration(local_exec, "timeout_ms", "timeout", "ms");
        migrate_integer_duration(local_exec, "hitl_max_wait_ms", "hitl_max_wait", "ms");
    }
    Ok(())
}

fn migrate_sidecar_scalars(sidecar: &mut Table) -> Result<()> {
    if let Some(interceptor) = optional_table_mut(sidecar, "interceptor")? {
        migrate_integer_duration(interceptor, "drain_timeout_secs", "drain_timeout", "s");
        migrate_integer_size(
            interceptor,
            "max_request_body_bytes",
            "max_request_body_size",
        );
        migrate_integer_size(interceptor, "total_body_budget_bytes", "total_body_budget");
        if let Some(relay) = optional_table_mut(interceptor, "connect_relay")? {
            migrate_integer_duration(relay, "setup_timeout_secs", "setup_timeout", "s");
            migrate_integer_duration(relay, "session_max_secs", "session_max", "s");
        }
        if let Some(https) = optional_table_mut(interceptor, "https_mitm")? {
            migrate_integer_duration(https, "cert_ttl_secs", "cert_ttl", "s");
        }
    }
    if let Some(capability) = optional_table_mut(sidecar, "capability_validation")? {
        migrate_integer_duration(
            capability,
            "clock_skew_tolerance_seconds",
            "clock_skew_tolerance",
            "s",
        );
    }
    if let Some(connector) = optional_table_mut(sidecar, "connector")? {
        migrate_integer_duration(connector, "default_timeout_ms", "default_timeout", "ms");
        if let Some(hosts) = connector
            .get_mut("hosts")
            .and_then(Item::as_array_of_tables_mut)
        {
            for host in hosts.iter_mut() {
                migrate_integer_duration(host, "timeout_ms", "timeout", "ms");
            }
        } else if let Some(hosts) = connector.get_mut("hosts").and_then(Item::as_array_mut) {
            for host in hosts.iter_mut() {
                let Some(host) = host.as_inline_table_mut() else {
                    bail!("`hosts` array entries must be inline tables");
                };
                migrate_integer_duration(host, "timeout_ms", "timeout", "ms");
            }
        } else if connector.contains_key("hosts") {
            bail!("`hosts` must be an array of tables or an inline array");
        }
    }
    if let Some(audit) = optional_table_mut(sidecar, "audit")? {
        migrate_integer_size(audit, "wal_max_bytes", "wal_max_size");
    }
    if let Some(authority) = optional_table_mut(sidecar, "authority")? {
        migrate_integer_duration(authority, "connect_timeout_secs", "connect_timeout", "s");
        migrate_integer_duration(
            authority,
            "reconnect_min_backoff_ms",
            "reconnect_min_backoff",
            "ms",
        );
        migrate_integer_duration(
            authority,
            "reconnect_max_backoff_secs",
            "reconnect_max_backoff",
            "s",
        );
        migrate_integer_duration(
            authority,
            "revocation_readiness_grace_ms",
            "revocation_readiness_grace",
            "ms",
        );
    }
    if let Some(local_exec) = optional_table_mut(sidecar, "local_exec")? {
        migrate_integer_duration(local_exec, "token_ttl_secs", "token_ttl", "s");
        migrate_integer_duration(local_exec, "retry_after_ms", "retry_after", "ms");
    }
    Ok(())
}

fn replace_workspace_mount(mounts: &mut ArrayOfTables, workspace: &str) {
    // Drop any prior workspace mount (matched by source==target && !read_only);
    // unrelated mounts the user added are preserved.
    let mut new_mounts = ArrayOfTables::new();
    for mount in mounts.iter() {
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
        // Skip the previously-generated workspace mount; user-added
        // entries (read-only, or differing source/target) stay.
        let is_generated_workspace = !read_only && !source.is_empty() && source == target;
        if !is_generated_workspace {
            new_mounts.push(mount.clone());
        }
    }
    let mut entry = Table::new();
    entry.insert("source", value(workspace));
    entry.insert("target", value(workspace));
    entry.insert("read_only", value(false));
    new_mounts.push(entry);
    *mounts = new_mounts;
}

// ── mapping-rules.toml ────────────────────────────────────────────────────────

fn merge_mapping_rules_toml(doc: &mut DocumentMut, inputs: &DocInputs<'_>) -> Result<()> {
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

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
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

fn optional_table_mut<'a>(parent: &'a mut Table, key: &str) -> Result<Option<&'a mut Table>> {
    let Some(item) = parent.get_mut(key) else {
        return Ok(None);
    };
    let Some(table) = item.as_table_mut() else {
        bail!("`{key}` must be a table");
    };
    Ok(Some(table))
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

fn migrate_integer_duration(table: &mut impl TableLike, old_key: &str, new_key: &str, unit: &str) {
    migrate_integer_scalar(table, old_key, new_key, |old_value| {
        format!("{old_value}{unit}")
    });
}

fn migrate_integer_scalar(
    table: &mut impl TableLike,
    old_key: &str,
    new_key: &str,
    render: impl FnOnce(i64) -> String,
) {
    if table.contains_key(new_key) {
        let old_decor = table
            .get_key_value(old_key)
            .map(|(key, item)| (key.clone(), item.clone()));
        table.remove(old_key);
        if let Some((old_key, old_item)) = old_decor
            && let Some((mut new_key, _)) = table.get_key_value_mut(new_key)
        {
            let mut prefix = String::new();
            append_comment_decor(&mut prefix, old_key.leaf_decor().prefix(), false);
            append_comment_decor(
                &mut prefix,
                old_item.as_value().and_then(|value| value.decor().suffix()),
                true,
            );
            if let Some(existing) = new_key
                .leaf_decor()
                .prefix()
                .and_then(toml_edit::RawString::as_str)
            {
                prefix.push_str(existing);
            }
            new_key.leaf_decor_mut().set_prefix(prefix);
        }
        return;
    }
    let Some(old_value) = table.get(old_key).and_then(Item::as_integer) else {
        return;
    };
    let Some((old_formatted_key, old_item)) = table
        .get_key_value(old_key)
        .map(|(key, item)| (key.clone(), item.clone()))
    else {
        return;
    };
    table.remove(old_key);

    let mut migrated_key = Key::new(new_key);
    *migrated_key.leaf_decor_mut() = old_formatted_key.leaf_decor().clone();
    *migrated_key.dotted_decor_mut() = old_formatted_key.dotted_decor().clone();

    let mut migrated_item = value(render(old_value));
    if let (Some(old_value), Some(migrated_value)) =
        (old_item.as_value(), migrated_item.as_value_mut())
    {
        *migrated_value.decor_mut() = old_value.decor().clone();
    }
    table.entry_format(&migrated_key).or_insert(migrated_item);
}

fn append_comment_decor(
    output: &mut String,
    raw: Option<&toml_edit::RawString>,
    trim_leading_whitespace: bool,
) {
    let Some(raw) = raw.and_then(toml_edit::RawString::as_str) else {
        return;
    };
    if !raw.contains('#') {
        return;
    }
    let raw = if trim_leading_whitespace {
        raw.trim_start()
    } else {
        raw
    };
    output.push_str(raw);
    if !output.ends_with('\n') {
        output.push('\n');
    }
}

fn set_int_if_absent(table: &mut Table, key: &str, val: i64) {
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

/// Merge `items` into an existing string array, preserving existing entries
/// and their order and appending only the items not already present. Used for
/// `strict_hosts`, which narrows the egress surface: keeping the operator's
/// hand-added hosts while still seeding any newly intercepted ones is safe
/// (fail-closed) and lets an operator add one host without re-listing the set.
fn merge_string_array(table: &mut Table, key: &str, items: &[&str]) {
    let mut arr = table
        .get(key)
        .and_then(Item::as_array)
        .map_or_else(Array::new, Clone::clone);
    let present: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    for item in items {
        if !present.iter().any(|p| p == item) {
            arr.push(Value::from(*item));
        }
    }
    table.insert(key, value(arr));
}

fn set_str_array(table: &mut Table, key: &str, items: &[String]) {
    let mut arr = Array::new();
    for item in items {
        arr.push(Value::from(item.as_str()));
    }
    table.insert(key, value(arr));
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
            profile: "generic",
            agent_id: Some(&TEST_AGENT_ID),
            authority_listen: "127.0.0.1:50051",
            authority_url: "http://127.0.0.1:50051",
            authority_ca_cert: "/state/tls/authority-ca.crt",
            authority_pub_key: "/state/authority.pub",
            revocation_file: "/state/revocations.txt",
            key_file: "/state/authority.key",
            ca_dir: "/state/generated-firma-ca",
            audit_file: "/state/audit.jsonl",
            audit_key: "/state/audit.key",
            tls_cert_path: "/state/tls/authority.crt",
            tls_key_path: "/state/tls/authority.key",
            mapping_paths: &[],
            mitm_hosts: &[],
            mitm_bypass_hosts: &[],
            workspace: "/workspace",
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
    fn merge_migrates_legacy_interceptor_drain_timeout() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.interceptor]\ndrain_timeout_secs = 30\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("drain_timeout = \"30s\""));
        assert!(!out.contains("drain_timeout_secs"));
    }

    #[test]
    fn merge_migrates_legacy_connect_setup_timeout() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.interceptor.connect_relay]\nsetup_timeout_secs = 10\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("setup_timeout = \"10s\""));
        assert!(!out.contains("setup_timeout_secs"));
    }

    #[test]
    fn merge_migrates_legacy_connect_session_max() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.interceptor.connect_relay]\nsession_max_secs = 600\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("session_max = \"600s\""));
        assert!(!out.contains("session_max_secs"));
    }

    #[test]
    fn merge_migrates_legacy_https_mitm_cert_ttl() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.interceptor.https_mitm]\ncert_ttl_secs = 86400\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("cert_ttl = \"86400s\""));
        assert!(!out.contains("cert_ttl_secs"));
    }

    #[test]
    fn merge_migrates_legacy_authority_connect_timeout() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.authority]\nconnect_timeout_secs = 10\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("connect_timeout = \"10s\""));
        assert!(!out.contains("connect_timeout_secs"));
    }

    #[test]
    fn merge_migrates_legacy_authority_reconnect_min_backoff() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.authority]\nreconnect_min_backoff_ms = 250\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("reconnect_min_backoff = \"250ms\""));
        assert!(!out.contains("reconnect_min_backoff_ms"));
    }

    #[test]
    fn merge_migrates_legacy_authority_reconnect_max_backoff() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.authority]\nreconnect_max_backoff_secs = 30\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("reconnect_max_backoff = \"30s\""));
        assert!(!out.contains("reconnect_max_backoff_secs"));
    }

    #[test]
    fn merge_migrates_legacy_authority_revocation_readiness_grace() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.authority]\nrevocation_readiness_grace_ms = 500\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("revocation_readiness_grace = \"500ms\""));
        assert!(!out.contains("revocation_readiness_grace_ms"));
    }

    #[test]
    fn merge_migrates_legacy_clock_skew_tolerance() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.capability_validation]\nclock_skew_tolerance_seconds = 5\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("clock_skew_tolerance = \"5s\""));
        assert!(!out.contains("clock_skew_tolerance_seconds"));
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
    fn merge_migrates_legacy_local_exec_token_ttl() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.local_exec]\nsocket_path = \"/run/firma/local-exec.sock\"\ntoken_ttl_secs = 300\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("token_ttl = \"300s\""));
        assert!(!out.contains("token_ttl_secs"));
    }

    #[test]
    fn merge_migrates_legacy_local_exec_retry_after() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "[sidecar.local_exec]\nsocket_path = \"/run/firma/local-exec.sock\"\nretry_after_ms = 500\n";

        let out = render_firma_toml(existing, &inputs).unwrap();

        assert!(out.contains("retry_after = \"500ms\""));
        assert!(!out.contains("retry_after_ms"));
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
        assert_eq!(
            auth.get("ca_cert_path").and_then(|v| v.as_str()),
            Some("/state/tls/authority-ca.crt")
        );
        assert_eq!(
            auth.get("public_key_path").and_then(|v| v.as_str()),
            Some("/state/authority.pub")
        );
    }

    #[test]
    fn mode_switch_remote_to_local_replaces_stale_connect_keys() {
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
        assert_eq!(
            auth.get("ca_cert_path").and_then(|v| v.as_str()),
            Some("/state/tls/authority-ca.crt")
        );
        assert_eq!(
            auth.get("public_key_path").and_then(|v| v.as_str()),
            Some("/state/authority.pub")
        );
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
    fn merge_preserves_unknown_sections_and_user_overrides() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = "\
[experimental]
flag = true

[authority]
bundle_ttl = \"10m\"
custom_user_key = \"keep-me\"
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        // Unknown section preserved verbatim.
        assert_eq!(parsed["experimental"]["flag"].as_bool(), Some(true));
        // User override of a static-default key respected.
        assert_eq!(parsed["authority"]["bundle_ttl"].as_str(), Some("10m"));
        // Unknown key inside authority survives.
        assert_eq!(
            parsed["authority"]["custom_user_key"].as_str(),
            Some("keep-me")
        );
        // User-driven key still updated.
        assert_eq!(
            parsed["authority"]["listen_addr"].as_str(),
            Some("127.0.0.1:50051")
        );
    }

    #[test]
    fn merge_migrates_legacy_scalar_keys_in_every_schema_section() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let existing = r#"
[authority]
max_ttl_seconds = 3600
bundle_ttl_seconds = 30

[sidecar.interceptor]
drain_timeout_secs = 30
max_request_body_bytes = 4194304
total_body_budget_bytes = 67108864

[sidecar.interceptor.connect_relay]
setup_timeout_secs = 10
session_max_secs = 600

[sidecar.interceptor.https_mitm]
cert_ttl_secs = 86400

[sidecar.connector]
default_timeout_ms = 30000

[[sidecar.connector.hosts]]
host = "api.example.com"
rps = 1
burst = 1
timeout_ms = 5000

[sidecar.audit]
wal_max_bytes = 104857600

[sidecar.authority]
connect_timeout_secs = 10
reconnect_min_backoff_ms = 250
reconnect_max_backoff_secs = 30
revocation_readiness_grace_ms = 500

[sidecar.capability_validation]
clock_skew_tolerance_seconds = 5

[sidecar.local_exec]
socket_path = "/run/firma/local-exec.sock"
token_ttl_secs = 300
retry_after_ms = 500

[run.defaults.capability]
grace_seconds = 30

[run.defaults.sidecar_local_exec]
timeout_ms = 500
hitl_max_wait_ms = 300000

[run.profiles.unselected.capability]
grace_seconds = 45

[run.profiles.unselected.sidecar_local_exec]
timeout_ms = 750
hitl_max_wait_ms = 600000
"#;

        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let _: firma_config_schema::authority::AuthorityConfig = parsed["authority"]
            .clone()
            .try_into()
            .expect("migrated authority config must satisfy the strict schema");
        let _: firma_config_schema::sidecar::SidecarConfig = parsed["sidecar"]
            .clone()
            .try_into()
            .expect("migrated sidecar config must satisfy the strict schema");
        let run: firma_config_schema::run::FileConfig = parsed["run"]
            .clone()
            .try_into()
            .expect("migrated run config must satisfy the strict schema");

        assert_eq!(
            parsed["sidecar"]["interceptor"]["max_request_body_size"].as_str(),
            Some("4194304 B")
        );
        assert_eq!(
            parsed["sidecar"]["connector"]["hosts"][0]["timeout"].as_str(),
            Some("5000ms")
        );
        assert_eq!(
            run.profiles["unselected"]
                .capability
                .as_ref()
                .and_then(|capability| capability.grace),
            Some(std::time::Duration::from_secs(45))
        );
        for old_key in [
            "max_ttl_seconds",
            "bundle_ttl_seconds",
            "drain_timeout_secs",
            "max_request_body_bytes",
            "total_body_budget_bytes",
            "setup_timeout_secs",
            "session_max_secs",
            "cert_ttl_secs",
            "default_timeout_ms",
            "timeout_ms",
            "wal_max_bytes",
            "connect_timeout_secs",
            "reconnect_min_backoff_ms",
            "reconnect_max_backoff_secs",
            "revocation_readiness_grace_ms",
            "clock_skew_tolerance_seconds",
            "token_ttl_secs",
            "retry_after_ms",
            "grace_seconds",
            "hitl_max_wait_ms",
        ] {
            assert!(!out.contains(old_key), "legacy key survived: {old_key}");
        }
    }

    #[test]
    fn array_fields_fully_replace_on_merge() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let mappings = vec!["mappings/anthropic.toml".to_string()];
        let mitm = ["api.github.com"];
        inputs.mapping_paths = &mappings;
        inputs.mitm_hosts = &mitm;

        let existing = "\
[sidecar.interceptor.https_mitm]
intercept_hosts = [\"old.example.com\"]
strict_hosts = [\"old.example.com\"]

[sidecar.mapping]
rules_paths = [\"mappings/stale.toml\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();

        let mitm_out: Vec<&str> = parsed["sidecar"]["interceptor"]["https_mitm"]["intercept_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(mitm_out, vec!["api.github.com"]);

        // strict_hosts is decoupled from intercept_hosts: existing operator
        // entries are preserved and the newly intercepted host is merged in.
        let strict_out: Vec<&str> = parsed["sidecar"]["interceptor"]["https_mitm"]["strict_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(strict_out, vec!["old.example.com", "api.github.com"]);

        let paths_out: Vec<&str> = parsed["sidecar"]["mapping"]["rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(paths_out, vec!["mappings/anthropic.toml"]);
    }

    #[test]
    fn mitm_disabled_when_hosts_cleared_on_merge() {
        // Existing config had MITM hosts; re-run with no MITM mappings should
        // set enabled = false and remove stale host lists.
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        inputs.mitm_hosts = &[];
        let existing = "\
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = [\"api.github.com\"]
strict_hosts = [\"api.github.com\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https_mitm = &parsed["sidecar"]["interceptor"]["https_mitm"];
        assert_eq!(https_mitm["enabled"].as_bool(), Some(false));
        assert!(https_mitm.get("intercept_hosts").is_none());
        assert!(https_mitm.get("strict_hosts").is_none());
    }

    #[test]
    fn mitm_enabled_when_hosts_added_on_merge() {
        // Existing config had MITM disabled; re-run with hosts should
        // set enabled = true and write host lists.
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let mitm = ["api.github.com"];
        inputs.mitm_hosts = &mitm;
        let existing = "\
[sidecar.interceptor.https_mitm]
enabled = false
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https_mitm = &parsed["sidecar"]["interceptor"]["https_mitm"];
        assert_eq!(https_mitm["enabled"].as_bool(), Some(true));
        let hosts: Vec<&str> = https_mitm["intercept_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(hosts, vec!["api.github.com"]);
    }

    #[test]
    fn bypass_hosts_emitted_and_mitm_stays_enabled_for_copilot() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        inputs.mitm_hosts = &[];
        let bypass = ["github.com", "api.github.com"];
        inputs.mitm_bypass_hosts = &bypass;
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https = &parsed["sidecar"]["interceptor"]["https_mitm"];
        assert_eq!(https["enabled"].as_bool(), Some(true));
        let got: Vec<&str> = https["bypass_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(got.contains(&"github.com"));
        assert!(got.contains(&"api.github.com"));
    }

    #[test]
    fn strict_hosts_seeded_to_intercept_on_initial_render() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let mitm = ["api.github.com", "gmail.googleapis.com"];
        inputs.mitm_hosts = &mitm;
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let strict: Vec<&str> = parsed["sidecar"]["interceptor"]["https_mitm"]["strict_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        // Seeded fail-closed: defaults to the intercepted hosts.
        assert_eq!(strict, vec!["api.github.com", "gmail.googleapis.com"]);
    }

    #[test]
    fn hand_added_strict_host_survives_rerun() {
        // Operator added a strict host by hand (api.anthropic.com) that is not
        // in the current intercept selection. A re-run must preserve it and
        // merge in the newly intercepted hosts — no entry dropped.
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let mitm = ["api.github.com", "gmail.googleapis.com"];
        inputs.mitm_hosts = &mitm;
        let existing = "\
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = [\"api.github.com\"]
strict_hosts = [\"api.github.com\", \"api.anthropic.com\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let https_mitm = &parsed["sidecar"]["interceptor"]["https_mitm"];
        // intercept_hosts reflects the new (wider) selection — full replace.
        let intercept: Vec<&str> = https_mitm["intercept_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(intercept, vec!["api.github.com", "gmail.googleapis.com"]);
        // strict_hosts merged: existing (incl. hand-added) kept in order,
        // newly intercepted gmail appended, github not duplicated.
        let strict: Vec<&str> = https_mitm["strict_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            strict,
            vec![
                "api.github.com",
                "api.anthropic.com",
                "gmail.googleapis.com"
            ]
        );
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

    #[test]
    fn sidecar_section_seeds_mode_enforce_when_absent() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(
            parsed["sidecar"]["mode"].as_str(),
            Some("enforce"),
            "scaffolded firma.toml must seed mode = \"enforce\""
        );
    }

    #[test]
    fn sidecar_section_preserves_existing_mode_on_merge() {
        let existing = "[sidecar]\nmode = \"monitor\"\n";
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(
            parsed["sidecar"]["mode"].as_str(),
            Some("monitor"),
            "merge must not overwrite a user-set mode"
        );
    }
}
