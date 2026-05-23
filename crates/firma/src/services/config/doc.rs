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
//!   tweak (e.g. `bundle_ttl_seconds = 60`) survives.
//! - **array selections** (intercept hosts, mapping paths, requested
//!   actions, extra-host rules) are fully replaced because they reflect
//!   the *current* selection — keeping stale entries would silently widen
//!   the policy surface.

use std::path::Path;

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value, value};

use crate::args::config::Mode;

/// Inputs flattened for document emission. Self-contained — no template
/// engine, no `CollectedInputs` reference, so the doc layer can be unit
/// tested without dragging in the whole `firma config` collection path.
pub struct DocInputs<'a> {
    pub mode: &'a Mode,
    pub keep_local_authority: bool,
    pub name: &'a str,
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
    pub requested_actions: &'a [String],
    pub mapping_paths: &'a [String],
    pub mitm_hosts: &'a [&'a str],
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
        // Mirrors `generate_files`: when remote, write the `url` keys; when
        // agent-local the URL is also written so the sidecar can talk to
        // the colocated authority via the same loopback URL.
        self.has_sidecar()
    }
}

// ── Public renderers ──────────────────────────────────────────────────────────

/// Parse `text` as a `firma.toml` document, merge `inputs` into it, and
/// return the serialized result. Empty `text` produces an initial document.
///
/// # Errors
///
/// Returns the parse error if `text` is not valid TOML.
pub fn render_firma_toml(
    text: &str,
    inputs: &DocInputs<'_>,
) -> Result<String, toml_edit::TomlError> {
    let mut doc = parse_or_empty(text)?;
    merge_firma_toml(&mut doc, inputs);
    Ok(doc.to_string())
}

/// Parse `text` as a `firma-run.toml` document, merge `inputs`, and
/// return the serialized result.
///
/// # Errors
///
/// Returns the parse error if `text` is not valid TOML.
pub fn render_firma_run_toml(
    text: &str,
    inputs: &DocInputs<'_>,
) -> Result<String, toml_edit::TomlError> {
    let mut doc = parse_or_empty(text)?;
    merge_firma_run_toml(&mut doc, inputs);
    Ok(doc.to_string())
}

/// Parse `text` as a `mapping-rules.toml` document, merge `inputs`, and
/// return the serialized result.
///
/// # Errors
///
/// Returns the parse error if `text` is not valid TOML.
pub fn render_mapping_rules_toml(
    text: &str,
    inputs: &DocInputs<'_>,
) -> Result<String, toml_edit::TomlError> {
    let mut doc = parse_or_empty(text)?;
    merge_mapping_rules_toml(&mut doc, inputs);
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

fn parse_or_empty(text: &str) -> Result<DocumentMut, toml_edit::TomlError> {
    if text.is_empty() {
        return Ok(DocumentMut::new());
    }
    text.parse::<DocumentMut>()
}

// ── firma.toml ────────────────────────────────────────────────────────────────

fn merge_firma_toml(doc: &mut DocumentMut, inputs: &DocInputs<'_>) {
    if inputs.has_server() {
        ensure_authority_section(doc, inputs);
    } else {
        doc.as_table_mut().remove("authority");
    }

    if inputs.has_sidecar() {
        ensure_sidecar_section(doc, inputs);
    } else {
        doc.as_table_mut().remove("sidecar");
    }
}

fn ensure_authority_section(doc: &mut DocumentMut, inputs: &DocInputs<'_>) {
    let table = ensure_table(doc.as_table_mut(), "authority");
    set_str(table, "listen_addr", inputs.authority_listen);
    set_str_if_absent(table, "policy_dir", "policies/");
    set_str_if_absent(table, "issuance_policy_dir", "issuance-policies/");
    set_str(table, "revocation_file", inputs.revocation_file);
    set_str(table, "key_file", inputs.key_file);
    set_int_if_absent(table, "max_ttl_seconds", 3600);
    set_int_if_absent(table, "bundle_ttl_seconds", 30);
    set_str(table, "tls_cert_path", inputs.tls_cert_path);
    set_str(table, "tls_key_path", inputs.tls_key_path);
}

fn ensure_sidecar_section(doc: &mut DocumentMut, inputs: &DocInputs<'_>) {
    let sidecar = ensure_table(doc.as_table_mut(), "sidecar");

    // sidecar.interceptor.https_mitm.{intercept_hosts, strict_hosts}
    {
        let interceptor = ensure_table(sidecar, "interceptor");
        let https = ensure_table(interceptor, "https_mitm");
        set_string_array(https, "intercept_hosts", inputs.mitm_hosts);
        set_string_array(https, "strict_hosts", inputs.mitm_hosts);
    }

    {
        let policy = ensure_table(sidecar, "policy");
        set_str_if_absent(policy, "dir", ".");
    }

    {
        let ca = ensure_table(sidecar, "ca");
        set_str(ca, "dir", inputs.ca_dir);
    }

    {
        let log = ensure_table(sidecar, "log");
        set_str_if_absent(log, "level", "info");
    }

    {
        let mapping = ensure_table(sidecar, "mapping");
        set_str_if_absent(mapping, "rules_path", "mapping-rules.toml");
        set_str_array(mapping, "rules_paths", inputs.mapping_paths);
        set_bool_if_absent(mapping, "default_protected", true);
    }

    {
        let cap = ensure_table(sidecar, "capability_validation");
        set_int_if_absent(cap, "clock_skew_tolerance_seconds", 0);
    }

    {
        let ce = ensure_table(sidecar, "constraint_enforcement");
        set_int_if_absent(ce, "bundle_ttl_seconds", 3600);
        set_int_if_absent(ce, "enforcement_timeout_ms", 50);
    }

    {
        let conn = ensure_table(sidecar, "connector");
        set_int_if_absent(conn, "default_timeout_ms", 120_000);
    }

    {
        let audit = ensure_table(sidecar, "audit");
        set_str_if_absent(audit, "sink", "file");
        set_str(audit, "file_path", inputs.audit_file);
        set_str(audit, "signing_key_path", inputs.audit_key);
    }

    {
        let auth = ensure_table(sidecar, "authority");
        if inputs.has_connect() {
            set_str(auth, "url", inputs.authority_url);
            set_str(auth, "ca_cert_path", inputs.authority_ca_cert);
            set_str(auth, "public_key_path", inputs.authority_pub_key);
        } else {
            auth.remove("url");
            auth.remove("ca_cert_path");
            auth.remove("public_key_path");
        }
        set_int_if_absent(auth, "connect_timeout_secs", 10);
        set_int_if_absent(auth, "reconnect_min_backoff_ms", 250);
        set_int_if_absent(auth, "reconnect_max_backoff_secs", 30);
        set_int_if_absent(auth, "revocation_readiness_grace_ms", 500);
        set_bool_if_absent(auth, "revocation_fail_closed_on_disconnect", false);
    }

    {
        let pre = ensure_table(sidecar, "preflight");
        set_str(pre, "agent_id", inputs.name);
        set_str_if_absent(pre, "session_id", "preflight-session");
        set_string_array(
            pre,
            "requested_actions",
            &string_slice(inputs.requested_actions),
        );
        set_str_if_absent(pre, "resource_scope", "*");
        set_int_if_absent(pre, "ttl_seconds", 3600);
    }
}

// ── firma-run.toml ────────────────────────────────────────────────────────────

fn merge_firma_run_toml(doc: &mut DocumentMut, inputs: &DocInputs<'_>) {
    // `[authority]` presence signals "autostart a local Mini Authority".
    // We always emit it on this command path (firma config currently
    // ships an agent that wraps a local mini-authority via firma run);
    // ephemeral port is picked by the supervisor at runtime.
    {
        let auth = ensure_table(doc.as_table_mut(), "authority");
        set_str_if_absent(auth, "listen_addr", "[::1]:0");
    }

    {
        let profiles = ensure_table(doc.as_table_mut(), "profiles");
        let generic = ensure_table(profiles, "generic");
        set_str_if_absent(generic, "backend", "bwrap");

        let env_set = ensure_table(generic, "env_set");
        set_str_if_absent(env_set, "FIRMA_RUN_BWRAP_ROOTFS_MODE", "readonly");
        set_str_if_absent(env_set, "FIRMA_RUN_BWRAP_RUNTIME_HOME", "true");
        set_str_if_absent(
            env_set,
            "FIRMA_RUN_BWRAP_MASK_HOME_PATHS",
            ".ssh,.gnupg,.aws,.config/gcloud,.env",
        );

        let mounts = ensure_array_of_tables(generic, "mounts");
        replace_workspace_mount(mounts, inputs.workspace);
    }
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

fn merge_mapping_rules_toml(doc: &mut DocumentMut, inputs: &DocInputs<'_>) {
    let rules = ensure_array_of_tables(doc.as_table_mut(), "rules");
    let mut new_rules = ArrayOfTables::new();

    // Preserve only rules that are neither the generated localhost rules
    // nor previously-generated extra-host rules. User-added rules survive.
    for rule in rules.iter() {
        if is_generated_rule(rule) {
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
}

fn is_generated_rule(rule: &Table) -> bool {
    let host = rule.get("host").and_then(Item::as_str).unwrap_or("");
    let path = rule.get("path").and_then(Item::as_str);
    let method = rule.get("method").and_then(Item::as_str);
    let action = rule
        .get("action_class")
        .and_then(Item::as_str)
        .unwrap_or("");

    // Localhost fallthroughs.
    if path == Some("*")
        && method.is_none()
        && action == "communication.internal.send"
        && matches!(host, "localhost:*" | "127.0.0.1:*")
    {
        return true;
    }

    // Extra-host CONNECT line: method=CONNECT, action=communication.external.send,
    // host ends with `:443`.
    if method == Some("CONNECT")
        && path.is_none()
        && action == "communication.external.send"
        && host.ends_with(":443")
    {
        return true;
    }

    // Extra-host wildcard line: method=None, path=*, action=external, host has no port.
    if path == Some("*")
        && method.is_none()
        && action == "communication.external.send"
        && !host.contains(':')
    {
        return true;
    }

    false
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

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> &'a mut Table {
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(false);
        parent.insert(key, Item::Table(t));
    }
    let entry = parent
        .entry(key)
        .or_insert_with(|| Item::Table(Table::new()));
    entry
        .as_table_mut()
        .unwrap_or_else(|| unreachable!("entry just ensured as Table"))
}

fn ensure_array_of_tables<'a>(parent: &'a mut Table, key: &str) -> &'a mut ArrayOfTables {
    if !parent.contains_key(key) {
        parent.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    parent
        .entry(key)
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .unwrap_or_else(|| unreachable!("entry just ensured as ArrayOfTables"))
}

fn set_str(table: &mut Table, key: &str, val: &str) {
    table.insert(key, value(val));
}

fn set_str_if_absent(table: &mut Table, key: &str, val: &str) {
    if !table.contains_key(key) {
        table.insert(key, value(val));
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

fn set_str_array(table: &mut Table, key: &str, items: &[String]) {
    let mut arr = Array::new();
    for item in items {
        arr.push(Value::from(item.as_str()));
    }
    table.insert(key, value(arr));
}

fn string_slice(items: &[String]) -> Vec<&str> {
    items.iter().map(String::as_str).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn dummy_inputs(mode: &Mode) -> DocInputs<'_> {
        DocInputs {
            mode,
            keep_local_authority: false,
            name: "test-agent",
            authority_listen: "127.0.0.1:9443",
            authority_url: "https://127.0.0.1:9443",
            authority_ca_cert: "/state/tls/authority-ca.crt",
            authority_pub_key: "/state/authority.pub",
            revocation_file: "/state/revocations.txt",
            key_file: "/state/authority.key",
            ca_dir: "/state/generated-firma-ca",
            audit_file: "/state/audit.jsonl",
            audit_key: "/state/audit.key",
            tls_cert_path: "/state/tls/authority.crt",
            tls_key_path: "/state/tls/authority.key",
            requested_actions: &[],
            mapping_paths: &[],
            mitm_hosts: &[],
            workspace: "/workspace",
            extra_hosts: &[],
        }
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
            Some("127.0.0.1:9443")
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
    fn agent_remote_drops_authority_server_section() {
        let inputs = dummy_inputs(&Mode::AgentRemote);
        let out = render_firma_toml("", &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed.get("authority").is_none(), "got: {out}");
        assert!(parsed.get("sidecar").is_some());
        assert_eq!(
            parsed["sidecar"]["authority"]["url"].as_str(),
            Some("https://127.0.0.1:9443")
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
bundle_ttl_seconds = 600
custom_user_key = \"keep-me\"
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        // Unknown section preserved verbatim.
        assert_eq!(parsed["experimental"]["flag"].as_bool(), Some(true));
        // User override of a static-default key respected.
        assert_eq!(
            parsed["authority"]["bundle_ttl_seconds"].as_integer(),
            Some(600)
        );
        // Unknown key inside authority survives.
        assert_eq!(
            parsed["authority"]["custom_user_key"].as_str(),
            Some("keep-me")
        );
        // User-driven key still updated.
        assert_eq!(
            parsed["authority"]["listen_addr"].as_str(),
            Some("127.0.0.1:9443")
        );
    }

    #[test]
    fn array_fields_fully_replace_on_merge() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        let actions = vec!["communication.external.send".to_string()];
        let mappings = vec!["mappings/anthropic.toml".to_string()];
        let mitm = ["api.github.com"];
        inputs.requested_actions = &actions;
        inputs.mapping_paths = &mappings;
        inputs.mitm_hosts = &mitm;

        let existing = "\
[sidecar.preflight]
requested_actions = [\"stale.action\"]

[sidecar.interceptor.https_mitm]
intercept_hosts = [\"old.example.com\"]
strict_hosts = [\"old.example.com\"]

[sidecar.mapping]
rules_paths = [\"mappings/stale.toml\"]
";
        let out = render_firma_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let actions_out: Vec<&str> = parsed["sidecar"]["preflight"]["requested_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(actions_out, vec!["communication.external.send"]);

        let mitm_out: Vec<&str> = parsed["sidecar"]["interceptor"]["https_mitm"]["intercept_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(mitm_out, vec!["api.github.com"]);

        let paths_out: Vec<&str> = parsed["sidecar"]["mapping"]["rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(paths_out, vec!["mappings/anthropic.toml"]);
    }

    #[test]
    fn firma_run_workspace_mount_replaced_on_merge() {
        let mut inputs = dummy_inputs(&Mode::AgentLocal);
        inputs.workspace = "/new/ws";
        let existing = "\
[authority]
listen_addr = \"[::1]:0\"

[profiles.generic]
backend = \"bwrap\"

[[profiles.generic.mounts]]
source = \"/old/ws\"
target = \"/old/ws\"
read_only = false

[[profiles.generic.mounts]]
source = \"/some/read-only/lib\"
target = \"/some/read-only/lib\"
read_only = true
";
        let out = render_firma_run_toml(existing, &inputs).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        let mounts = parsed["profiles"]["generic"]["mounts"].as_array().unwrap();
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
        // Old generated extra-host CONNECT dropped.
        assert!(!hosts.contains(&"stale.example.com:443"));
        // New extra-host rules emitted (CONNECT + wildcard).
        assert!(hosts.contains(&"api.example.com:443"));
        assert!(hosts.contains(&"api.example.com"));
    }

    #[test]
    fn merge_initial_doc_is_pure_function() {
        let inputs = dummy_inputs(&Mode::AgentLocal);
        let a = render_firma_toml("", &inputs).unwrap();
        let b = render_firma_toml("", &inputs).unwrap();
        assert_eq!(a, b);
    }
}
