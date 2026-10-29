//! Runner for `firma config` — scaffold a new agent config directory.

mod doc;
mod remote_authority;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::ValueEnum as _;
use dialoguer::theme::ColorfulTheme;

use crate::args::config::{InitArgs, Mapping, Mode, Posture};
use doc::DocInputs;
use firma_config_loader::{AgentProfile, CONFIG_DIR_NAME, CONFIG_FILE_NAME};
use firma_fs::create_private_dir_all;
use firma_identifiers::AgentId;
use firma_runtime_state::RuntimeLayout;
use remote_authority::{collect_remote_connect_inputs, same_authority_endpoint};

struct AuthorityInputs {
    /// gRPC listen address (agent-local + authority modes).
    listen: String,
    /// URL written to `[sidecar.authority].url`.
    connect_url: String,
    /// CA cert path written as `[sidecar.authority].ca_cert_paths = [path]`. `None`
    /// writes none: a remote Authority is then verified against the platform's
    /// trusted roots, and a local one against the state directory's CA.
    connect_ca_cert: Option<String>,
    /// Public key path written to `[sidecar.authority].public_key_path`.
    connect_pub_key: String,
}

struct SidecarInputs {
    posture: Posture,
    overwrite_policy: bool,
    mappings: Vec<Mapping>,
    extra_hosts: Vec<String>,
    workspace: PathBuf,
}

struct CollectedInputs {
    mode: Mode,
    keep_local_authority: bool,
    preserve_authority_mappings: bool,
    reset_remote_connection: bool,
    authority: AuthorityInputs,
    sidecar: SidecarInputs,
    config_dir: PathBuf,
    state_dir: PathBuf,
    agent_id: Option<AgentId>,
    profile: String,
}

#[derive(Debug, Default)]
struct ExistingConfigDefaults {
    exists: bool,
    mode: Option<Mode>,
    authority_listen: Option<String>,
    authority_url: Option<String>,
    authority_ca_cert: Option<PathBuf>,
    authority_pub_key: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    posture: Option<Posture>,
    mappings: Option<Vec<Mapping>>,
    workspace: Option<PathBuf>,
    profile: Option<String>,
    agent_id: Option<AgentId>,
    invalid_agent_id: Option<String>,
}

static TPL_CEDAR_ISSUANCE: &str = include_str!("../../../templates/issuance.cedar");

/// Entry point for `firma config`.
///
/// # Errors
///
/// Returns an error on I/O failure or template-rendering failure.
pub fn run(args: &InitArgs) -> Result<ExitCode> {
    if args.list_templates {
        return Ok(crate::services::policy::list());
    }

    let inputs = collect_inputs(args)?;
    let cfg = &inputs.config_dir;
    let state = &inputs.state_dir;
    let authority_layout = RuntimeLayout::from_root(state);

    let files = generate_files(&inputs)?;

    if args.dry_run {
        for (rel, content) in &files {
            println!("=== {} ===", cfg.join(rel).display());
            println!("{content}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    upgrade_connect_only_mappings(cfg, &inputs, args.force)?;

    warn_on_non_default_state_dir(state);
    create_scaffold_dirs(cfg, &authority_layout)?;
    write_scaffold_files(&files, cfg, args.force, inputs.sidecar.overwrite_policy)?;

    let has_server = has_server(&inputs);
    let has_sidecar = matches!(inputs.mode, Mode::AgentLocal | Mode::AgentRemote);

    if has_sidecar {
        let interactive = !args.yes && dialoguer::console::Term::stderr().is_term();
        cleanup_stale_posture_files(
            cfg,
            &inputs.sidecar.posture,
            interactive,
            args.force,
            &ColorfulTheme::default(),
        )?;
    }

    if has_server {
        write_revocations(&authority_layout, args.force)?;
        crate::services::authority::generate_audit_key_if_absent(
            &authority_layout.audit_key(),
            args.force,
        )?;
    }

    if has_server {
        write_server_material(&authority_layout, args.force)?;
    }

    println!("\nScaffolded:");
    println!("  config  {}", cfg.display());
    println!("  state   {}", state.display());
    println!("\nNext:");
    match inputs.mode {
        Mode::AgentLocal | Mode::AgentRemote => {
            println!(
                "  firma run --config {}/firma.toml -- <agent-command>",
                cfg.display()
            );
        }
        Mode::Authority => {
            println!("  firma authority --config {}/firma.toml", cfg.display());
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Every TLS artifact `firma config` generates for a local Authority.
///
/// Grouped here rather than in [`RuntimeLayout`] because "the files this
/// command writes" is a scaffolding concern, not part of the runtime layout
/// every component shares.
fn tls_files(layout: &RuntimeLayout) -> [PathBuf; 4] {
    [
        layout.authority_tls_certificate(),
        layout.authority_tls_private_key(),
        layout.authority_tls_ca_certificate(),
        layout.authority_tls_ca_private_key(),
    ]
}

fn write_revocations(layout: &RuntimeLayout, force: bool) -> Result<()> {
    let path = layout.revocations();
    if force {
        Ok(firma_fs::write_file(&path, b"", 0o600)?)
    } else {
        Ok(firma_fs::write_new_file(&path, b"", 0o600).or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?)
    }
}

fn create_scaffold_dirs(cfg: &Path, authority_layout: &RuntimeLayout) -> Result<()> {
    for dir in [
        cfg,
        &cfg.join("policies"),
        &cfg.join("issuance-policies"),
        &cfg.join("mappings"),
        authority_layout.root(),
        &authority_layout.generated_ca_dir(),
    ] {
        create_private_dir_all(dir)?;
    }
    Ok(())
}

/// Upgrades an existing mapping file that only classifies its hosts at CONNECT
/// level, keeping the operator's copy beside it.
///
/// Mapping files are not merged: an existing one is left untouched unless
/// `--force` is passed, so a directory scaffolded before interception became
/// the default keeps CONNECT-only rules while the Sidecar starts decrypting —
/// and every decrypted request to those hosts is then denied as unclassified,
/// which takes the agent down. Replacing only the files with that defect keeps
/// a working configuration working, and the displaced file is renamed rather
/// than discarded, so an operator's edits survive even when they are the reason
/// the file is incompatible.
///
/// A file matching the shipped mapping needs no upgrade, one that does not parse
/// is left to the Sidecar's own validation, and a host the selected mappings
/// bypass is exempt because it is never decrypted.
///
/// # Errors
///
/// Surfaces the I/O failures of moving the old file aside.
fn upgrade_connect_only_mappings(cfg: &Path, inputs: &CollectedInputs, force: bool) -> Result<()> {
    use std::collections::BTreeSet;

    use firma_core::normalize_mapping_host;

    if force {
        // `--force` rewrites every scaffold file anyway.
        return Ok(());
    }
    let bypassed: BTreeSet<String> = inputs
        .sidecar
        .mappings
        .iter()
        .flat_map(Mapping::mitm_bypass_hosts)
        .map(|host| normalize_mapping_host(host))
        .collect();
    for mapping in &inputs.sidecar.mappings {
        let rel = format!("mappings/{}.toml", mapping.as_str());
        let path = cfg.join(&rel);
        let Ok(existing) = fs::read_to_string(&path) else {
            continue;
        };
        if existing == mapping.static_content() {
            continue;
        }
        let Ok(parsed) = toml::from_str::<firma_sidecar::config::MappingRulesFile>(&existing)
        else {
            continue;
        };
        let is_connect = |rule: &firma_sidecar::config::MappingRuleConfig| {
            rule.method.as_ref() == Some(&firma_http::Method::CONNECT)
        };
        let unclassified: BTreeSet<String> = parsed
            .rules
            .iter()
            .filter(|rule| is_connect(rule))
            .map(|rule| normalize_mapping_host(&rule.host))
            .filter(|host| !bypassed.contains(host))
            .filter(|host| {
                !parsed
                    .rules
                    .iter()
                    .any(|other| !is_connect(other) && normalize_mapping_host(&other.host) == *host)
            })
            .collect();
        if unclassified.is_empty() {
            continue;
        }
        // Remove it so the normal scaffold write recreates it from the shipped
        // content; the copy keeps whatever the operator had.
        let displaced = path.with_extension("toml.bak");
        fs::rename(&path, &displaced).with_context(|| format!("move {} aside", path.display()))?;
        crate::output::warn(format!(
            "replaced {rel}: it classified {} at CONNECT level only, and every host is \
             intercepted by default, so their decrypted requests were denied as unclassified. \
             The previous file is at {}",
            unclassified.into_iter().collect::<Vec<_>>().join(", "),
            displaced.display()
        ));
    }
    Ok(())
}

fn write_scaffold_files(
    files: &[(String, String)],
    cfg: &Path,
    force: bool,
    overwrite_policy: bool,
) -> Result<()> {
    for (rel, content) in files {
        let path = cfg.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        // `firma.toml` and `mapping-rules.toml` are produced by the toml_edit
        // merge layer: the input was read from disk, modified in place, and
        // re-serialized. Writing the resulting bytes back is non-destructive —
        // schema-valid user-tuned defaults and comments are preserved.
        // Skipping the write here would silently swallow mode changes (e.g.
        // switching from agent-remote to agent-local would not persist the new
        // `[authority]` section).
        let is_merged_toml = matches!(rel.as_str(), CONFIG_FILE_NAME | "mapping-rules.toml");
        let should_overwrite =
            force || is_merged_toml || (overwrite_policy && rel.starts_with("policies/"));
        if !should_overwrite && path.exists() {
            crate::output::warn(format!(
                "skip (exists): {} — use --force to overwrite",
                path.display()
            ));
            continue;
        }
        fs::write(&path, content.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        println!("  wrote {}", path.display());
    }
    Ok(())
}

fn write_server_material(layout: &RuntimeLayout, force: bool) -> Result<()> {
    let key_path = layout.authority_key();
    if force && key_path.exists() {
        fs::remove_file(&key_path).with_context(|| format!("remove {}", key_path.display()))?;
        let pub_path = layout.authority_public_key();
        if pub_path.exists() {
            fs::remove_file(&pub_path).with_context(|| format!("remove {}", pub_path.display()))?;
        }
    }
    if key_path.exists() {
        println!("  preserved existing authority keypair");
    } else {
        crate::services::authority::run_generate_key(&key_path)
            .with_context(|| format!("generate authority key at {}", key_path.display()))?;
        println!("  generated authority keypair → {}", key_path.display());
    }

    let tls_dir = layout.tls_dir();
    let tls_cert = layout.authority_tls_certificate();
    if force && tls_dir.exists() {
        for p in tls_files(layout) {
            if p.exists() {
                fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            }
        }
    }
    if tls_cert.exists() {
        println!("  preserved existing TLS material");
    } else {
        crate::services::authority::run_bootstrap_tls(&tls_dir, &[])
            .with_context(|| "generate TLS material")?;
    }
    Ok(())
}

fn generate_files(inputs: &CollectedInputs) -> Result<Vec<(String, String)>> {
    let mapping_paths: Vec<String> = inputs
        .sidecar
        .mappings
        .iter()
        .map(|m| format!("mappings/{}.toml", m.as_str()))
        .collect();
    let mitm_bypass_hosts: Vec<&str> = inputs
        .sidecar
        .mappings
        .iter()
        .flat_map(Mapping::mitm_bypass_hosts)
        .copied()
        .collect();

    let workspace_display = path_display(&inputs.sidecar.workspace);

    let doc_inputs = DocInputs {
        mode: &inputs.mode,
        keep_local_authority: inputs.keep_local_authority,
        preserve_authority_mappings: inputs.preserve_authority_mappings,
        reset_remote_connection: inputs.reset_remote_connection,
        profile: &inputs.profile,
        agent_id: inputs.agent_id.as_ref(),
        authority_listen: &inputs.authority.listen,
        authority_url: &inputs.authority.connect_url,
        authority_ca_cert: inputs.authority.connect_ca_cert.as_deref(),
        authority_pub_key: &inputs.authority.connect_pub_key,
        mapping_paths: &mapping_paths,
        mitm_bypass_hosts: &mitm_bypass_hosts,
        workspace: &workspace_display,
        config_dir: &inputs.config_dir,
        extra_hosts: &inputs.sidecar.extra_hosts,
    };

    let firma_toml = render_for(&inputs.config_dir, CONFIG_FILE_NAME, |text| {
        doc::render_firma_toml(text, &doc_inputs)
    })?;

    let cedar_path = format!("policies/{}.cedar", inputs.sidecar.posture.file_name());
    let mut files: Vec<(String, String)> = vec![
        (CONFIG_FILE_NAME.into(), firma_toml),
        (
            cedar_path,
            inputs.sidecar.posture.cedar_content().to_string(),
        ),
        (
            "issuance-policies/issuance.cedar".into(),
            TPL_CEDAR_ISSUANCE.to_string(),
        ),
    ];

    if has_server(inputs) {
        let mapping_rules = render_for(&inputs.config_dir, "mapping-rules.toml", |text| {
            doc::render_mapping_rules_toml(text, &doc_inputs)
        })?;
        files.push(("mapping-rules.toml".into(), mapping_rules));
        for mapping in &inputs.sidecar.mappings {
            files.push((
                format!("mappings/{}.toml", mapping.as_str()),
                mapping.static_content().to_string(),
            ));
        }
    }

    Ok(files)
}

/// Read `config_dir/rel` (or empty if absent), pass to `render`, and
/// return the merged TOML string.
fn render_for<F>(config_dir: &Path, rel: &str, render: F) -> Result<String>
where
    F: FnOnce(&str) -> Result<String>,
{
    let path = config_dir.join(rel);
    let text =
        doc::read_existing_text(&path).with_context(|| format!("read {}", path.display()))?;
    render(&text).with_context(|| format!("merge {}", path.display()))
}

fn path_display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn default_output_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(CONFIG_DIR_NAME)
}

fn collect_inputs(args: &InitArgs) -> Result<CollectedInputs> {
    let theme = ColorfulTheme::default();
    let interactive = !args.yes && dialoguer::console::Term::stderr().is_term();

    let config_dir = resolve_config_dir(args, interactive, &theme)?;
    let existing = load_existing_defaults(&config_dir)?;

    let mode = match (&args.mode, &existing.mode) {
        (Some(m), _) => m.clone(),
        (None, Some(m)) if !interactive => m.clone(),
        (None, Some(m)) if interactive => prompt_mode_with_default(&theme, m)?,
        (None, _) if interactive => prompt_mode_with_default(&theme, &Mode::AgentLocal)?,
        (None, _) => Mode::AgentLocal,
    };
    let keep_local_authority =
        confirm_keep_local_authority(args, &existing, &mode, interactive, &theme)?;
    let agent_id = collect_agent_id(args, &existing, &mode, interactive, &theme)?;

    let state_dir =
        resolve_state_dir_with_default(args.state_dir.clone(), existing.state_dir.clone())
            .map_err(anyhow::Error::msg)?;
    let state_dir = std::path::absolute(&state_dir)
        .with_context(|| format!("resolve path {}", state_dir.display()))?;

    let authority =
        collect_authority_inputs(args, &existing, &mode, interactive, &theme, &state_dir)?;

    let profile = collect_profile(args, &existing, interactive, &theme)?;

    let sidecar = collect_sidecar_inputs(
        args,
        &existing,
        &mode,
        interactive,
        &theme,
        &config_dir,
        &profile,
    )?;
    let reset_remote_connection = matches!(mode, Mode::AgentLocal)
        && (matches!(existing.mode, Some(Mode::AgentRemote))
            || existing
                .authority_url
                .as_deref()
                .is_some_and(|old| !same_authority_endpoint(old, &authority.connect_url)));
    // Remote mode never collects a mapping selection: `collect_sidecar_inputs`
    // rejects `--mapping` there, so a kept local Authority list must survive
    // rather than be clobbered with just the primary. Local modes re-derive the
    // existing selection when none is requested, so rewriting keeps authored
    // paths and normalizes duplicate entries.
    let preserve_authority_mappings = matches!(mode, Mode::AgentRemote);

    Ok(CollectedInputs {
        mode,
        keep_local_authority,
        preserve_authority_mappings,
        reset_remote_connection,
        authority,
        sidecar,
        config_dir,
        state_dir,
        agent_id,
        profile,
    })
}

fn has_server(inputs: &CollectedInputs) -> bool {
    inputs.keep_local_authority || matches!(inputs.mode, Mode::AgentLocal | Mode::Authority)
}

/// Decide whether to retain the existing local `[authority]` section
/// when the operator is switching to `agent-remote`.
///
/// The `toml_edit` merge layer is non-destructive: switching modes patches
/// the relevant schema-valid sections in place, so there is no
/// "overwrite this file?" gate anymore. The only remaining decision is
/// whether the user wants the previously-configured local Mini Authority
/// to keep autostarting even though the sidecar is now configured to
/// reach a remote URL (an unusual but supported deployment).
fn confirm_keep_local_authority(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    mode: &Mode,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<bool> {
    if args.force {
        return Ok(false);
    }
    if !matches!(existing.mode, Some(Mode::AgentLocal | Mode::Authority))
        || !matches!(mode, Mode::AgentRemote)
    {
        return Ok(false);
    }

    crate::output::warn(
        "this configuration includes a local [authority] section. If you keep it, firma run starts the Authority locally instead of using only the remote Authority.",
    );
    if !interactive || args.dry_run {
        return Ok(false);
    }
    dialoguer::Confirm::with_theme(theme)
        .with_prompt("Keep the local [authority] section and local Authority startup?")
        .default(false)
        .interact()
        .context("authority section prompt")
}

fn resolve_config_dir(
    args: &InitArgs,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<PathBuf> {
    if let Some(p) = &args.output_dir {
        return std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()));
    }

    let default = firma_config_loader::ConfigResolver::default()
        .resolve_config(None)?
        .map_or_else(default_output_dir, |resolved| resolved.config_dir());

    if interactive {
        let s: String = dialoguer::Input::with_theme(theme)
            .with_prompt("Config directory")
            .default(default.to_string_lossy().into_owned())
            .interact_text()
            .context("config directory prompt")?;
        return std::path::absolute(PathBuf::from(s)).context("resolve config directory path");
    }

    Ok(default)
}

fn load_existing_defaults(config_dir: &Path) -> Result<ExistingConfigDefaults> {
    let firma_toml = config_dir.join(firma_config_loader::CONFIG_FILE_NAME);
    if !firma_toml.exists() {
        return Ok(ExistingConfigDefaults::default());
    }

    let text = fs::read_to_string(&firma_toml)
        .with_context(|| format!("read existing config {}", firma_toml.display()))?;
    let value: toml::Value = toml::from_str(&text)
        .with_context(|| format!("parse existing config {}", firma_toml.display()))?;
    let mut defaults = ExistingConfigDefaults {
        exists: true,
        ..ExistingConfigDefaults::default()
    };

    let has_server = value
        .get("authority")
        .and_then(toml::Value::as_table)
        .is_some();
    let has_connect = value
        .get("sidecar")
        .and_then(|v| v.get("authority"))
        .and_then(toml::Value::as_table)
        .is_some_and(|t| t.contains_key("url"));
    let has_sidecar = value
        .get("sidecar")
        .and_then(toml::Value::as_table)
        .is_some();
    defaults.mode = match (has_server, has_connect, has_sidecar) {
        (true, _, true) => Some(Mode::AgentLocal),
        (false, true, true) => Some(Mode::AgentRemote),
        (true, _, false) => Some(Mode::Authority),
        _ => None,
    };

    defaults.authority_listen = get_str(&value, &["authority", "listen_addr"]).or_else(|| {
        has_server.then(|| firma_config_schema::authority::AuthorityConfig::default().listen_addr)
    });
    defaults.authority_url = get_str(&value, &["sidecar", "authority", "url"]);
    // `firma config` writes a single CA; a hand-edited list is offered by its
    // first entry.
    let ca_cert_paths = ["sidecar", "authority", "ca_cert_paths"]
        .iter()
        .try_fold(&value, |current, key| current.get(key))
        .and_then(toml::Value::as_array);
    defaults.authority_ca_cert = ca_cert_paths
        .and_then(|paths| paths.first())
        .and_then(toml::Value::as_str)
        .map(PathBuf::from);
    if let Some(paths) = ca_cert_paths.filter(|paths| paths.len() > 1) {
        crate::output::warn(format!(
            "[sidecar.authority].ca_cert_paths lists {} CAs; firma config writes a single CA and drops the others",
            paths.len()
        ));
    }
    defaults.authority_pub_key = get_path(&value, &["sidecar", "authority", "public_key_path"]);
    defaults.posture = posture_from_policy_dir(config_dir);
    defaults.mappings = mappings_from_rules_paths(&value, config_dir);
    defaults.state_dir = infer_state_dir(&value);

    defaults.workspace = workspace_from_firma_toml(&value);
    defaults.profile = get_str(&value, &["run", "profile"]);
    if let Some(raw) = get_str(&value, &["sidecar", "authority", "agent_id"]) {
        match raw.parse() {
            Ok(agent_id) => defaults.agent_id = Some(agent_id),
            Err(_) => defaults.invalid_agent_id = Some(raw),
        }
    }

    Ok(defaults)
}

fn collect_agent_id(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    mode: &Mode,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<Option<AgentId>> {
    if matches!(mode, Mode::Authority) {
        return Ok(None);
    }
    if let Some(invalid_agent_id) = &existing.invalid_agent_id {
        anyhow::bail!(
            "existing [sidecar.authority].agent_id {invalid_agent_id:?} is not a valid agent TypeID"
        );
    }
    if let Some(agent_id) = args.agent_id {
        return Ok(Some(agent_id));
    }
    if let Some(agent_id) = existing.agent_id {
        return Ok(Some(agent_id));
    }
    if existing.exists {
        anyhow::bail!(
            "existing config has no [sidecar.authority].agent_id; re-run firma config with --agent-id <AGENT_ID>"
        );
    }
    if matches!(mode, Mode::AgentLocal) {
        return Ok(Some(AgentId::generate()));
    }
    if interactive {
        let raw: String = dialoguer::Input::with_theme(theme)
            .with_prompt("Authority-registered agent TypeID")
            .interact_text()
            .context("agent ID prompt")?;
        let agent_id = raw
            .trim()
            .parse()
            .context("agent ID must be a valid `agt` TypeID backed by UUIDv7")?;
        return Ok(Some(agent_id));
    }
    anyhow::bail!("--agent-id <AGENT_ID> is required when --mode agent-remote")
}

fn get_str(value: &toml::Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn get_path(value: &toml::Value, path: &[&str]) -> Option<PathBuf> {
    get_str(value, path).map(PathBuf::from)
}

/// Infer the active posture from the policy files present in `config_dir/policies/`.
///
/// Checks for the presence of each posture's cedar file in order of
/// specificity. Returns `None` when the directory is absent or no
/// recognised posture file is found, which causes the interactive prompt
/// (or the CLI `--posture` flag) to take over.
fn posture_from_policy_dir(config_dir: &Path) -> Option<Posture> {
    let policies_dir = config_dir.join("policies");
    for posture in [Posture::DevWithDeleteWatch, Posture::Dev, Posture::Strict] {
        let path = policies_dir.join(format!("{}.cedar", posture.file_name()));
        if path.exists() {
            return Some(posture);
        }
    }
    None
}

fn mappings_from_rules_paths(value: &toml::Value, config_dir: &Path) -> Option<Vec<Mapping>> {
    let paths = value
        .get("authority")?
        .get("mapping_rules_paths")?
        .as_array()?;
    let mut mappings: Vec<Mapping> = Vec::new();
    for path in paths {
        let Some(path) = path.as_str() else {
            continue;
        };
        if let Some(mapping) = shipped_mapping_path(config_dir, path)
            && !mappings
                .iter()
                .any(|existing| existing.as_str() == mapping.as_str())
        {
            mappings.push(mapping);
        }
    }
    Some(mappings)
}

/// Recognize any spelling of the generated path, never a custom same-basename file.
fn shipped_mapping_path(config_dir: &Path, path: &str) -> Option<Mapping> {
    let stem = Path::new(path).file_stem()?.to_str()?;
    let mapping = Mapping::from_str(stem, true).ok()?;
    let generated = format!("mappings/{}.toml", mapping.as_str());
    (resolve_mapping_path(config_dir, path) == resolve_mapping_path(config_dir, &generated))
        .then_some(mapping)
}

/// The file a `mapping_rules_paths` entry names, for comparing spellings.
fn resolve_mapping_path(config_dir: &Path, path: &str) -> PathBuf {
    let path = config_dir.join(path);
    path.canonicalize()
        .unwrap_or_else(|_| firma_fs::normalize_absolute_path(&path))
}

fn infer_state_dir(value: &toml::Value) -> Option<PathBuf> {
    for path in [
        get_path(value, &["authority", "key_file"]),
        get_path(value, &["authority", "revocation_file"]),
        get_path(value, &["sidecar", "audit", "file_path"]),
        get_path(value, &["sidecar", "audit", "signing_key_path"]),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(parent) = path.parent() {
            return Some(parent.to_path_buf());
        }
    }

    get_path(value, &["sidecar", "ca", "dir"]).and_then(|path| path.parent().map(Path::to_path_buf))
}

fn workspace_from_firma_toml(value: &toml::Value) -> Option<PathBuf> {
    let mounts = value
        .get("run")?
        .get("profiles")?
        .get("generic")?
        .get("mounts")?
        .as_array()?;
    for mount in mounts {
        if mount.get("read_only").and_then(toml::Value::as_bool) == Some(false)
            && let Some(src) = mount.get("source").and_then(toml::Value::as_str)
        {
            return Some(PathBuf::from(src));
        }
    }
    None
}

fn collect_local_connect_inputs(
    listen: &str,
    state_dir: &Path,
) -> (String, Option<String>, String) {
    let url = format!("https://{listen}");
    let pub_key = RuntimeLayout::from_root(state_dir)
        .authority_public_key()
        .to_string_lossy()
        .into_owned();
    // A local Authority's CA is adopted from the state directory, so none is
    // written.
    (url, None, pub_key)
}

fn collect_authority_inputs(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    mode: &Mode,
    interactive: bool,
    theme: &ColorfulTheme,
    state_dir: &Path,
) -> Result<AuthorityInputs> {
    let listen = match (args.authority_listen.as_deref(), mode) {
        (Some(addr), _) => addr.to_string(),
        (None, _) if existing.authority_listen.is_some() && !interactive => {
            existing.authority_listen.clone().unwrap_or_default()
        }
        (None, Mode::Authority) if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Authority listen address")
            .default(
                existing
                    .authority_listen
                    .clone()
                    .unwrap_or_else(|| "0.0.0.0:50051".to_string()),
            )
            .interact_text()
            .context("authority listen address prompt")?,
        (None, Mode::AgentLocal) if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Authority listen address")
            .default(
                existing
                    .authority_listen
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:50051".to_string()),
            )
            .interact_text()
            .context("authority listen address prompt")?,
        _ => "127.0.0.1:50051".to_string(),
    };

    let (connect_url, connect_ca_cert, connect_pub_key) = match mode {
        Mode::AgentLocal => collect_local_connect_inputs(&listen, state_dir),
        Mode::AgentRemote => collect_remote_connect_inputs(args, existing, interactive, theme)?,
        Mode::Authority => (String::new(), None, String::new()),
    };

    Ok(AuthorityInputs {
        listen,
        connect_url,
        connect_ca_cert,
        connect_pub_key,
    })
}

fn collect_workspace(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<PathBuf> {
    if let Some(p) = &args.workspace {
        return std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()));
    }
    if let Some(p) = &existing.workspace
        && !interactive
    {
        return Ok(p.clone());
    }
    let cwd = std::env::current_dir().context("get current directory")?;
    if !interactive {
        return Ok(cwd);
    }
    let default_path = existing.workspace.as_ref().unwrap_or(&cwd);
    let default = default_path.to_string_lossy().into_owned();
    let s: String = dialoguer::Input::with_theme(theme)
        .with_prompt("Workspace directory (agent RW access)")
        .default(default)
        .interact_text()
        .context("workspace prompt")?;
    let p = PathBuf::from(s);
    std::path::absolute(&p).with_context(|| format!("resolve path {}", p.display()))
}

fn collect_sidecar_inputs(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    mode: &Mode,
    interactive: bool,
    theme: &ColorfulTheme,
    config_dir: &Path,
    profile: &str,
) -> Result<SidecarInputs> {
    let overwrite_policy = args.posture.is_some() || interactive;
    let posture = match (&args.posture, &existing.posture) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) if !interactive => p.clone(),
        (None, Some(p)) if interactive => prompt_posture_with_default(theme, p)?,
        (None, _) if interactive => prompt_posture_with_default(theme, &Posture::Dev)?,
        (None, _) => Posture::Dev,
    };

    if matches!(mode, Mode::AgentRemote) && (!args.mapping.is_empty() || args.extra_hosts.is_some())
    {
        anyhow::bail!(
            "--mapping and --extra-hosts are local Authority options; manage remote Authority mappings centrally"
        );
    }
    if matches!(mode, Mode::AgentRemote) {
        return Ok(SidecarInputs {
            posture,
            overwrite_policy,
            mappings: vec![],
            extra_hosts: vec![],
            workspace: collect_workspace(args, existing, interactive, theme)?,
        });
    }

    let profile_default_mappings = profile_default_mappings(profile);
    let mappings = if !args.mapping.is_empty() {
        args.mapping.clone()
    } else if let Some(mappings) = &existing.mappings
        && !interactive
    {
        mappings.clone()
    } else if interactive {
        let mapping_default = existing
            .mappings
            .as_deref()
            .unwrap_or(&profile_default_mappings);
        prompt_mappings_with_default(theme, Some(mapping_default))?
    } else {
        profile_default_mappings
    };

    let extra_hosts_raw: String = match args.extra_hosts.as_deref() {
        Some(v) => v.to_string(),
        None if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Extra hosts (comma-separated, blank for none)")
            .allow_empty(true)
            .interact_text()
            .context("extra hosts prompt")?,
        None => String::new(),
    };
    let extra_hosts: Vec<String> = extra_hosts_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    // The Authority is the only mapping consumer, so a standalone Authority
    // scaffold publishes the selection too; only its workspace is moot.
    let workspace = if matches!(mode, Mode::Authority) {
        config_dir.to_path_buf()
    } else {
        collect_workspace(args, existing, interactive, theme)?
    };

    Ok(SidecarInputs {
        posture,
        overwrite_policy,
        mappings,
        extra_hosts,
        workspace,
    })
}

fn mode_name(m: &Mode) -> &'static str {
    match m {
        Mode::AgentLocal => "agent-local",
        Mode::AgentRemote => "agent-remote",
        Mode::Authority => "authority",
    }
}

fn prompt_mode_with_default(theme: &ColorfulTheme, default: &Mode) -> Result<Mode> {
    let variants = Mode::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|m| format!("{:<16}  {}", mode_name(m), m.description()))
        .collect();
    let selection = dialoguer::Select::with_theme(theme)
        .with_prompt("What are you configuring?")
        .items(&items)
        .default(
            variants
                .iter()
                .position(|m| mode_name(m) == mode_name(default))
                .unwrap_or(0),
        )
        .report(false)
        .interact()
        .context("mode prompt")?;
    let chosen = variants[selection].clone();
    eprintln!("  Mode     · {}", mode_name(&chosen));
    Ok(chosen)
}

fn prompt_posture_with_default(theme: &ColorfulTheme, default: &Posture) -> Result<Posture> {
    let variants = Posture::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|p| format!("{:<24}  {}", p.file_name(), p.description()))
        .collect();
    let selection = dialoguer::Select::with_theme(theme)
        .with_prompt("Posture")
        .items(&items)
        .default(
            variants
                .iter()
                .position(|p| p.file_name() == default.file_name())
                .unwrap_or(1),
        )
        .report(false)
        .interact()
        .context("posture prompt")?;
    let chosen = variants[selection].clone();
    eprintln!("  Posture  · {}", chosen.file_name());
    Ok(chosen)
}

fn prompt_mappings_with_default(
    theme: &ColorfulTheme,
    default: Option<&[Mapping]>,
) -> Result<Vec<Mapping>> {
    let variants = Mapping::CONFIG_CHOICES;
    let items: Vec<String> = variants
        .iter()
        .map(|m| format!("{:<12}  {}", m.as_str(), m.description()))
        .collect();
    let defaults: Vec<bool> = variants
        .iter()
        .map(|m| {
            default.map_or_else(
                || matches!(m, Mapping::Anthropic),
                |selected| selected.iter().any(|d| d.as_str() == m.as_str()),
            )
        })
        .collect();
    let selections = dialoguer::MultiSelect::with_theme(theme)
        .with_prompt("Mappings (space to toggle, enter to confirm)")
        .items(&items)
        .defaults(&defaults)
        .report(false)
        .interact()
        .context("mappings prompt")?;
    let chosen: Vec<Mapping> = selections
        .into_iter()
        .map(|i| variants[i].clone())
        .collect();
    eprintln!(
        "  Mappings · {}",
        chosen
            .iter()
            .map(Mapping::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(chosen)
}

fn collect_profile(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<String> {
    if let Some(p) = &args.profile {
        return Ok(p.as_str().to_string());
    }
    let default = existing
        .profile
        .as_deref()
        .and_then(AgentProfile::from_name)
        .unwrap_or(AgentProfile::Generic);
    if interactive {
        prompt_profile_with_default(theme, default)
    } else {
        Ok(default.as_str().to_string())
    }
}

fn prompt_profile_with_default(theme: &ColorfulTheme, default: AgentProfile) -> Result<String> {
    let variants = config_profile_choices();
    let items: Vec<String> = variants
        .iter()
        .map(|p| format!("{:<16}  {}", p.as_str(), p.description()))
        .collect();
    let selection = dialoguer::Select::with_theme(theme)
        .with_prompt("Agent profile")
        .items(&items)
        .default(
            variants
                .iter()
                .position(|p| p.as_str() == default.as_str())
                .unwrap_or(0),
        )
        .report(false)
        .interact()
        .context("profile prompt")?;
    let chosen = variants[selection].as_str().to_string();
    eprintln!("  Profile  · {chosen}");
    Ok(chosen)
}

fn config_profile_choices() -> &'static [AgentProfile] {
    &[
        AgentProfile::ClaudeCode,
        AgentProfile::Codex,
        AgentProfile::Copilot,
        AgentProfile::Generic,
        AgentProfile::Vscode,
    ]
}

/// Mappings a profile selects when the operator names none.
///
/// `vscode` takes `github` as well: the `vscode` mapping reaches github.com and
/// api.github.com but deliberately leaves their endpoints to `github`, which
/// classifies each one. Without it every decrypted repository request is denied
/// as unclassified, because interception is on for every host.
fn profile_default_mappings(profile: &str) -> Vec<Mapping> {
    match profile {
        "codex" => vec![Mapping::Openai, Mapping::Github],
        "copilot" => vec![Mapping::Copilot],
        "vscode" => vec![Mapping::Vscode, Mapping::Github],
        _ => vec![Mapping::Anthropic],
    }
}

/// Delete posture cedar files left behind by previous postures.
///
/// Each posture lives in its own file under `policies/`, so when the
/// operator switches posture the old file lingers and the sidecar
/// (which loads every `.cedar` in the dir) ends up applying both.
/// Remove stale posture files here.
///
/// Pristine files (content matches the shipped template) are deleted
/// silently. Files with local edits are kept by default; in
/// interactive mode the user is asked. `--force` removes everything.
fn cleanup_stale_posture_files(
    cfg: &Path,
    active: &Posture,
    interactive: bool,
    force: bool,
    theme: &ColorfulTheme,
) -> Result<()> {
    let policies_dir = cfg.join("policies");
    for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
        if posture.file_name() == active.file_name() {
            continue;
        }
        let path = policies_dir.join(format!("{}.cedar", posture.file_name()));
        if !path.exists() {
            continue;
        }
        let current =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let pristine = posture.cedar_content();
        let modified = current.trim() != pristine.trim();
        if force || !modified {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
            println!("  removed stale posture file {}", path.display());
            continue;
        }
        if interactive {
            let prompt = format!(
                "Old posture file {} has local edits. Remove?",
                path.display()
            );
            let confirmed = dialoguer::Confirm::with_theme(theme)
                .with_prompt(prompt)
                .default(false)
                .interact()
                .context("posture cleanup prompt")?;
            if confirmed {
                fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
                println!("  removed {}", path.display());
            } else {
                crate::output::warn(format!(
                    "kept {} — sidecar will load it alongside the active posture",
                    path.display()
                ));
            }
        } else {
            crate::output::warn(format!(
                "kept {} (locally modified) — pass --force to delete",
                path.display()
            ));
        }
    }
    Ok(())
}

// ── Public API used by `firma run` implicit init and other services ───────────

/// Resolved scaffold parameters. Used by `firma run` for implicit init.
#[derive(Debug, Clone)]
pub struct ScaffoldPlan {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub workspace: PathBuf,
    pub force: bool,
    pub authority_listen: String,
    pub agent_id: AgentId,
    pub agent: String,
    pub provider: String,
    pub authority: AuthorityShape,
}

/// Authority deployment shape for `ScaffoldPlan`.
#[derive(Debug, Clone)]
pub enum AuthorityShape {
    Local,
}

/// Resolve the runtime state directory.
///
/// Priority: explicit flag → `FIRMA_STATE_DIR` env → platform default.
///
/// # Errors
/// Returns a formatted error string on resolution failure.
pub fn resolve_state_dir(flag: Option<PathBuf>) -> Result<PathBuf, String> {
    resolve_state_dir_with_default(flag, None)
}

/// Resolve the audit log path for `firma monitor`.
///
/// Priority: explicit `--state-dir` → `sidecar.audit.file_path` from a
/// discovered `firma.toml` → `<state_dir>/audit.jsonl`.
///
/// Relative config paths are resolved from the directory containing the
/// selected `firma.toml`.
pub fn resolve_audit_log_path(
    state_dir_flag: Option<&PathBuf>,
    config_override: Option<&Path>,
) -> Result<PathBuf, String> {
    let state_dir = resolve_state_dir(state_dir_flag.cloned())?;
    if state_dir_flag.is_some() {
        return Ok(RuntimeLayout::from_root(state_dir).audit_log());
    }

    if let Some(resolved) = firma_config_loader::ConfigResolver::default()
        .resolve_config(config_override)
        .map_err(|error| format!("resolve discovered config: {error}"))?
        && let Ok(body) = resolved.config.raw_section("sidecar.audit")
    {
        let value: toml::Value = toml::from_str(&body).map_err(|error| {
            format!(
                "parse discovered audit config {}: {error}",
                resolved.config_file().display()
            )
        })?;
        if let Some(path) = value
            .get("file_path")
            .and_then(toml::Value::as_str)
            .filter(|path| !path.is_empty())
        {
            return Ok(resolve_config_relative_path(&resolved.config_dir(), path));
        }
    }

    Ok(RuntimeLayout::from_root(state_dir).audit_log())
}

fn resolve_config_relative_path(config_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

/// Warn when the material is being written somewhere the processes will not
/// look by default.
///
/// `firma.toml` no longer carries artifact paths, so nothing in the generated
/// file points at a custom state directory. The Authority and Sidecar resolve
/// it from `FIRMA_STATE_DIR` or the platform runtime directory, and a config
/// scaffolded elsewhere fails at startup on material it cannot find.
///
/// Both roots are compared absolute: the resolved default always is, while
/// `--state-dir` and `FIRMA_STATE_DIR` are taken verbatim, so a relative form
/// of the very directory the processes will use must not warn.
fn warn_on_non_default_state_dir(state_dir: &Path) {
    let (Ok(default), Ok(state_dir)) = (
        firma_runtime_state::resolve_state_dir(None),
        std::path::absolute(state_dir),
    ) else {
        return;
    };
    if state_dir == default {
        return;
    }
    crate::output::warn(format!(
        "state dir {} is not the default {}; export FIRMA_STATE_DIR={} so the \
         Authority and Sidecar resolve the material generated here",
        state_dir.display(),
        default.display(),
        state_dir.display()
    ));
}

fn resolve_state_dir_with_default(
    flag: Option<PathBuf>,
    default: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(path) = flag {
        return Ok(path);
    }
    if let Some(path) = default {
        return Ok(path);
    }
    if let Ok(env) = std::env::var("FIRMA_STATE_DIR")
        && !env.is_empty()
    {
        return Ok(PathBuf::from(env));
    }
    firma_runtime_state::resolve_state_dir(None).map_err(|error| format!("state_dir: {error}"))
}

/// Scaffold from an already-resolved plan. Called by `firma run` on first use
/// when no `firma.toml` is discoverable.
///
/// # Errors
/// Returns a formatted string on any filesystem or key-generation failure.
pub fn scaffold_from_plan(plan: &ScaffoldPlan) -> Result<()> {
    let mappings = provider_to_mappings(&plan.provider);
    let authority_layout = RuntimeLayout::from_root(&plan.state_dir);
    let (mode, authority) = match &plan.authority {
        AuthorityShape::Local => {
            let (connect_url, connect_ca_cert, connect_pub_key) =
                collect_local_connect_inputs(&plan.authority_listen, &plan.state_dir);
            (
                Mode::AgentLocal,
                AuthorityInputs {
                    listen: plan.authority_listen.clone(),
                    connect_url,
                    connect_ca_cert,
                    connect_pub_key,
                },
            )
        }
    };
    let inputs = CollectedInputs {
        mode,
        keep_local_authority: false,
        preserve_authority_mappings: false,
        reset_remote_connection: false,
        authority,
        sidecar: SidecarInputs {
            posture: Posture::Dev,
            overwrite_policy: false,
            mappings,
            extra_hosts: vec![],
            workspace: plan.workspace.clone(),
        },
        config_dir: plan.config_dir.clone(),
        state_dir: plan.state_dir.clone(),
        agent_id: Some(plan.agent_id),
        profile: firma_config_loader::AgentProfile::from_name(&plan.agent).map_or_else(
            || provider_to_profile(&plan.provider),
            |p| p.as_str().to_string(),
        ),
    };
    let files = generate_files(&inputs).context("generate files")?;

    for dir in [
        plan.config_dir.as_path(),
        &plan.config_dir.join("policies"),
        &plan.config_dir.join("issuance-policies"),
        &plan.config_dir.join("mappings"),
        authority_layout.root(),
        &authority_layout.generated_ca_dir(),
    ] {
        create_private_dir_all(dir)?;
    }

    for (rel, content) in &files {
        let path = plan.config_dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        if !plan.force && path.exists() {
            continue;
        }
        fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    }

    write_revocations(&authority_layout, plan.force)?;
    crate::services::authority::generate_audit_key_if_absent(
        &authority_layout.audit_key(),
        plan.force,
    )?;

    let key_path = authority_layout.authority_key();
    if plan.force || !key_path.exists() {
        crate::services::authority::run_generate_key(&key_path)?;
    }

    let tls_dir = authority_layout.tls_dir();
    if plan.force && tls_dir.exists() {
        for p in tls_files(&authority_layout) {
            if p.exists() {
                fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            }
        }
    }
    if !authority_layout.authority_tls_certificate().exists() {
        crate::services::authority::run_bootstrap_tls(&tls_dir, &[])
            .context("generate TLS material")?;
    }

    Ok(())
}

fn provider_to_mappings(provider: &str) -> Vec<Mapping> {
    match provider {
        "openai" => vec![Mapping::Openai],
        "github" => vec![Mapping::Copilot],
        // Pairs with `profile_default_mappings`: `github` classifies the
        // repository endpoints the `vscode` mapping only tunnels.
        "vscode" => vec![Mapping::Vscode, Mapping::Github],
        _ => vec![Mapping::Anthropic],
    }
}

fn provider_to_profile(provider: &str) -> String {
    use firma_config_loader::AgentProfile;
    match provider {
        p if AgentProfile::Codex.provider() == p => AgentProfile::Codex.as_str().to_string(),
        p if AgentProfile::ClaudeCode.provider() == p => {
            AgentProfile::ClaudeCode.as_str().to_string()
        }
        p if AgentProfile::Copilot.provider() == p => AgentProfile::Copilot.as_str().to_string(),
        p if AgentProfile::Vscode.provider() == p => AgentProfile::Vscode.as_str().to_string(),
        _ => AgentProfile::Generic.as_str().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use firma_core::normalize_mapping_host;
    use firma_http::Method;
    use strum::IntoEnumIterator;

    use super::*;

    const TEST_WORKSPACE: &str = "/tmp/test-workspace";

    #[test]
    fn copilot_profile_scaffolds_copilot_mapping_and_bypass() {
        assert_eq!(
            super::profile_default_mappings("copilot")
                .iter()
                .map(Mapping::as_str)
                .collect::<Vec<_>>(),
            vec!["copilot"]
        );
        assert_eq!(super::provider_to_profile("github"), "copilot");
        assert_eq!(
            super::provider_to_mappings("github")
                .iter()
                .map(Mapping::as_str)
                .collect::<Vec<_>>(),
            vec!["copilot"]
        );
    }

    #[test]
    fn codex_profile_scaffolds_openai_and_github_mappings() {
        assert_eq!(
            super::profile_default_mappings("codex")
                .iter()
                .map(Mapping::as_str)
                .collect::<Vec<_>>(),
            vec!["openai", "github"]
        );
    }

    #[test]
    fn vscode_profile_scaffolds_vscode_and_github_mappings() {
        assert_eq!(
            super::profile_default_mappings("vscode")
                .iter()
                .map(Mapping::as_str)
                .collect::<Vec<_>>(),
            vec!["vscode", "github"]
        );
        assert_eq!(super::provider_to_profile("vscode"), "vscode");
        assert_eq!(
            super::provider_to_mappings("vscode")
                .iter()
                .map(Mapping::as_str)
                .collect::<Vec<_>>(),
            vec!["vscode", "github"]
        );
    }

    fn make_files(
        posture: &Posture,
        mappings: &[Mapping],
        extra_hosts: &[String],
    ) -> Vec<(String, String)> {
        let inputs = CollectedInputs {
            mode: Mode::AgentLocal,
            keep_local_authority: false,
            preserve_authority_mappings: false,
            reset_remote_connection: false,
            authority: AuthorityInputs {
                listen: "127.0.0.1:50051".to_string(),
                connect_url: "http://127.0.0.1:50051".to_string(),
                connect_ca_cert: None,
                connect_pub_key: "/tmp/test-state/authority.pub".to_string(),
            },
            sidecar: SidecarInputs {
                posture: posture.clone(),
                overwrite_policy: false,
                mappings: mappings.to_vec(),
                extra_hosts: extra_hosts.to_vec(),
                workspace: PathBuf::from(TEST_WORKSPACE),
            },
            config_dir: PathBuf::from(TEST_WORKSPACE),
            state_dir: PathBuf::from("/tmp/test-state"),
            agent_id: Some("agt_01j0000000e008000000000001".parse().unwrap()),
            profile: "generic".to_string(),
        };
        generate_files(&inputs).unwrap()
    }

    fn make_inputs(mappings: &[Mapping], config_dir: PathBuf) -> CollectedInputs {
        CollectedInputs {
            mode: Mode::AgentLocal,
            keep_local_authority: false,
            preserve_authority_mappings: false,
            reset_remote_connection: false,
            authority: AuthorityInputs {
                listen: "127.0.0.1:50051".to_string(),
                connect_url: "http://127.0.0.1:50051".to_string(),
                connect_ca_cert: None,
                connect_pub_key: "/tmp/test-state/authority.pub".to_string(),
            },
            sidecar: SidecarInputs {
                posture: Posture::Dev,
                overwrite_policy: false,
                mappings: mappings.to_vec(),
                extra_hosts: Vec::new(),
                workspace: PathBuf::from(TEST_WORKSPACE),
            },
            config_dir,
            state_dir: PathBuf::from("/tmp/test-state"),
            agent_id: Some("agt_01j0000000e008000000000001".parse().unwrap()),
            profile: "generic".to_string(),
        }
    }

    fn write_mapping(cfg: &Path, mapping: &Mapping, content: &str) {
        let dir = cfg.join("mappings");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{}.toml", mapping.as_str())), content).unwrap();
    }

    /// A directory scaffolded before interception became the default keeps its
    /// CONNECT-only mapping, because mapping files are replaced only under
    /// `--force`. Leaving it would deny every decrypted request on those hosts,
    /// so the re-run moves it aside and lets the shipped mapping be written.
    #[test]
    fn a_connect_only_mapping_left_on_disk_is_upgraded() {
        let dir = tempfile::tempdir().unwrap();
        let previous = "[[rules]]\nmethod = \"CONNECT\"\nhost = \"api.anthropic.com\"\n\
                        action_class = \"communication.external.send\"\n";
        write_mapping(dir.path(), &Mapping::Anthropic, previous);
        let inputs = make_inputs(&[Mapping::Anthropic], dir.path().to_path_buf());

        upgrade_connect_only_mappings(dir.path(), &inputs, false).unwrap();

        let mappings = dir.path().join("mappings");
        assert!(
            !mappings.join("anthropic.toml").exists(),
            "the incompatible file must make way for the shipped mapping"
        );
        assert_eq!(
            fs::read_to_string(mappings.join("anthropic.toml.bak")).unwrap(),
            previous,
            "the displaced file keeps the operator's rules"
        );
    }

    /// `--force` rewrites every scaffold file, so nothing is displaced.
    #[test]
    fn a_forced_rerun_leaves_the_upgrade_to_the_scaffold_write() {
        let dir = tempfile::tempdir().unwrap();
        write_mapping(
            dir.path(),
            &Mapping::Anthropic,
            "[[rules]]\nmethod = \"CONNECT\"\nhost = \"api.anthropic.com\"\n\
             action_class = \"communication.external.send\"\n",
        );
        let inputs = make_inputs(&[Mapping::Anthropic], dir.path().to_path_buf());

        upgrade_connect_only_mappings(dir.path(), &inputs, true).unwrap();

        assert!(dir.path().join("mappings/anthropic.toml").exists());
        assert!(!dir.path().join("mappings/anthropic.toml.bak").exists());
    }

    #[test]
    fn a_bypassed_connect_only_host_is_left_alone() {
        // The `copilot` mapping classifies the GitHub hosts at CONNECT level on
        // purpose and exempts them from interception, so they are never
        // decrypted and need no rule.
        let dir = tempfile::tempdir().unwrap();
        write_mapping(
            dir.path(),
            &Mapping::Copilot,
            "[[rules]]\nmethod = \"CONNECT\"\nhost = \"api.github.com\"\n\
             action_class = \"code.write\"\n",
        );
        let inputs = make_inputs(&[Mapping::Copilot], dir.path().to_path_buf());

        upgrade_connect_only_mappings(dir.path(), &inputs, false).unwrap();

        assert!(dir.path().join("mappings/copilot.toml").exists());
        assert!(!dir.path().join("mappings/copilot.toml.bak").exists());
    }

    /// The shipped mappings are what a re-run would write, so none of them may
    /// trip the upgrade.
    #[test]
    fn the_shipped_mappings_are_accepted_as_they_are() {
        let dir = tempfile::tempdir().unwrap();
        for mapping in Mapping::iter() {
            write_mapping(dir.path(), &mapping, mapping.static_content());
        }
        let inputs = make_inputs(
            &Mapping::iter().collect::<Vec<_>>(),
            dir.path().to_path_buf(),
        );

        upgrade_connect_only_mappings(dir.path(), &inputs, false).unwrap();
        for mapping in Mapping::iter() {
            assert!(
                !dir.path()
                    .join(format!("mappings/{}.toml.bak", mapping.as_str()))
                    .exists(),
                "{} must not be displaced",
                mapping.as_str()
            );
        }
    }

    fn get<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
        files.iter().find(|(k, _)| k == name).map_or_else(
            || panic!("file {name} not found in generated output"),
            |(_, v)| v.as_str(),
        )
    }

    fn parse_rules(content: &str) -> firma_sidecar::config::MappingRulesFile {
        toml::from_str(content).unwrap()
    }

    #[test]
    fn audit_log_path_honors_explicit_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(CONFIG_FILE_NAME);
        let audit_log = dir.path().join("explicit-audit.jsonl");
        fs::write(
            &config,
            format!(
                "[sidecar.audit]\nfile_path = {:?}\n",
                audit_log.to_string_lossy()
            ),
        )
        .unwrap();

        let resolved = resolve_audit_log_path(None, Some(&config)).unwrap();

        assert_eq!(resolved, audit_log);
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    #[test]
    fn all_postures_render_without_error() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            make_files(&posture, &[], &[]);
        }
    }

    #[test]
    fn all_mappings_render_without_error() {
        let all_mappings = vec![
            Mapping::Anthropic,
            Mapping::Openai,
            Mapping::Github,
            Mapping::Gmail,
            Mapping::Npm,
            Mapping::Pypi,
            Mapping::Cargo,
            Mapping::Stripe,
            Mapping::Vscode,
        ];
        make_files(&Posture::Dev, &all_mappings, &[]);
    }

    #[test]
    fn extra_hosts_render_without_error() {
        make_files(
            &Posture::Dev,
            &[Mapping::Anthropic],
            &["api.example.com".to_string()],
        );
    }

    // ── firma.toml ───────────────────────────────────────────────────────────

    #[test]
    fn firma_toml_is_valid_toml() {
        for posture in Posture::iter() {
            let files = make_files(&posture, &[Mapping::Anthropic, Mapping::Github], &[]);
            let _: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
        }
    }

    #[test]
    fn firma_toml_parses_as_authority_config() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        fs::write(&path, get(&files, CONFIG_FILE_NAME)).unwrap();
        let body = firma_config_loader::load_section(&path, "authority").unwrap();
        firma_authority::AuthorityConfigBuilder::from_toml_str(
            &body,
            &firma_runtime_state::RuntimeLayout::from_root(dir.path()),
        )
        .unwrap()
        .without_tls()
        .build()
        .unwrap();
    }

    #[test]
    fn firma_toml_parses_as_sidecar_config() {
        for posture in [Posture::Strict, Posture::Dev] {
            for mappings in [
                vec![],
                vec![Mapping::Anthropic],
                vec![Mapping::Github, Mapping::Gmail],
            ] {
                let files = make_files(&posture, &mappings, &[]);
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join(CONFIG_FILE_NAME);
                fs::write(&path, get(&files, CONFIG_FILE_NAME)).unwrap();
                let body = firma_config_loader::load_section(&path, "sidecar").unwrap();
                let schema: firma_config_schema::sidecar::SidecarConfig =
                    toml::from_str(&body).unwrap();
                let state = firma_runtime_state::RuntimeLayout::from_root(dir.path());
                let _ = firma_sidecar::config::SidecarConfig::resolve(schema, &state).unwrap();
            }
        }
    }

    #[test]
    fn firma_toml_leaves_interception_to_the_sidecar_default() {
        // Interception is not a per-mapping selection: the sidecar intercepts
        // every host by default, so the generated config pins nothing.
        for mappings in [
            vec![Mapping::Anthropic],
            vec![Mapping::Anthropic, Mapping::Github, Mapping::Gmail],
        ] {
            let files = make_files(&Posture::Dev, &mappings, &[]);
            let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
            assert!(
                t["sidecar"]["interceptor"].get("https_mitm").is_none(),
                "{mappings:?}"
            );
        }
    }

    #[test]
    fn firma_toml_rules_paths_contains_selected_mappings() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic, Mapping::Github], &[]);
        let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
        let paths = t["authority"]["mapping_rules_paths"].as_array().unwrap();
        let path_strs: Vec<_> = paths.iter().filter_map(|v| v.as_str()).collect();
        assert!(path_strs.contains(&"mappings/anthropic.toml"));
        assert!(path_strs.contains(&"mappings/github.toml"));
    }

    #[test]
    fn firma_toml_copilot_mapping_bypasses_github_and_lists_rules_path() {
        let files = make_files(&Posture::Dev, &[Mapping::Copilot], &[]);
        let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
        let https_mitm = &t["sidecar"]["interceptor"]["https_mitm"];
        let bypass: Vec<_> = https_mitm["bypass_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(bypass.contains(&"github.com"));
        assert!(bypass.contains(&"api.github.com"));
        let paths = t["authority"]["mapping_rules_paths"].as_array().unwrap();
        assert!(
            paths
                .iter()
                .filter_map(|v| v.as_str())
                .any(|p| p == "mappings/copilot.toml")
        );
    }

    /// The `vscode` mapping leaves the GitHub endpoints to the `github`
    /// mapping, so the profile has to select both — otherwise every decrypted
    /// repository request is denied as unclassified. Neither host is exempted
    /// from interception.
    #[test]
    fn the_vscode_profile_selects_github_instead_of_exempting_it() {
        let mappings = super::profile_default_mappings("vscode");
        assert_eq!(
            mappings.iter().map(Mapping::as_str).collect::<Vec<_>>(),
            vec!["vscode", "github"]
        );
        let files = make_files(&Posture::Dev, &mappings, &[]);
        let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
        assert!(
            t["sidecar"]["interceptor"]
                .get("https_mitm")
                .is_none_or(|https| https.get("bypass_hosts").is_none()),
            "the vscode profile exempts no host: {}",
            get(&files, CONFIG_FILE_NAME)
        );
        let paths: Vec<&str> = t["authority"]["mapping_rules_paths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "mapping-rules.toml",
                "mappings/vscode.toml",
                "mappings/github.toml"
            ],
            "{paths:?}"
        );
    }

    // ── mapping-rules.toml ───────────────────────────────────────────────────

    #[test]
    fn mapping_rules_is_valid_toml() {
        let files = make_files(&Posture::Dev, &[], &[]);
        parse_rules(get(&files, "mapping-rules.toml"));
    }

    #[test]
    fn mapping_rules_has_localhost_rules() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(rules.iter().any(|r| r.host.starts_with("localhost:")));
        assert!(rules.iter().any(|r| r.host.starts_with("127.0.0.1:")));
    }

    #[test]
    fn mapping_rules_no_llm_connect_rule_in_base() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            !rules.iter().any(|r| r.host == "api.anthropic.com:443"),
            "LLM rules must be in mappings/ not in mapping-rules.toml"
        );
        assert!(
            !rules.iter().any(|r| r.host == "api.openai.com:443"),
            "LLM rules must be in mappings/ not in mapping-rules.toml"
        );
    }

    #[test]
    fn mapping_rules_extra_hosts_produce_connect_and_wildcard_rules() {
        let extra = vec!["api.example.com".to_string()];
        let files = make_files(&Posture::Dev, &[], &extra);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            rules.iter().any(|r| r.host == "api.example.com:443"
                && r.method
                    .as_ref()
                    .is_some_and(|method| *method == Method::CONNECT)),
            "CONNECT rule for extra host missing"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.example.com" && r.path.as_deref() == Some("*")),
            "wildcard GET rule for extra host missing"
        );
    }

    #[test]
    fn mapping_rules_all_rules_pass_validation() {
        let files = make_files(&Posture::Dev, &[], &["extra.host.com".to_string()]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        for rule in &rules {
            rule.validate()
                .unwrap_or_else(|e| panic!("invalid rule {:?}: {e}", rule.host));
        }
    }

    // ── Individual mapping files ──────────────────────────────────────────────

    #[test]
    fn anthropic_mapping_has_connect_rule() {
        let rules = parse_rules(Mapping::Anthropic.static_content()).rules;
        assert!(
            rules.iter().any(|r| r.host == "*.anthropic.com"
                && r.method
                    .as_ref()
                    .is_some_and(|method| *method == Method::CONNECT)),
            "expected *.anthropic.com CONNECT rule"
        );
    }

    #[test]
    fn openai_mapping_has_connect_rule() {
        let rules = parse_rules(Mapping::Openai.static_content()).rules;
        assert!(
            rules.iter().any(|r| r.host == "*.openai.com"
                && r.method
                    .as_ref()
                    .is_some_and(|method| *method == Method::CONNECT)),
            "expected *.openai.com:443 CONNECT rule"
        );
    }

    #[test]
    fn github_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Github.static_content()).rules;
        assert!(
            rules.iter().any(|r| r.host == "api.github.com"
                && r.method
                    .as_ref()
                    .is_some_and(|method| *method == Method::CONNECT)),
            "CONNECT rule missing from github mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.github.com" && r.path.is_some()),
            "REST rules missing from github mapping"
        );
    }

    #[test]
    fn gmail_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Gmail.static_content()).rules;
        assert!(
            rules.iter().any(|r| r.host == "gmail.googleapis.com"
                && r.method
                    .as_ref()
                    .is_some_and(|method| *method == Method::CONNECT)),
            "CONNECT rule missing from gmail mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "gmail.googleapis.com" && r.path.is_some()),
            "REST rules missing from gmail mapping"
        );
    }

    #[test]
    fn stripe_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Stripe.static_content()).rules;
        assert!(
            rules.iter().any(|r| r.host == "api.stripe.com:443"
                && r.method
                    .as_ref()
                    .is_some_and(|method| *method == Method::CONNECT)),
            "CONNECT rule missing from stripe mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.stripe.com" && r.path.is_some()),
            "REST rules missing from stripe mapping"
        );
    }

    /// Host patterns whose decrypted requests the `github` mapping classifies
    /// per endpoint, leaving anything it does not cover denied as unclassified.
    ///
    /// No mapping may give them a catch-all fallback: every template's rules for
    /// one host merge into a single standard set, and a catch-all there answers
    /// the endpoints `github` deliberately leaves unmatched with one coarse
    /// class. `*.github.com` is included because the matcher's wildcard spans
    /// labels, so a fallback under it also answers for the exact subdomains.
    ///
    /// uploads.github.com is included even though no mapping classifies its
    /// endpoints: it merges into the same owner set, so a catch-all for it is
    /// read as GitHub coverage it does not have.
    const GITHUB_CLASSIFIED_HOSTS: [&str; 4] = [
        "github.com",
        "*.github.com",
        "api.github.com",
        "uploads.github.com",
    ];

    /// Every CONNECT host needs a rule covering its decrypted inner requests.
    ///
    /// Interception is on for every host, so a template that classifies only the
    /// tunnel preface leaves its own traffic matching nothing — and a protected
    /// host with no matching rule is denied as unclassified. A CONNECT-only
    /// mapping therefore denies exactly the agent it was selected for, which is
    /// why this is checked for every template rather than the one that first hit
    /// it.
    #[test]
    fn every_connect_host_is_classified_after_interception() {
        for mapping in Mapping::iter() {
            let rules = parse_rules(mapping.static_content()).rules;
            let selection = mapping.as_str();
            let bypassed: Vec<String> = mapping
                .mitm_bypass_hosts()
                .iter()
                .map(|host| normalize_mapping_host(host))
                .collect();
            for rule in rules
                .iter()
                .filter(|rule| rule.method.as_ref() == Some(&Method::CONNECT))
            {
                // A CONNECT host may carry an explicit `:443`; the runtime
                // normalizes it away, so its rules are matched the same way.
                let host = normalize_mapping_host(&rule.host);
                // A host the mapping exempts is never decrypted, so the CONNECT
                // rule is the only one its traffic can match.
                if bypassed.contains(&host) {
                    continue;
                }
                let decrypted = rules.iter().filter(|other| {
                    other.method.as_ref() != Some(&Method::CONNECT)
                        && normalize_mapping_host(&other.host) == host
                });
                let catch_all = decrypted
                    .clone()
                    .find(|other| other.method.is_none() && other.path.as_deref() == Some("*"));
                if GITHUB_CLASSIFIED_HOSTS.contains(&host.as_str()) {
                    assert!(
                        catch_all.is_none(),
                        "{selection}: {host} must stay classified by the github mapping, \
                         not by a catch-all"
                    );
                    continue;
                }
                assert!(
                    decrypted.count() > 0,
                    "{selection}: no rule classifies decrypted requests to CONNECT host {host}"
                );
                // A host classified endpoint by endpoint needs no catch-all;
                // one that has it must not reclassify the host on the way.
                if let Some(catch_all) = catch_all {
                    assert_eq!(
                        catch_all.action_class, rule.action_class,
                        "{selection}: catch-all for {host} must not change the host's action class"
                    );
                }
            }
        }
    }

    #[test]
    fn vscode_mapping_has_core_connect_rules_and_copilot_hosts() {
        let rules = parse_rules(Mapping::Vscode.static_content()).rules;
        // The two github.com hosts VS Code itself reaches are named instead of
        // covered by a `*.github.com` fallback, which is what keeps every other
        // subdomain fail-closed. See `GITHUB_CLASSIFIED_HOSTS`.
        for host in ["collector.github.com", "copilot-reports.github.com"] {
            assert!(
                rules
                    .iter()
                    .any(|rule| rule.host == host && rule.path.as_deref() == Some("*")),
                "{host} needs its own fallback once *.github.com has none"
            );
        }
        for copilot_host in [
            "*.githubcopilot.com",
            "*.individual.githubcopilot.com",
            "*.business.githubcopilot.com",
            "*.enterprise.githubcopilot.com",
        ] {
            assert!(
                rules.iter().any(|rule| rule.host == copilot_host),
                "Copilot host {copilot_host} missing from vscode mapping"
            );
        }
        for agent_host in [
            "*.openai.com",
            "chatgpt.com",
            "*.anthropic.com",
            "*.claude.com",
            "*.claude.ai",
        ] {
            assert!(
                rules.iter().all(|rule| rule.host != agent_host),
                "agent host {agent_host} should be selected through its own mapping"
            );
        }
    }

    #[test]
    fn all_mapping_files_parse_and_validate() {
        for m in Mapping::iter() {
            let f = parse_rules(m.static_content());
            for rule in &f.rules {
                rule.validate()
                    .unwrap_or_else(|e| panic!("invalid rule in {}: {e}", m.as_str()));
            }
        }
    }

    // ── [run.profiles.generic] in firma.toml ─────────────────────────────────

    #[test]
    fn firma_toml_has_run_profiles_section() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
        assert!(
            t.get("run").and_then(|r| r.get("profiles")).is_some(),
            "[run.profiles] missing from firma.toml"
        );
    }

    #[test]
    fn run_profiles_workspace_mount_matches_input() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
        let mounts = t["run"]["profiles"]["generic"]["mounts"]
            .as_array()
            .unwrap();
        assert_eq!(mounts[0]["source"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["target"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["read_only"].as_bool(), Some(false));
    }

    #[test]
    fn run_profile_does_not_scaffold_capability_table() {
        // A run requests all action classes and the agent's policy set decides
        // the grant, so `firma config` writes no `[capability]` table into the
        // profile regardless of posture.
        for posture in Posture::iter() {
            let files = make_files(&posture, &[], &[]);
            let t: toml::Value = toml::from_str(get(&files, CONFIG_FILE_NAME)).unwrap();
            let profile = &t["run"]["profiles"]["generic"];
            assert!(
                profile.get("capability").is_none(),
                "posture {posture:?} must not scaffold a [capability] table: {profile:?}"
            );
        }
    }

    /// The ordinary layout — config in `<workspace>/.firma/` — needs no mount
    /// entry, because `firma run` derives exactly this workspace from the
    /// config's own location. The file must therefore carry no path from the
    /// machine that generated it.
    #[test]
    fn implicit_scaffold_omits_the_mount_it_can_derive() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("project");
        let config_dir = workspace.join(CONFIG_DIR_NAME);
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&workspace).unwrap();

        scaffold_from_plan(&ScaffoldPlan {
            config_dir: config_dir.clone(),
            state_dir,
            workspace: workspace.clone(),
            force: false,
            authority_listen: "127.0.0.1:50051".into(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            agent: "generic".into(),
            provider: "anthropic".into(),
            authority: AuthorityShape::Local,
        })
        .unwrap();

        let text = fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)).unwrap();
        let t: toml::Value = toml::from_str(&text).unwrap();
        // agent="generic" is a recognized profile → section is [run.profiles.generic]
        let profile = &t["run"]["profiles"]["generic"];
        // Absent, not empty: `firma run` merges `mounts` by replacement, so a
        // serialized `mounts = []` would clear the derived default and leave
        // the agent with no workspace at all.
        assert!(
            profile.get("mounts").is_none(),
            "the derivable workspace must not be written: {profile:?}"
        );
        assert!(
            !text.contains(workspace.to_string_lossy().as_ref()),
            "scaffolded config must carry no path from this checkout:\n{text}"
        );
        // ...and the value it omits is the one `firma run` resolves.
        assert_eq!(
            firma_run::config::workspace_root(
                Some(&config_dir.join(CONFIG_FILE_NAME)),
                std::env::var_os("HOME").map(PathBuf::from).as_deref(),
            )
            .as_deref(),
            Some(workspace.as_path()),
        );
    }

    /// A workspace the run-time default would not produce — here because the
    /// config directory is not named `.firma` — must still be written out, or
    /// the agent silently loses it.
    #[test]
    fn scaffold_records_a_workspace_it_cannot_derive() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("project");
        let config_dir = tmp.path().join("elsewhere");
        fs::create_dir_all(&workspace).unwrap();

        scaffold_from_plan(&ScaffoldPlan {
            config_dir: config_dir.clone(),
            state_dir: tmp.path().join("state"),
            workspace: workspace.clone(),
            force: false,
            authority_listen: "127.0.0.1:50051".into(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            agent: "generic".into(),
            provider: "anthropic".into(),
            authority: AuthorityShape::Local,
        })
        .unwrap();

        let text = fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)).unwrap();
        let t: toml::Value = toml::from_str(&text).unwrap();
        let mounts = t["run"]["profiles"]["generic"]["mounts"]
            .as_array()
            .unwrap();
        assert_eq!(
            mounts[0]["source"].as_str(),
            Some(workspace.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn implicit_scaffold_rejects_invalid_input_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("project");
        let config_dir = workspace.join(CONFIG_DIR_NAME);
        let config_path = config_dir.join(CONFIG_FILE_NAME);
        let state_dir = tmp.path().join("state");
        let original = "[authority]\nmax_ttl_seconds = 3600\n";
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(&config_path, original).unwrap();
        fs::write(config_dir.join("sentinel"), "unchanged").unwrap();

        let error = scaffold_from_plan(&ScaffoldPlan {
            config_dir: config_dir.clone(),
            state_dir: state_dir.clone(),
            workspace,
            force: false,
            authority_listen: "127.0.0.1:50051".into(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            agent: "generic".into(),
            provider: "anthropic".into(),
            authority: AuthorityShape::Local,
        })
        .expect_err("invalid original config must fail before scaffold writes");

        let error = format!("{error:#}");
        assert!(error.contains("max_ttl_seconds"), "{error}");
        assert_eq!(fs::read_to_string(config_path).unwrap(), original);
        assert_eq!(
            fs::read_to_string(config_dir.join("sentinel")).unwrap(),
            "unchanged"
        );
        assert!(!config_dir.join("policies").exists());
        assert!(!config_dir.join("issuance-policies").exists());
        assert!(!config_dir.join("mappings").exists());
        assert!(!state_dir.exists());
    }

    // ── Cedar posture files ───────────────────────────────────────────────────

    #[test]
    fn cedar_file_named_after_posture() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            let files = make_files(&posture, &[], &[]);
            let expected = format!("policies/{}.cedar", posture.file_name());
            assert!(
                files.iter().any(|(k, _)| k == &expected),
                "expected {expected} in generated files for posture {posture:?}"
            );
        }
    }

    #[test]
    fn posture_cedar_files_are_non_empty() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            assert_ne!(posture.cedar_content(), "");
        }
    }

    #[test]
    fn shipped_posture_templates_pass_schema_validation() {
        use cedar_policy::{PolicySet, Schema};

        let (schema, _) = Schema::from_cedarschema_str(firma_core::FIRMA_SCHEMA)
            .unwrap_or_else(|e| panic!("schema parse: {e}"));

        for posture in Posture::iter() {
            let set: PolicySet = posture
                .cedar_content()
                .parse()
                .unwrap_or_else(|e| panic!("{posture:?} parse: {e}"));
            firma_core::validate_policies(&set, &schema, None)
                .unwrap_or_else(|err| panic!("{posture:?} schema validation: {err}"));
        }

        // The issuance template ships alongside every posture.
        let issuance: PolicySet = TPL_CEDAR_ISSUANCE
            .parse()
            .unwrap_or_else(|e| panic!("issuance parse: {e}"));
        firma_core::validate_policies(&issuance, &schema, None)
            .unwrap_or_else(|err| panic!("issuance schema validation: {err}"));
    }

    #[test]
    fn strict_posture_does_not_permit_code_write() {
        assert!(
            !Posture::Strict.cedar_content().contains("code.write"),
            "strict posture must not permit code.write"
        );
    }

    #[test]
    fn dev_with_delete_watch_does_not_forbid_code_destructive() {
        let content = Posture::DevWithDeleteWatch.cedar_content();
        let forbid_stanza =
            "forbid (\n    principal,\n    action == Firma::Action::\"code.destructive\"";
        assert!(
            !content.contains(forbid_stanza),
            "dev-with-delete-watch must not contain a forbid stanza for code.destructive"
        );
    }
}
