//! Runner for `firma config` — scaffold a new agent config directory.

mod doc;

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::ValueEnum as _;
use dialoguer::theme::ColorfulTheme;

use crate::args::config::{InitArgs, Mapping, Mode, Posture};
use crate::fs::create_private_dir_all;
use doc::DocInputs;

struct AuthorityInputs {
    /// gRPC listen address (agent-local + authority modes).
    listen: String,
    /// URL written to `[sidecar.authority].url`.
    connect_url: String,
    /// CA cert path written to `[sidecar.authority].ca_cert_path`.
    connect_ca_cert: String,
    /// Public key path written to `[sidecar.authority].public_key_path`.
    connect_pub_key: String,
}

struct SidecarInputs {
    name: String,
    posture: Posture,
    overwrite_policy: bool,
    requested_actions: Option<Vec<String>>,
    mappings: Vec<Mapping>,
    extra_hosts: Vec<String>,
    workspace: PathBuf,
}

struct CollectedInputs {
    mode: Mode,
    keep_local_authority: bool,
    authority: AuthorityInputs,
    sidecar: SidecarInputs,
    config_dir: PathBuf,
    state_dir: PathBuf,
}

#[derive(Debug, Default)]
struct ExistingConfigDefaults {
    mode: Option<Mode>,
    authority_listen: Option<String>,
    authority_url: Option<String>,
    authority_ca_cert: Option<PathBuf>,
    authority_pub_key: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    name: Option<String>,
    posture: Option<Posture>,
    requested_actions: Option<Vec<String>>,
    mappings: Option<Vec<Mapping>>,
    workspace: Option<PathBuf>,
}

static TPL_CEDAR_ISSUANCE: &str = include_str!("../../templates/issuance.cedar");

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

    let files = generate_files(&inputs)?;

    if args.dry_run {
        for (rel, content) in &files {
            println!("=== {} ===", cfg.join(rel).display());
            println!("{content}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    create_scaffold_dirs(cfg, state)?;
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
        write_revocations(state, args.force)?;
        crate::services::authority::generate_audit_key_if_absent(
            &state.join("audit.key"),
            args.force,
        )?;
    }

    if has_server {
        write_server_material(state, args.force)?;
    }

    println!("\nScaffolded:");
    println!("  config  {}", cfg.display());
    println!("  state   {}", state.display());
    println!("\nNext:");
    match inputs.mode {
        Mode::AgentLocal | Mode::AgentRemote => {
            println!(
                "  firma run --config {}/firma-run.toml -- <agent-command>",
                cfg.display()
            );
        }
        Mode::Authority => {
            println!("  firma authority --config {}/firma.toml", cfg.display());
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn write_revocations(state_dir: &Path, force: bool) -> Result<()> {
    let path = state_dir.join("revocations.txt");
    if force {
        Ok(crate::fs::write_file(&path, b"", 0o600)?)
    } else {
        Ok(crate::fs::write_new_file(&path, b"", 0o600).or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?)
    }
}

fn create_scaffold_dirs(cfg: &Path, state: &Path) -> Result<()> {
    for dir in [
        cfg,
        &cfg.join("policies"),
        &cfg.join("issuance-policies"),
        &cfg.join("mappings"),
        state,
        &state.join("generated-firma-ca"),
    ] {
        create_private_dir_all(dir)?;
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
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        // `firma.toml`, `firma-run.toml`, and `mapping-rules.toml` are
        // produced by the toml_edit merge layer: the input was read from
        // disk, modified in place, and re-serialized. Writing the
        // resulting bytes back is non-destructive — unknown sections,
        // user-tuned defaults, and comments are preserved. Skipping the
        // write here would silently swallow mode changes (e.g. switching
        // from agent-remote to agent-local would not persist the new
        // `[authority]` section).
        let is_merged_toml = matches!(
            rel.as_str(),
            "firma.toml" | "firma-run.toml" | "mapping-rules.toml"
        );
        let should_overwrite =
            force || is_merged_toml || (overwrite_policy && rel.starts_with("policies/"));
        if !should_overwrite && path.exists() {
            eprintln!(
                "skip (exists): {} — use --force to overwrite",
                path.display()
            );
            continue;
        }
        std::fs::write(&path, content.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        println!("  wrote {}", path.display());
    }
    Ok(())
}

fn write_server_material(state: &Path, force: bool) -> Result<()> {
    let key_path = state.join("authority.key");
    if force && key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| format!("remove {}", key_path.display()))?;
        let pub_path = state.join("authority.pub");
        if pub_path.exists() {
            std::fs::remove_file(&pub_path)
                .with_context(|| format!("remove {}", pub_path.display()))?;
        }
    }
    if key_path.exists() {
        println!("  preserved existing authority keypair");
    } else {
        crate::services::authority::run_generate_key(&key_path)
            .with_context(|| format!("generate authority key at {}", key_path.display()))?;
        println!("  generated authority keypair → {}", key_path.display());
    }

    let tls_dir = state.join("tls");
    let tls_cert = tls_dir.join("authority.crt");
    if force && tls_dir.exists() {
        for name in [
            "authority.crt",
            "authority.key",
            "authority-ca.crt",
            "authority-ca.key",
        ] {
            let p = tls_dir.join(name);
            if p.exists() {
                std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
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
    let has_sidecar = matches!(inputs.mode, Mode::AgentLocal | Mode::AgentRemote);

    let mapping_paths: Vec<String> = inputs
        .sidecar
        .mappings
        .iter()
        .map(|m| format!("mappings/{}.toml", m.as_str()))
        .collect();
    let mitm_hosts: Vec<&str> = inputs
        .sidecar
        .mappings
        .iter()
        .flat_map(Mapping::mitm_hosts)
        .copied()
        .collect();
    let requested_actions = inputs.sidecar.requested_actions.clone().unwrap_or_else(|| {
        inputs
            .sidecar
            .posture
            .requested_actions()
            .into_iter()
            .map(String::from)
            .collect()
    });

    let state_dir = &inputs.state_dir;
    let tls_dir = state_dir.join("tls");
    let revocation_file = path_display(&state_dir.join("revocations.txt"));
    let key_file = path_display(&state_dir.join("authority.key"));
    let ca_dir = path_display(&state_dir.join("generated-firma-ca"));
    let audit_file = path_display(&state_dir.join("audit.jsonl"));
    let audit_key = path_display(&state_dir.join("audit.key"));
    let tls_cert_path = path_display(&tls_dir.join("authority.crt"));
    let tls_key_path = path_display(&tls_dir.join("authority.key"));
    let workspace_display = path_display(&inputs.sidecar.workspace);

    let doc_inputs = DocInputs {
        mode: &inputs.mode,
        keep_local_authority: inputs.keep_local_authority,
        name: &inputs.sidecar.name,
        authority_listen: &inputs.authority.listen,
        authority_url: &inputs.authority.connect_url,
        authority_ca_cert: &inputs.authority.connect_ca_cert,
        authority_pub_key: &inputs.authority.connect_pub_key,
        revocation_file: &revocation_file,
        key_file: &key_file,
        ca_dir: &ca_dir,
        audit_file: &audit_file,
        audit_key: &audit_key,
        tls_cert_path: &tls_cert_path,
        tls_key_path: &tls_key_path,
        requested_actions: &requested_actions,
        mapping_paths: &mapping_paths,
        mitm_hosts: &mitm_hosts,
        workspace: &workspace_display,
        extra_hosts: &inputs.sidecar.extra_hosts,
    };

    let firma_toml = render_for(&inputs.config_dir, "firma.toml", |text| {
        doc::render_firma_toml(text, &doc_inputs)
    })?;

    let cedar_path = format!("policies/{}.cedar", inputs.sidecar.posture.file_name());
    let mut files: Vec<(String, String)> = vec![
        ("firma.toml".into(), firma_toml),
        (
            cedar_path,
            inputs.sidecar.posture.cedar_content().to_string(),
        ),
        (
            "issuance-policies/issuance.cedar".into(),
            TPL_CEDAR_ISSUANCE.to_string(),
        ),
    ];

    if has_sidecar {
        let mapping_rules = render_for(&inputs.config_dir, "mapping-rules.toml", |text| {
            doc::render_mapping_rules_toml(text, &doc_inputs)
        })?;
        let firma_run = render_for(&inputs.config_dir, "firma-run.toml", |text| {
            doc::render_firma_run_toml(text, &doc_inputs)
        })?;
        files.push(("mapping-rules.toml".into(), mapping_rules));
        files.push(("firma-run.toml".into(), firma_run));
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
        .join(".firma")
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

    let state_dir =
        resolve_state_dir_with_default(args.state_dir.clone(), existing.state_dir.clone())
            .map_err(anyhow::Error::msg)?;
    let state_dir = std::path::absolute(&state_dir)
        .with_context(|| format!("resolve path {}", state_dir.display()))?;

    let authority =
        collect_authority_inputs(args, &existing, &mode, interactive, &theme, &state_dir)?;

    let has_sidecar = matches!(mode, Mode::AgentLocal | Mode::AgentRemote);
    let sidecar = collect_sidecar_inputs(
        args,
        &existing,
        has_sidecar,
        interactive,
        &theme,
        &config_dir,
    )?;

    Ok(CollectedInputs {
        mode,
        keep_local_authority,
        authority,
        sidecar,
        config_dir,
        state_dir,
    })
}

fn has_server(inputs: &CollectedInputs) -> bool {
    inputs.keep_local_authority || matches!(inputs.mode, Mode::AgentLocal | Mode::Authority)
}

/// Decide whether to retain the existing local `[authority]` section
/// when the operator is switching to `agent-remote`.
///
/// The `toml_edit` merge layer is non-destructive: switching modes patches
/// the relevant sections without blasting unknown content, so there is no
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

    eprintln!(
        "Warning: this configuration includes a local [authority] section. \
         If you keep it, firma run starts the Authority locally instead of using only the remote Authority."
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

    let default = firma_config::resolve_config("config", None, &firma_config::SystemDirs)
        .map_or_else(|_| default_output_dir(), |resolved| resolved.config_dir);

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
    let firma_toml = config_dir.join(firma_config::CONFIG_FILE_NAME);
    if !firma_toml.exists() {
        return Ok(ExistingConfigDefaults::default());
    }

    let text = std::fs::read_to_string(&firma_toml)
        .with_context(|| format!("read existing config {}", firma_toml.display()))?;
    let value: toml::Value = toml::from_str(&text)
        .with_context(|| format!("parse existing config {}", firma_toml.display()))?;
    let mut defaults = ExistingConfigDefaults::default();

    let has_server = value
        .get("authority")
        .and_then(toml::Value::as_table)
        .is_some_and(|t| t.contains_key("listen_addr"));
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

    defaults.authority_listen = get_str(&value, &["authority", "listen_addr"]);
    defaults.authority_url = get_str(&value, &["sidecar", "authority", "url"]);
    defaults.authority_ca_cert = get_path(&value, &["sidecar", "authority", "ca_cert_path"]);
    defaults.authority_pub_key = get_path(&value, &["sidecar", "authority", "public_key_path"]);
    defaults.name = get_str(&value, &["sidecar", "preflight", "agent_id"]);
    defaults.posture = posture_from_preflight_actions(&value);
    defaults.requested_actions = requested_actions_from_config(&value);
    defaults.mappings = mappings_from_rules_paths(&value);
    defaults.state_dir = infer_state_dir(&value);

    let firma_run_path = config_dir.join("firma-run.toml");
    if firma_run_path.exists()
        && let Ok(run_text) = std::fs::read_to_string(&firma_run_path)
    {
        defaults.workspace = workspace_from_firma_run(&run_text);
    }

    Ok(defaults)
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

fn posture_from_preflight_actions(value: &toml::Value) -> Option<Posture> {
    let actions = value
        .get("sidecar")?
        .get("preflight")?
        .get("requested_actions")?
        .as_array()?;
    let has_action = |needle: &str| actions.iter().any(|v| v.as_str() == Some(needle));
    if has_action("code.destructive") {
        Some(Posture::DevWithDeleteWatch)
    } else if has_action("code.write") {
        Some(Posture::Dev)
    } else {
        Some(Posture::Strict)
    }
}

fn requested_actions_from_config(value: &toml::Value) -> Option<Vec<String>> {
    let actions = value
        .get("sidecar")?
        .get("preflight")?
        .get("requested_actions")?
        .as_array()?;
    Some(
        actions
            .iter()
            .filter_map(toml::Value::as_str)
            .map(String::from)
            .collect(),
    )
}

fn mappings_from_rules_paths(value: &toml::Value) -> Option<Vec<Mapping>> {
    let paths = value
        .get("sidecar")?
        .get("mapping")?
        .get("rules_paths")?
        .as_array()?;
    let mut mappings = Vec::new();
    for path in paths {
        let Some(path) = path.as_str() else {
            continue;
        };
        let Some(stem) = Path::new(path).file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Ok(mapping) = Mapping::from_str(stem, true) {
            mappings.push(mapping);
        }
    }
    Some(mappings)
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

fn workspace_from_firma_run(toml_text: &str) -> Option<PathBuf> {
    let value: toml::Value = toml::from_str(toml_text).ok()?;
    let mounts = value
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

fn collect_local_connect_inputs(listen: &str, state_dir: &Path) -> (String, String, String) {
    let url = format!("https://{listen}");
    let tls_ca = state_dir
        .join("tls")
        .join("authority-ca.crt")
        .to_string_lossy()
        .into_owned();
    let pub_key = state_dir
        .join("authority.pub")
        .to_string_lossy()
        .into_owned();
    (url, tls_ca, pub_key)
}

struct RemoteAuthorityField<'a> {
    value: Option<Cow<'a, str>>,
    existing: Option<Cow<'a, str>>,
    interactive: bool,
    theme: &'a ColorfulTheme,
    prompt: &'a str,
    context: &'a str,
    flag: &'a str,
    configured_name: &'a str,
}

fn collect_required_remote_authority_field(field: RemoteAuthorityField<'_>) -> Result<String> {
    let value = match field.value {
        Some(value) => value.to_string(),
        None if field.existing.is_some() && !field.interactive => {
            field.existing.unwrap_or_default().to_string()
        }
        None if field.interactive => dialoguer::Input::with_theme(field.theme)
            .with_prompt(field.prompt)
            .default(field.existing.unwrap_or_default().to_string())
            .interact_text()
            .with_context(|| field.context.to_string())?,
        None => String::new(),
    };

    if value.trim().is_empty() {
        anyhow::bail!(
            "{} is required when --mode agent-remote and no existing remote {} is configured",
            field.flag,
            field.configured_name
        );
    }
    Ok(value)
}

fn collect_remote_connect_inputs(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<(String, String, String)> {
    let url = collect_required_remote_authority_field(RemoteAuthorityField {
        value: args.authority_url.as_deref().map(Cow::Borrowed),
        existing: existing.authority_url.as_deref().map(Cow::Borrowed),
        interactive,
        theme,
        prompt: "Authority URL",
        context: "authority URL prompt",
        flag: "--authority-url",
        configured_name: "URL",
    })?;
    let ca = collect_required_remote_authority_field(RemoteAuthorityField {
        value: args
            .authority_ca_cert
            .as_deref()
            .map(|p| p.to_string_lossy()),
        existing: existing
            .authority_ca_cert
            .as_ref()
            .map(|p| p.to_string_lossy()),
        interactive,
        theme,
        prompt: "Path to authority CA certificate (PEM)",
        context: "authority CA cert prompt",
        flag: "--authority-ca-cert",
        configured_name: "CA certificate",
    })?;
    let pub_key = collect_required_remote_authority_field(RemoteAuthorityField {
        value: args
            .authority_pub_key
            .as_deref()
            .map(|p| p.to_string_lossy()),
        existing: existing
            .authority_pub_key
            .as_ref()
            .map(|p| p.to_string_lossy()),
        interactive,
        theme,
        prompt: "Path to authority public key",
        context: "authority public key prompt",
        flag: "--authority-pub-key",
        configured_name: "public key",
    })?;
    Ok((url, ca, pub_key))
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
                    .unwrap_or_else(|| "0.0.0.0:9443".to_string()),
            )
            .interact_text()
            .context("authority listen address prompt")?,
        (None, Mode::AgentLocal) if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Authority listen address")
            .default(
                existing
                    .authority_listen
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:9443".to_string()),
            )
            .interact_text()
            .context("authority listen address prompt")?,
        _ => "127.0.0.1:9443".to_string(),
    };

    let (connect_url, connect_ca_cert, connect_pub_key) = match mode {
        Mode::AgentLocal => collect_local_connect_inputs(&listen, state_dir),
        Mode::AgentRemote => collect_remote_connect_inputs(args, existing, interactive, theme)?,
        Mode::Authority => (String::new(), String::new(), String::new()),
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
    has_sidecar: bool,
    interactive: bool,
    theme: &ColorfulTheme,
    config_dir: &Path,
) -> Result<SidecarInputs> {
    let overwrite_policy = args.posture.is_some() || interactive;
    let posture = match (&args.posture, &existing.posture) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) if !interactive => p.clone(),
        (None, Some(p)) if interactive => prompt_posture_with_default(theme, p)?,
        (None, _) if interactive => prompt_posture_with_default(theme, &Posture::Dev)?,
        (None, _) => Posture::Dev,
    };

    if !has_sidecar {
        return Ok(SidecarInputs {
            name: "authority".to_string(),
            posture,
            overwrite_policy,
            requested_actions: None,
            mappings: vec![],
            extra_hosts: vec![],
            workspace: config_dir.to_path_buf(),
        });
    }

    let name = match args.name.as_deref() {
        Some(v) => v.to_string(),
        None if existing.name.is_some() && !interactive => {
            existing.name.clone().unwrap_or_default()
        }
        None if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Agent name")
            .default(
                existing
                    .name
                    .clone()
                    .unwrap_or_else(|| "my-agent".to_string()),
            )
            .interact_text()
            .context("agent name prompt")?,
        None => "my-agent".to_string(),
    };

    let requested_actions = if args.posture.is_some() {
        None
    } else {
        existing.requested_actions.clone()
    };

    let mappings = if !args.mapping.is_empty() {
        args.mapping.clone()
    } else if let Some(mappings) = &existing.mappings
        && !interactive
    {
        mappings.clone()
    } else if interactive {
        prompt_mappings_with_default(theme, existing.mappings.as_deref())?
    } else {
        vec![Mapping::Anthropic]
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

    let workspace = collect_workspace(args, existing, interactive, theme)?;

    Ok(SidecarInputs {
        name,
        posture,
        overwrite_policy,
        requested_actions,
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
    let variants = Mapping::value_variants();
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

/// Delete posture cedar files left behind by previous postures.
///
/// Posture is a closed set of `(cedar file, requested_actions)` presets.
/// Changing posture rewrites `requested_actions` in `firma.toml`, but
/// each posture lives in its own file under `policies/`, so the old
/// file lingers and the sidecar (which loads every `.cedar` in the
/// dir) ends up applying both. Remove stale posture files here.
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
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let pristine = posture.cedar_content();
        let modified = current.trim() != pristine.trim();
        if force || !modified {
            std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
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
                std::fs::remove_file(&path)
                    .with_context(|| format!("remove {}", path.display()))?;
                println!("  removed {}", path.display());
            } else {
                eprintln!(
                    "  kept {} — sidecar will load it alongside the active posture",
                    path.display()
                );
            }
        } else {
            eprintln!(
                "  kept {} (locally modified) — pass --force to delete",
                path.display()
            );
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
    firma_stack::resolve_state_dir(None).map_err(|error| format!("state_dir: {error}"))
}

/// Scaffold from an already-resolved plan. Called by `firma run` on first use
/// when no `firma.toml` is discoverable.
///
/// # Errors
/// Returns a formatted string on any filesystem or key-generation failure.
#[allow(clippy::too_many_lines)]
pub fn scaffold_from_plan(plan: &ScaffoldPlan) -> Result<()> {
    let mappings = provider_to_mappings(&plan.provider);
    let (mode, authority) = match &plan.authority {
        AuthorityShape::Local => {
            let connect_url = format!("https://{}", plan.authority_listen);
            let connect_ca_cert = plan
                .state_dir
                .join("tls")
                .join("authority-ca.crt")
                .to_string_lossy()
                .into_owned();
            (
                Mode::AgentLocal,
                AuthorityInputs {
                    listen: plan.authority_listen.clone(),
                    connect_url,
                    connect_ca_cert,
                    connect_pub_key: plan
                        .state_dir
                        .join("authority.pub")
                        .to_string_lossy()
                        .into_owned(),
                },
            )
        }
    };
    let inputs = CollectedInputs {
        mode,
        keep_local_authority: false,
        authority,
        sidecar: SidecarInputs {
            name: plan.agent.clone(),
            posture: Posture::Dev,
            overwrite_policy: false,
            requested_actions: None,
            mappings,
            extra_hosts: vec![],
            workspace: plan.workspace.clone(),
        },
        config_dir: plan.config_dir.clone(),
        state_dir: plan.state_dir.clone(),
    };
    let files = generate_files(&inputs).context("generate files")?;

    for dir in [
        plan.config_dir.as_path(),
        &plan.config_dir.join("policies"),
        &plan.config_dir.join("issuance-policies"),
        &plan.config_dir.join("mappings"),
        plan.state_dir.as_path(),
        &plan.state_dir.join("generated-firma-ca"),
    ] {
        create_private_dir_all(dir)?;
    }

    for (rel, content) in &files {
        let path = plan.config_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        if !plan.force && path.exists() {
            continue;
        }
        std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    }

    write_revocations(&plan.state_dir, plan.force)?;
    crate::services::authority::generate_audit_key_if_absent(
        &plan.state_dir.join("audit.key"),
        plan.force,
    )?;

    let key_path = plan.state_dir.join("authority.key");
    if plan.force || !key_path.exists() {
        crate::services::authority::run_generate_key(&key_path)?;
    }

    let tls_dir = plan.state_dir.join("tls");
    if plan.force && tls_dir.exists() {
        for name in [
            "authority.crt",
            "authority.key",
            "authority-ca.crt",
            "authority-ca.key",
        ] {
            let p = tls_dir.join(name);
            if p.exists() {
                std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            }
        }
    }
    if !tls_dir.join("authority.crt").exists() {
        crate::services::authority::run_bootstrap_tls(&tls_dir, &[])
            .context("generate TLS material")?;
    }

    Ok(())
}

fn provider_to_mappings(provider: &str) -> Vec<Mapping> {
    match provider {
        "openai" => vec![Mapping::Openai],
        _ => vec![Mapping::Anthropic],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;

    const TEST_AGENT: &str = "test-agent";
    const TEST_WORKSPACE: &str = "/tmp/test-workspace";

    fn make_files(
        posture: &Posture,
        mappings: &[Mapping],
        extra_hosts: &[String],
    ) -> Vec<(String, String)> {
        let inputs = CollectedInputs {
            mode: Mode::AgentLocal,
            keep_local_authority: false,
            authority: AuthorityInputs {
                listen: "127.0.0.1:9443".to_string(),
                connect_url: "https://127.0.0.1:9443".to_string(),
                connect_ca_cert: "/tmp/test-state/tls/authority-ca.crt".to_string(),
                connect_pub_key: "/tmp/test-state/authority.pub".to_string(),
            },
            sidecar: SidecarInputs {
                name: TEST_AGENT.to_string(),
                posture: posture.clone(),
                overwrite_policy: false,
                requested_actions: None,
                mappings: mappings.to_vec(),
                extra_hosts: extra_hosts.to_vec(),
                workspace: PathBuf::from(TEST_WORKSPACE),
            },
            config_dir: PathBuf::from(TEST_WORKSPACE),
            state_dir: PathBuf::from("/tmp/test-state"),
        };
        generate_files(&inputs).unwrap()
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
            let _: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        }
    }

    #[test]
    fn firma_toml_agent_id_matches_name() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        assert_eq!(
            t["sidecar"]["preflight"]["agent_id"].as_str(),
            Some(TEST_AGENT),
        );
    }

    #[test]
    fn firma_toml_parses_as_authority_config() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firma.toml");
        std::fs::write(&path, get(&files, "firma.toml")).unwrap();
        let body = firma_config::load_section(&path, "authority").unwrap();
        let _: firma_authority::AuthorityConfig = toml::from_str(&body).unwrap();
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
                let path = dir.path().join("firma.toml");
                std::fs::write(&path, get(&files, "firma.toml")).unwrap();
                let body = firma_config::load_section(&path, "sidecar").unwrap();
                let _: firma_sidecar::config::SidecarConfig = toml::from_str(&body).unwrap();
            }
        }
    }

    #[test]
    fn firma_toml_mitm_hosts_populated_for_github_gmail() {
        let files = make_files(
            &Posture::Dev,
            &[Mapping::Anthropic, Mapping::Github, Mapping::Gmail],
            &[],
        );
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        let hosts = t["sidecar"]["interceptor"]["https_mitm"]["intercept_hosts"]
            .as_array()
            .unwrap();
        let host_strs: Vec<_> = hosts.iter().filter_map(|v| v.as_str()).collect();
        assert!(host_strs.contains(&"api.github.com"));
        assert!(host_strs.contains(&"gmail.googleapis.com"));
        assert!(!host_strs.contains(&"api.anthropic.com"));
    }

    #[test]
    fn firma_toml_no_mitm_hosts_when_only_anthropic() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        let hosts = t["sidecar"]["interceptor"]["https_mitm"]["intercept_hosts"]
            .as_array()
            .unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn firma_toml_rules_paths_contains_selected_mappings() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic, Mapping::Github], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        let paths = t["sidecar"]["mapping"]["rules_paths"].as_array().unwrap();
        let path_strs: Vec<_> = paths.iter().filter_map(|v| v.as_str()).collect();
        assert!(path_strs.contains(&"mappings/anthropic.toml"));
        assert!(path_strs.contains(&"mappings/github.toml"));
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
            rules
                .iter()
                .any(|r| r.host == "api.example.com:443" && r.method.as_deref() == Some("CONNECT")),
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
            rules.iter().any(
                |r| r.host == "api.anthropic.com:443" && r.method.as_deref() == Some("CONNECT")
            ),
            "expected api.anthropic.com:443 CONNECT rule"
        );
    }

    #[test]
    fn openai_mapping_has_connect_rule() {
        let rules = parse_rules(Mapping::Openai.static_content()).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.openai.com:443" && r.method.as_deref() == Some("CONNECT")),
            "expected api.openai.com:443 CONNECT rule"
        );
    }

    #[test]
    fn github_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Github.static_content()).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.github.com:443" && r.method.as_deref() == Some("CONNECT")),
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
            rules
                .iter()
                .any(|r| r.host == "gmail.googleapis.com:443"
                    && r.method.as_deref() == Some("CONNECT")),
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
            rules
                .iter()
                .any(|r| r.host == "api.stripe.com:443" && r.method.as_deref() == Some("CONNECT")),
            "CONNECT rule missing from stripe mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.stripe.com" && r.path.is_some()),
            "REST rules missing from stripe mapping"
        );
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

    // ── firma-run.toml ───────────────────────────────────────────────────────

    #[test]
    fn firma_run_toml_is_valid_toml() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let _: toml::Value = toml::from_str(get(&files, "firma-run.toml")).unwrap();
    }

    #[test]
    fn firma_run_toml_workspace_mount_matches_input() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma-run.toml")).unwrap();
        let mounts = t["profiles"]["generic"]["mounts"].as_array().unwrap();
        assert_eq!(mounts[0]["source"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["target"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["read_only"].as_bool(), Some(false));
    }

    #[test]
    fn implicit_scaffold_uses_workspace_not_config_dir_for_mount() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("project");
        let config_dir = workspace.join(".firma");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&workspace).unwrap();

        scaffold_from_plan(&ScaffoldPlan {
            config_dir: config_dir.clone(),
            state_dir,
            workspace: workspace.clone(),
            force: false,
            authority_listen: "127.0.0.1:50051".into(),
            agent: "generic".into(),
            provider: "anthropic".into(),
            authority: AuthorityShape::Local,
        })
        .unwrap();

        let text = std::fs::read_to_string(config_dir.join("firma-run.toml")).unwrap();
        let t: toml::Value = toml::from_str(&text).unwrap();
        let mounts = t["profiles"]["generic"]["mounts"].as_array().unwrap();
        assert_eq!(
            mounts[0]["source"].as_str(),
            Some(workspace.to_string_lossy().as_ref())
        );
        assert_eq!(
            mounts[0]["target"].as_str(),
            Some(workspace.to_string_lossy().as_ref())
        );
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
            assert!(!posture.cedar_content().is_empty());
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
            firma_core::validate_policies(&set, &schema).unwrap_or_else(|errs| {
                panic!("{posture:?} schema validation: {}", errs.join("; "))
            });
        }

        // The issuance template ships alongside every posture.
        let issuance: PolicySet = TPL_CEDAR_ISSUANCE
            .parse()
            .unwrap_or_else(|e| panic!("issuance parse: {e}"));
        firma_core::validate_policies(&issuance, &schema)
            .unwrap_or_else(|errs| panic!("issuance schema validation: {}", errs.join("; ")));
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
