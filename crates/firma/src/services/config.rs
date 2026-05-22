//! Runner for `firma config` — scaffold a new agent config directory.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::ValueEnum as _;
use dialoguer::theme::ColorfulTheme;
use minijinja::{Environment, context};

use crate::args::config::{InitArgs, Mapping, Mode, Posture};

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
    requested_actions: Option<Vec<String>>,
    mappings: Vec<Mapping>,
    extra_hosts: Vec<String>,
    workspace: PathBuf,
    existing_firma_run_toml: Option<String>,
}

struct CollectedInputs {
    mode: Mode,
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
    firma_run_toml: Option<String>,
}

static TPL_FIRMA_TOML: &str = include_str!("../../templates/firma.toml.j2");
static TPL_MAPPING_RULES: &str = include_str!("../../templates/mapping-rules.toml.j2");
static TPL_FIRMA_RUN: &str = include_str!("../../templates/firma-run.toml.j2");
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

    let env = build_template_env()?;
    let files = generate_files(&env, &inputs)?;

    if args.dry_run {
        for (rel, content) in &files {
            println!("=== {} ===", cfg.join(rel).display());
            println!("{content}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    create_scaffold_dirs(cfg, state)?;
    write_scaffold_files(&files, cfg, args.force)?;

    let has_server = matches!(inputs.mode, Mode::AgentLocal | Mode::Authority);
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

    if has_sidecar {
        write_if_absent(&state.join("revocations.txt"), b"", args.force)?;
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

fn create_scaffold_dirs(cfg: &Path, state: &Path) -> Result<()> {
    for dir in [
        cfg,
        &cfg.join("policies"),
        &cfg.join("issuance-policies"),
        &cfg.join("mappings"),
    ] {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        #[cfg(unix)]
        set_dir_mode_0700(dir).with_context(|| format!("chmod {}", dir.display()))?;
    }
    for dir in [state, &state.join("generated-firma-ca")] {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        #[cfg(unix)]
        set_dir_mode_0700(dir).with_context(|| format!("chmod {}", dir.display()))?;
    }
    Ok(())
}

fn write_scaffold_files(files: &[(String, String)], cfg: &Path, force: bool) -> Result<()> {
    for (rel, content) in files {
        let path = cfg.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        if !force && path.exists() {
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

fn build_template_env() -> Result<Environment<'static>> {
    let mut env = Environment::new();
    env.add_template("firma.toml", TPL_FIRMA_TOML)
        .context("load firma.toml template")?;
    env.add_template("mapping-rules.toml", TPL_MAPPING_RULES)
        .context("load mapping-rules.toml template")?;
    env.add_template("firma-run.toml", TPL_FIRMA_RUN)
        .context("load firma-run.toml template")?;
    Ok(env)
}

fn generate_files(
    env: &Environment<'_>,
    inputs: &CollectedInputs,
) -> Result<Vec<(String, String)>> {
    let has_server = matches!(inputs.mode, Mode::AgentLocal | Mode::Authority);
    let has_connect = matches!(inputs.mode, Mode::AgentLocal | Mode::AgentRemote);
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

    let firma_toml = render(
        env,
        "firma.toml",
        context! {
            has_server,
            has_connect,
            has_sidecar,
            name => inputs.sidecar.name,
            mapping_paths,
            mitm_hosts,
            requested_actions,
            authority_listen => inputs.authority.listen,
            authority_url => inputs.authority.connect_url,
            tls_ca_cert_path => &inputs.authority.connect_ca_cert,
            authority_pub_key_path => &inputs.authority.connect_pub_key,
            revocation_file,
            key_file,
            ca_dir,
            audit_file,
            audit_key,
            tls_cert_path,
            tls_key_path,
        },
    )?;

    let cedar_path = format!("policies/{}.cedar", inputs.sidecar.posture.file_name());
    let mut files = vec![
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
        let mapping_rules = render(
            env,
            "mapping-rules.toml",
            context! { extra_hosts => inputs.sidecar.extra_hosts },
        )?;
        let firma_run = if let Some(existing) = &inputs.sidecar.existing_firma_run_toml {
            existing.clone()
        } else {
            let workspace = path_display(&inputs.sidecar.workspace);
            render(
                env,
                "firma-run.toml",
                context! { name => inputs.sidecar.name, workspace },
            )?
        };
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

fn render(env: &Environment<'_>, template: &str, ctx: minijinja::Value) -> Result<String> {
    env.get_template(template)
        .and_then(|t| t.render(ctx))
        .with_context(|| format!("render template {template}"))
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
        authority,
        sidecar,
        config_dir,
        state_dir,
    })
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
        defaults.firma_run_toml = Some(run_text);
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

    let default_pub_key = state_dir
        .join("authority.pub")
        .to_string_lossy()
        .into_owned();
    let connect_pub_key = args
        .authority_pub_key
        .as_ref()
        .or(existing.authority_pub_key.as_ref())
        .map_or(default_pub_key, |p| p.to_string_lossy().into_owned());

    let (connect_url, connect_ca_cert) = match mode {
        Mode::AgentLocal => {
            let url = format!("https://{listen}");
            let tls_ca = state_dir
                .join("tls")
                .join("authority-ca.crt")
                .to_string_lossy()
                .into_owned();
            (url, tls_ca)
        }
        Mode::AgentRemote => {
            let url = match args.authority_url.as_deref() {
                Some(u) => u.to_string(),
                None if existing.authority_url.is_some() && !interactive => {
                    existing.authority_url.clone().unwrap_or_default()
                }
                None if interactive => dialoguer::Input::with_theme(theme)
                    .with_prompt("Authority URL")
                    .default(existing.authority_url.clone().unwrap_or_default())
                    .interact_text()
                    .context("authority URL prompt")?,
                None => String::new(),
            };
            let ca = match args.authority_ca_cert.as_deref() {
                Some(p) => p.to_string_lossy().into_owned(),
                None if existing.authority_ca_cert.is_some() && !interactive => existing
                    .authority_ca_cert
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                None if interactive => dialoguer::Input::with_theme(theme)
                    .with_prompt("Path to authority CA certificate (PEM)")
                    .default(
                        existing
                            .authority_ca_cert
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    )
                    .interact_text()
                    .context("authority CA cert prompt")?,
                None => String::new(),
            };
            (url, ca)
        }
        Mode::Authority => (String::new(), String::new()),
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
) -> Result<(PathBuf, Option<String>)> {
    let mut overridden = args.workspace.is_some();
    let workspace = if let Some(p) = &args.workspace {
        std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()))?
    } else if let Some(p) = &existing.workspace
        && !interactive
    {
        p.clone()
    } else {
        let cwd = std::env::current_dir().context("get current directory")?;
        if interactive {
            let default_path = existing.workspace.as_ref().unwrap_or(&cwd);
            let default = default_path.to_string_lossy().into_owned();
            let s: String = dialoguer::Input::with_theme(theme)
                .with_prompt("Workspace directory (agent RW access)")
                .default(default)
                .interact_text()
                .context("workspace prompt")?;
            let p = PathBuf::from(s);
            let abs =
                std::path::absolute(&p).with_context(|| format!("resolve path {}", p.display()))?;
            let abs_default = std::path::absolute(default_path)
                .with_context(|| format!("resolve path {}", default_path.display()))?;
            overridden = abs != abs_default;
            abs
        } else {
            cwd
        }
    };
    let preserved = if overridden {
        None
    } else {
        existing.firma_run_toml.clone()
    };
    Ok((workspace, preserved))
}

fn collect_sidecar_inputs(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    has_sidecar: bool,
    interactive: bool,
    theme: &ColorfulTheme,
    config_dir: &Path,
) -> Result<SidecarInputs> {
    if !has_sidecar {
        return Ok(SidecarInputs {
            name: "authority".to_string(),
            posture: Posture::Strict,
            requested_actions: None,
            mappings: vec![],
            extra_hosts: vec![],
            workspace: config_dir.to_path_buf(),
            existing_firma_run_toml: None,
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

    let posture = match (&args.posture, &existing.posture) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) if !interactive => p.clone(),
        (None, Some(p)) if interactive => prompt_posture_with_default(theme, p)?,
        (None, _) if interactive => prompt_posture_with_default(theme, &Posture::Dev)?,
        (None, _) => Posture::Dev,
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

    let (workspace, existing_firma_run_toml) =
        collect_workspace(args, existing, interactive, theme)?;

    Ok(SidecarInputs {
        name,
        posture,
        requested_actions,
        mappings,
        extra_hosts,
        workspace,
        existing_firma_run_toml,
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

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))
}

fn write_if_absent(path: &Path, content: &[u8], force: bool) -> Result<()> {
    if !force && path.exists() {
        return Ok(());
    }
    std::fs::write(path, content).with_context(|| format!("write {}", path.display()))
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
    Remote {
        url: String,
        ca_cert: Option<PathBuf>,
    },
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
pub fn scaffold_from_plan(plan: &ScaffoldPlan) -> Result<(), String> {
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
        AuthorityShape::Remote { url, ca_cert } => (
            Mode::AgentRemote,
            AuthorityInputs {
                listen: plan.authority_listen.clone(),
                connect_url: url.clone(),
                connect_ca_cert: ca_cert
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                connect_pub_key: plan
                    .state_dir
                    .join("authority.pub")
                    .to_string_lossy()
                    .into_owned(),
            },
        ),
    };
    let inputs = CollectedInputs {
        mode,
        authority,
        sidecar: SidecarInputs {
            name: plan.agent.clone(),
            posture: Posture::Dev,
            requested_actions: None,
            mappings,
            extra_hosts: vec![],
            workspace: plan.config_dir.clone(),
            existing_firma_run_toml: None,
        },
        config_dir: plan.config_dir.clone(),
        state_dir: plan.state_dir.clone(),
    };
    let env = build_template_env().map_err(|e| format!("template env: {e}"))?;
    let files = generate_files(&env, &inputs).map_err(|e| format!("generate files: {e}"))?;

    for dir in [
        plan.config_dir.as_path(),
        &plan.config_dir.join("policies"),
        &plan.config_dir.join("issuance-policies"),
        &plan.config_dir.join("mappings"),
        plan.state_dir.as_path(),
        &plan.state_dir.join("generated-firma-ca"),
    ] {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }

    for (rel, content) in &files {
        let path = plan.config_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        if !plan.force && path.exists() {
            continue;
        }
        std::fs::write(&path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    write_if_absent(&plan.state_dir.join("revocations.txt"), b"", plan.force)
        .map_err(|e| e.to_string())?;
    crate::services::authority::generate_audit_key_if_absent(
        &plan.state_dir.join("audit.key"),
        plan.force,
    )
    .map_err(|e| e.to_string())?;

    let key_path = plan.state_dir.join("authority.key");
    if plan.force || !key_path.exists() {
        crate::services::authority::run_generate_key(&key_path).map_err(|e| e.to_string())?;
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
                std::fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()))?;
            }
        }
    }
    if !tls_dir.join("authority.crt").exists() {
        crate::services::authority::run_bootstrap_tls(&tls_dir, &[])
            .map_err(|e| format!("generate TLS material: {e}"))?;
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
        let env = build_template_env().unwrap();
        let inputs = CollectedInputs {
            mode: Mode::AgentLocal,
            authority: AuthorityInputs {
                listen: "127.0.0.1:9443".to_string(),
                connect_url: "https://127.0.0.1:9443".to_string(),
                connect_ca_cert: "/tmp/test-state/tls/authority-ca.crt".to_string(),
                connect_pub_key: "/tmp/test-state/authority.pub".to_string(),
            },
            sidecar: SidecarInputs {
                name: TEST_AGENT.to_string(),
                posture: posture.clone(),
                requested_actions: None,
                mappings: mappings.to_vec(),
                extra_hosts: extra_hosts.to_vec(),
                workspace: PathBuf::from(TEST_WORKSPACE),
                existing_firma_run_toml: None,
            },
            config_dir: PathBuf::from(TEST_WORKSPACE),
            state_dir: PathBuf::from("/tmp/test-state"),
        };
        generate_files(&env, &inputs).unwrap()
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
            Mapping::Custom,
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
