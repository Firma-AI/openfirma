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
    /// URL written to `[authority.connect].url`.
    connect_url: String,
    /// CA cert path written to `[authority.connect].ca_cert_path`.
    connect_ca_cert: String,
}

struct SidecarInputs {
    name: String,
    posture: Posture,
    mappings: Vec<Mapping>,
    extra_hosts: Vec<String>,
    workspace: PathBuf,
}

struct CollectedInputs {
    mode: Mode,
    authority: AuthorityInputs,
    sidecar: SidecarInputs,
    config_dir: PathBuf,
    state_dir: PathBuf,
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

    let requested_actions = inputs.sidecar.posture.requested_actions();
    let workspace_str = inputs.sidecar.workspace.to_string_lossy();
    let state_dir_str = inputs.state_dir.to_string_lossy();
    let tls_dir = inputs.state_dir.join("tls");
    let tls_cert_path = tls_dir.join("authority.crt").to_string_lossy().into_owned();
    let tls_key_path = tls_dir.join("authority.key").to_string_lossy().into_owned();

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
            tls_ca_cert_path => inputs.authority.connect_ca_cert,
            state_dir => state_dir_str.as_ref(),
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
        let firma_run = render(
            env,
            "firma-run.toml",
            context! { name => inputs.sidecar.name, workspace => workspace_str.as_ref() },
        )?;
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

fn default_output_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".firma")
}

fn collect_inputs(args: &InitArgs) -> Result<CollectedInputs> {
    let theme = ColorfulTheme::default();
    let interactive = !args.yes && dialoguer::console::Term::stderr().is_term();

    let mode = match &args.mode {
        Some(m) => m.clone(),
        None if interactive => prompt_mode(&theme)?,
        None => Mode::AgentLocal,
    };

    let config_dir = match &args.output_dir {
        Some(p) => {
            std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()))?
        }
        None if interactive => {
            let default = default_output_dir().to_string_lossy().into_owned();
            let s: String = dialoguer::Input::with_theme(&theme)
                .with_prompt("Config directory")
                .default(default)
                .interact_text()
                .context("config directory prompt")?;
            std::path::absolute(PathBuf::from(s)).context("resolve config directory path")?
        }
        None => default_output_dir(),
    };

    let state_dir = resolve_state_dir(args.state_dir.clone()).map_err(anyhow::Error::msg)?;
    let state_dir = std::path::absolute(&state_dir)
        .with_context(|| format!("resolve path {}", state_dir.display()))?;

    let authority = collect_authority_inputs(args, &mode, interactive, &theme, &state_dir)?;

    let has_sidecar = matches!(mode, Mode::AgentLocal | Mode::AgentRemote);
    let sidecar = collect_sidecar_inputs(args, has_sidecar, interactive, &theme, &config_dir)?;

    Ok(CollectedInputs {
        mode,
        authority,
        sidecar,
        config_dir,
        state_dir,
    })
}

fn collect_authority_inputs(
    args: &InitArgs,
    mode: &Mode,
    interactive: bool,
    theme: &ColorfulTheme,
    state_dir: &Path,
) -> Result<AuthorityInputs> {
    let listen = match (args.authority_listen.as_deref(), mode) {
        (Some(addr), _) => addr.to_string(),
        (None, Mode::Authority) if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Authority listen address")
            .default("0.0.0.0:9443".to_string())
            .interact_text()
            .context("authority listen address prompt")?,
        _ => "127.0.0.1:9443".to_string(),
    };

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
                None if interactive => dialoguer::Input::with_theme(theme)
                    .with_prompt("Authority URL")
                    .interact_text()
                    .context("authority URL prompt")?,
                None => String::new(),
            };
            let ca = match args.authority_ca_cert.as_deref() {
                Some(p) => p.to_string_lossy().into_owned(),
                None if interactive => dialoguer::Input::with_theme(theme)
                    .with_prompt("Path to authority CA certificate (PEM)")
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
    })
}

fn collect_sidecar_inputs(
    args: &InitArgs,
    has_sidecar: bool,
    interactive: bool,
    theme: &ColorfulTheme,
    config_dir: &Path,
) -> Result<SidecarInputs> {
    if !has_sidecar {
        return Ok(SidecarInputs {
            name: "authority".to_string(),
            posture: Posture::Strict,
            mappings: vec![],
            extra_hosts: vec![],
            workspace: config_dir.to_path_buf(),
        });
    }

    let name = match args.name.as_deref() {
        Some(v) => v.to_string(),
        None if interactive => dialoguer::Input::with_theme(theme)
            .with_prompt("Agent name")
            .default("my-agent".to_string())
            .interact_text()
            .context("agent name prompt")?,
        None => "my-agent".to_string(),
    };

    let posture = match &args.posture {
        Some(p) => p.clone(),
        None if interactive => prompt_posture(theme)?,
        None => Posture::Dev,
    };

    let mappings = if !args.mapping.is_empty() {
        args.mapping.clone()
    } else if interactive {
        prompt_mappings(theme)?
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

    let workspace = if let Some(p) = &args.workspace {
        std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()))?
    } else {
        let cwd = std::env::current_dir().context("get current directory")?;
        if interactive {
            let default = cwd.to_string_lossy().into_owned();
            let s: String = dialoguer::Input::with_theme(theme)
                .with_prompt("Workspace directory (agent RW access)")
                .default(default)
                .interact_text()
                .context("workspace prompt")?;
            let p = PathBuf::from(s);
            std::path::absolute(&p).with_context(|| format!("resolve path {}", p.display()))?
        } else {
            cwd
        }
    };

    Ok(SidecarInputs {
        name,
        posture,
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

fn prompt_mode(theme: &ColorfulTheme) -> Result<Mode> {
    let variants = Mode::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|m| format!("{:<16}  {}", mode_name(m), m.description()))
        .collect();
    let selection = dialoguer::Select::with_theme(theme)
        .with_prompt("What are you configuring?")
        .items(&items)
        .default(0)
        .report(false)
        .interact()
        .context("mode prompt")?;
    let chosen = variants[selection].clone();
    eprintln!("  Mode     · {}", mode_name(&chosen));
    Ok(chosen)
}

fn prompt_posture(theme: &ColorfulTheme) -> Result<Posture> {
    let variants = Posture::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|p| format!("{:<24}  {}", p.file_name(), p.description()))
        .collect();
    let selection = dialoguer::Select::with_theme(theme)
        .with_prompt("Posture")
        .items(&items)
        .default(1)
        .report(false)
        .interact()
        .context("posture prompt")?;
    let chosen = variants[selection].clone();
    eprintln!("  Posture  · {}", chosen.file_name());
    Ok(chosen)
}

fn prompt_mappings(theme: &ColorfulTheme) -> Result<Vec<Mapping>> {
    let variants = Mapping::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|m| format!("{:<12}  {}", m.as_str(), m.description()))
        .collect();
    let defaults: Vec<bool> = variants
        .iter()
        .map(|m| matches!(m, Mapping::Anthropic))
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
    if let Some(path) = flag {
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
            },
        ),
    };
    let inputs = CollectedInputs {
        mode,
        authority,
        sidecar: SidecarInputs {
            name: plan.agent.clone(),
            posture: Posture::Dev,
            mappings,
            extra_hosts: vec![],
            workspace: plan.config_dir.clone(),
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
            },
            sidecar: SidecarInputs {
                name: TEST_AGENT.to_string(),
                posture: posture.clone(),
                mappings: mappings.to_vec(),
                extra_hosts: extra_hosts.to_vec(),
                workspace: PathBuf::from(TEST_WORKSPACE),
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
        let body = firma_config::load_section(&path, "authority.server").unwrap();
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
