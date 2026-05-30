//! Runner for `firma run`.

use std::process::ExitCode;

use firma_run::authority::AuthorityPromptIo;
use firma_run::runtime::{RunInput, execute_run};
use tracing::{info, warn};

use crate::args::run::RunArgs;
use crate::services::config::{AuthorityShape, ScaffoldPlan, scaffold_from_plan};

/// Run the `firma run` subcommand. Sync — must not be called from inside
/// a tokio runtime.
///
/// # Errors
///
/// Returns an error if `firma_run` fails to launch or supervise the
/// wrapped command.
pub fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    if args.no_autostart && args.authority.as_deref() == Some("local") {
        anyhow::bail!(
            "--no-autostart is incompatible with --authority local; pass --authority <url> or omit --no-autostart"
        );
    }
    // Reject `--sidecar local` + `--no-autostart` before any filesystem side
    // effects (implicit init). `execute_run` would also catch this via
    // `RunError::SidecarLocalNoAutostart`, but only after init runs — and if
    // init fails for an unrelated reason (e.g. a non-writable scaffold path),
    // that downstream error never surfaces. Fail fast on the bad arg pair.
    if args.no_autostart && args.sidecar.as_deref() == Some("local") {
        anyhow::bail!(
            "`--sidecar local` is incompatible with `--no-autostart`; \
             pass `--sidecar <tcp://...|unix:///...>` or omit `--no-autostart`"
        );
    }
    validate_sidecar_endpoint_flag(&args)?;

    // Implicit init: if no firma.toml is discoverable for this project,
    // scaffold one before handing off to firma-run. Keeps the spec's
    // one-command path (`firma run codex`) working from a fresh clone.
    maybe_implicit_init(&args)?;

    // Auto-discover firma.toml when --config is not set.
    let run_config = args.config.clone().or_else(|| {
        firma_config::resolve_config("run", None, &firma_config::SystemDirs)
            .ok()
            .map(|r| r.config_dir.join(firma_config::CONFIG_FILE_NAME))
            .filter(|p| p.is_file())
    });

    let profile = resolve_profile_name(args.profile.as_deref(), run_config.as_deref());
    let authority_cli = match args.authority.as_deref() {
        None => firma_run::authority::AuthorityCli::Unset,
        Some("local") => firma_run::authority::AuthorityCli::Local,
        Some(url) => firma_run::authority::AuthorityCli::Remote(url.to_string()),
    };
    let sidecar_cli = match args.sidecar.as_deref() {
        None => firma_run::sidecar::SidecarCli::Unset,
        Some("local") => firma_run::sidecar::SidecarCli::Local,
        Some(endpoint) => firma_run::sidecar::SidecarCli::Remote(endpoint.to_string()),
    };
    let input = RunInput {
        profile,
        config: run_config,
        backend: args.backend.map(Into::into),
        capability_file: args.capability_file,
        identity_mode: args.identity_mode.map(Into::into),
        preserve_host_user: args.preserve_host_user,
        print_effective_config: args.print_effective_config,
        sidecar_cli,
        no_autostart: args.no_autostart,
        sidecar_template_path: args.sidecar_config,
        sidecar_startup_timeout_secs: args.sidecar_startup_timeout_secs,
        command: args.command,
        authority_cli,
        authority_profile: args.authority_profile,
        user_config_path: None,
        allow_non_structural: args.allow_non_structural,
    };
    match execute_run(&input) {
        Ok(code) => Ok(exit_code(code)),
        Err(error) => Err(anyhow::anyhow!("{error}")),
    }
}

fn maybe_implicit_init(args: &RunArgs) -> anyhow::Result<()> {
    if args.config.is_some() {
        // Trust the user-supplied config path. If it does not exist we
        // let firma-run report the parse/IO error normally.
        return Ok(());
    }
    // Spec §4 step 1 + §5: walk-up `./.firma/firma.toml` is the project-local
    // tier, picked up by `firma_config::resolve_config`. If anything in the
    // search path resolves, skip implicit init.
    if firma_config::resolve_config("run", None, &firma_config::SystemDirs).is_ok() {
        return Ok(());
    }

    // Spec §4.1: implicit init creates a long-lived Ed25519 key under
    // $XDG_DATA_HOME/firma/authority/keys/ and persists `[authority]` to
    // `firma.toml`. Both are security-relevant side effects. Gate them on
    // a deliberate user choice — `--authority` flag, or an interactive
    // y/N prompt — before any filesystem mutation.
    let authority = resolve_implicit_init_authority(args)?;

    let cwd = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("resolve cwd for implicit init: {e}"))?;
    let resolved = cwd.join(".firma");
    let firma_toml = resolved.join(firma_config::CONFIG_FILE_NAME);
    info!(
        path = %firma_toml.display(),
        "no firma.toml found; running implicit init with defaults into cwd/.firma"
    );

    let state_dir = firma_stack::resolve_state_dir(None)
        .map_err(|e| anyhow::anyhow!("resolve state_dir for implicit init: {e}"))?;

    let plan = ScaffoldPlan {
        config_dir: resolved,
        state_dir,
        workspace: cwd,
        force: false,
        authority_listen: "127.0.0.1:50051".into(),
        agent: args
            .profile
            .clone()
            .unwrap_or_else(|| "my-agent".to_string()),
        provider: profile_to_provider(args.profile.as_deref()),
        authority,
    };
    if let Err(error) = scaffold_from_plan(&plan) {
        warn!(%error, "implicit init failed; continuing — firma-run will surface the underlying error");
        return Err(error.context("implicit init"));
    }
    Ok(())
}

/// Decide the authority shape for implicit init.
///
/// `--authority` is a commitment that bypasses the prompt. `--no-autostart`
/// refuses any side-effecting scaffold. Otherwise the user must answer Y
/// to a single y/N prompt on the controlling TTY; non-TTY aborts.
fn resolve_implicit_init_authority(args: &RunArgs) -> anyhow::Result<AuthorityShape> {
    if args.no_autostart {
        anyhow::bail!(
            "no firma.toml found and `--no-autostart` is set; \
             run `firma config` to scaffold a project config, or omit `--no-autostart`"
        );
    }
    if let Some(value) = args.authority.as_deref() {
        return Ok(match value {
            "local" => AuthorityShape::Local,
            _ => anyhow::bail!(
                "no firma.toml found and remote `--authority <url>` cannot be scaffolded implicitly; \
                 run `firma config --mode agent-remote` with --authority-url, \
                 --authority-ca-cert, and --authority-pub-key"
            ),
        });
    }

    let mut prompt = firma_run::authority::StdAuthorityPrompt;
    if !prompt.is_tty() {
        anyhow::bail!(
            "no firma.toml found and stdin is not a terminal; \
             run `firma config` to scaffold a project config, or pass \
             `--authority local` to commit to local implicit setup non-interactively"
        );
    }
    let confirmed = prompt
        .confirm(firma_run::authority::bootstrap::PROMPT_TEXT)
        .map_err(|e| anyhow::anyhow!("read y/N answer: {e}"))?;
    if !confirmed {
        anyhow::bail!(
            "local Mini Authority bootstrap declined; \
             run `firma config` to pick a deployment shape interactively, \
             use `firma config --mode agent-remote` for a remote authority, \
             or re-run with `--authority local` to bypass this prompt"
        );
    }
    Ok(AuthorityShape::Local)
}

fn validate_sidecar_endpoint_flag(args: &RunArgs) -> anyhow::Result<()> {
    let Some(value) = args.sidecar.as_deref() else {
        return Ok(());
    };
    if value == "local" {
        return Ok(());
    }

    firma_run::sidecar::resolve(
        &firma_run::sidecar::SidecarCli::Remote(value.to_string()),
        false,
        None,
    )
    .map(|_| ())
    .map_err(|error| anyhow::anyhow!("{error}"))
}

fn resolve_profile_name(
    cli_profile: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> String {
    if let Some(p) = cli_profile {
        return p.to_string();
    }
    if let Some(path) = config_path
        && let Ok(Some(p)) = firma_run::config::read_configured_profile(path)
    {
        return p;
    }
    "generic".to_string()
}

fn profile_to_provider(profile: Option<&str>) -> String {
    profile
        .and_then(firma_config::AgentProfile::from_name)
        .map_or("anthropic", firma_config::AgentProfile::provider)
        .to_string()
}

fn exit_code(code: i32) -> ExitCode {
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        let exit = u8::try_from(code).unwrap_or(1);
        ExitCode::from(exit)
    }
}
