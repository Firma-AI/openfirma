//! Runner for `firma run`.

use std::process::ExitCode;

use firma_run::runtime::{RunInput, execute_run};
use tracing::{info, warn};

use crate::args::run::RunArgs;
use crate::services::init::{AuthorityShape, ScaffoldPlan, scaffold_from_plan};

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

    // Implicit init: if no firma.toml is discoverable for this project,
    // scaffold one before handing off to firma-run. Keeps the spec's
    // one-command path (`firma run codex`) working from a fresh clone.
    maybe_implicit_init(&args)?;

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
        profile: args.profile,
        config: args.config,
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
    };
    match execute_run(&input) {
        Ok(code) => Ok(exit_code(code)),
        Err(error) => Err(anyhow::anyhow!("{error}")),
    }
}

fn maybe_implicit_init(args: &RunArgs) -> anyhow::Result<()> {
    if let Some(explicit) = args.config.as_ref() {
        // Trust the user-supplied config path. If it does not exist we
        // let firma-run report the parse/IO error normally.
        if explicit.exists() {
            return Ok(());
        }
    }
    // Spec §4 step 1 + §5: walk-up `./.firma/firma.toml` is the project-local
    // tier, picked up by `firma_config::resolve_config`. If anything in the
    // search path resolves, skip implicit init.
    if firma_config::resolve_config("run", None, &firma_config::SystemDirs).is_ok() {
        return Ok(());
    }
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

    // Match the persisted [authority] section to whatever the CLI is
    // about to ask firma-run to do. Default = local mini authority.
    let authority = match args.authority.as_deref() {
        None | Some("local") => AuthorityShape::Local,
        Some(url) => AuthorityShape::Remote(url.to_string()),
    };

    let plan = ScaffoldPlan {
        config_dir: resolved,
        state_dir,
        force: false,
        authority_listen: "127.0.0.1:50051".into(),
        sidecar_listen: "127.0.0.1:8080".into(),
        agent: args.profile.clone(),
        provider: "anthropic".into(),
        authority,
    };
    if let Err(error) = scaffold_from_plan(&plan) {
        warn!(%error, "implicit init failed; continuing — firma-run will surface the underlying error");
        return Err(anyhow::anyhow!("implicit init: {error}"));
    }
    Ok(())
}

fn exit_code(code: i32) -> ExitCode {
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        let exit = u8::try_from(code).unwrap_or(1);
        ExitCode::from(exit)
    }
}
