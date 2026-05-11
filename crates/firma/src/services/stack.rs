//! Wire `firma stack` CLI args to the `firma-stack` library.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use tracing::{debug, info};

use crate::args::stack::{InitArgs, StackArgs, StackCommand, StartArgs, StatusArgs, StopArgs};

pub fn run(args: StackArgs) -> ExitCode {
    match args.command {
        StackCommand::Init(args) => run_init(&args),
        StackCommand::Start(args) => run_start(args),
        StackCommand::Stop(args) => run_stop(args),
        StackCommand::Status(args) => run_status(args),
    }
}

const DEMO_AUDIT_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
";

fn run_init(args: &InitArgs) -> ExitCode {
    match init_scaffold(args) {
        Ok(()) => {
            println!(
                "firma stack initialized\n  config_dir: {}\n  state_dir:  {}",
                args.config_dir.display(),
                args.state_dir.display(),
            );
            println!("next:");
            #[cfg(unix)]
            println!(
                "  firma stack start --config {}/firma-stack.toml",
                args.config_dir.display(),
            );
            #[cfg(windows)]
            println!(
                "  firma stack start --config {}\\firma-stack.toml",
                args.config_dir.display(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("init: {error}")),
    }
}

#[allow(clippy::too_many_lines)]
fn init_scaffold(args: &InitArgs) -> Result<(), String> {
    // Absolutize the user-supplied paths once. Relative paths get re-joined
    // by `load_stack_config` (against the stack TOML's parent dir) and by the
    // spawned children (against their CWD), which leads to surprising
    // double-joining like `..\test\config\..\test\config\authority.toml`.
    // Writing absolute paths into every generated TOML keeps resolution
    // unambiguous regardless of where `firma stack start` is invoked from.
    let config_dir = absolutize(&args.config_dir)
        .map_err(|e| format!("resolve config_dir {}: {e}", args.config_dir.display()))?;
    let state_dir = absolutize(&args.state_dir)
        .map_err(|e| format!("resolve state_dir {}: {e}", args.state_dir.display()))?;
    let config_dir = &config_dir;
    let state_dir = &state_dir;
    info!(
        config_dir = %config_dir.display(),
        state_dir = %state_dir.display(),
        force = args.force,
        "scaffolding firma stack"
    );

    // Config dir: TOMLs, keys, policy dirs.
    for sub in ["", "policies", "issuance-policies"] {
        let path = config_dir.join(sub);
        debug!(path = %path.display(), "mkdir config subdir");
        std::fs::create_dir_all(&path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }
    // State dir: revocations + generated-CA. Mutable runtime artifacts.
    for sub in ["", "generated-firma-ca"] {
        let path = state_dir.join(sub);
        debug!(path = %path.display(), "mkdir state subdir");
        std::fs::create_dir_all(&path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }

    debug!("writing revocations.txt");
    write_if_absent(&state_dir.join("revocations.txt"), b"", args.force)?;
    debug!("writing audit.key");
    write_if_absent(
        &config_dir.join("audit.key"),
        DEMO_AUDIT_KEY_PEM.as_bytes(),
        args.force,
    )?;

    let authority_key = config_dir.join("authority.key");
    if args.force || !authority_key.exists() {
        info!(path = %authority_key.display(), "generating authority signing key");
        crate::services::authority::run_generate_key(&authority_key)
            .map_err(|e| format!("generate-key: {e}"))?;
    } else {
        debug!(path = %authority_key.display(), "authority key already exists; preserving");
    }

    let authority_toml = format!(
        r#"listen_addr         = "{listen}"
policy_dir          = '{policy_dir}'
issuance_policy_dir = '{issuance_dir}'
revocation_file     = '{revocation_file}'
key_file            = '{key_file}'
max_ttl_seconds     = 3600
bundle_ttl_seconds  = 30
"#,
        listen = args.authority_listen,
        policy_dir = config_dir.join("policies").display(),
        issuance_dir = config_dir.join("issuance-policies").display(),
        revocation_file = state_dir.join("revocations.txt").display(),
        key_file = config_dir.join("authority.key").display(),
    );
    debug!("writing authority.toml");
    write_if_absent(
        &config_dir.join("authority.toml"),
        authority_toml.as_bytes(),
        args.force,
    )?;

    let sidecar_toml = format!(
        r#"[interceptor]
listen_addr = "{listen}"

[policy]
authority_url = "http://{authority}"

[ca]
dir = '{ca_dir}'

[audit]
signing_key_path = '{audit_key}'

[mapping]
rules_path = '{rules_path}'
"#,
        listen = args.sidecar_listen,
        authority = args.authority_listen,
        ca_dir = state_dir.join("generated-firma-ca").display(),
        audit_key = config_dir.join("audit.key").display(),
        rules_path = config_dir.join("mapping-rules.toml").display(),
    );
    debug!("writing sidecar.toml");
    write_if_absent(
        &config_dir.join("sidecar.toml"),
        sidecar_toml.as_bytes(),
        args.force,
    )?;
    debug!("writing mapping-rules.toml");
    write_if_absent(
        &config_dir.join("mapping-rules.toml"),
        b"# Placeholder rule; replace with real mappings for your workload.\n\
          [[rules]]\n\
          host = \"example.invalid\"\n\
          action_class = \"filesystem.read\"\n",
        args.force,
    )?;

    let stack_toml = format!(
        r"state_dir        = '{state_dir}'
authority_config = '{authority_config}'
sidecar_config   = '{sidecar_config}'
",
        state_dir = state_dir.display(),
        authority_config = config_dir.join("authority.toml").display(),
        sidecar_config = config_dir.join("sidecar.toml").display(),
    );
    debug!("writing firma-stack.toml");
    write_if_absent(
        &config_dir.join("firma-stack.toml"),
        stack_toml.as_bytes(),
        args.force,
    )?;

    info!("scaffold complete");
    Ok(())
}

fn absolutize(path: &Path) -> std::io::Result<PathBuf> {
    std::path::absolute(path)
}

fn write_if_absent(path: &Path, content: &[u8], force: bool) -> Result<(), String> {
    if !force && path.exists() {
        return Ok(());
    }
    std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Resolve `state_dir` for stop/status/monitor.
///
/// Order: explicit `--state-dir` (or `FIRMA_STATE_DIR` env) → `state_dir` field
/// from the stack config file at `config_path` if set → XDG/platform default
/// via [`firma_stack::resolve_state_dir`].
pub(crate) fn resolve_state_dir(
    flag: Option<PathBuf>,
    config_path: Option<&Path>,
) -> Result<PathBuf, String> {
    if let Some(path) = flag {
        return Ok(path);
    }
    if let Ok(env) = std::env::var("FIRMA_STATE_DIR") {
        if !env.is_empty() {
            return Ok(PathBuf::from(env));
        }
    }
    if let Some(path) = config_path {
        match firma_stack::load_stack_config(path) {
            Ok(cfg) => {
                if let Some(state_dir) = cfg.state_dir {
                    return Ok(state_dir);
                }
            }
            Err(error) => return Err(format!("config: {error}")),
        }
    }
    firma_stack::resolve_state_dir(None).map_err(|error| format!("state_dir: {error}"))
}

fn run_start(args: StartArgs) -> ExitCode {
    info!(
        detach = args.detach,
        config = ?args.config,
        state_dir = ?args.state_dir,
        "firma stack start invoked"
    );
    let cfg_path = args
        .config
        .unwrap_or_else(|| PathBuf::from("firma-stack.toml"));
    let cfg = match firma_stack::load_stack_config(&cfg_path) {
        Ok(cfg) => cfg,
        Err(error) => return fail(&format!("config: {error}")),
    };
    let state_flag = args.state_dir.or_else(|| cfg.state_dir.clone());
    let state_dir = match firma_stack::resolve_state_dir(state_flag) {
        Ok(path) => path,
        Err(error) => return fail(&format!("state_dir: {error}")),
    };
    let mode = if args.detach {
        firma_stack::StartMode::Detached
    } else {
        firma_stack::StartMode::Foreground
    };
    match firma_stack::start(&cfg, &state_dir, mode) {
        Ok(_) => {
            if mode == firma_stack::StartMode::Detached {
                println!("firma stack running, state_dir={}", state_dir.display());
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("start: {error}")),
    }
}

fn run_stop(args: StopArgs) -> ExitCode {
    info!(timeout = args.timeout, "firma stack stop invoked");
    let state_dir = match resolve_state_dir(args.state_dir, args.config.as_deref()) {
        Ok(path) => path,
        Err(error) => return fail(&error),
    };
    match firma_stack::stop(&state_dir, Duration::from_secs(args.timeout)) {
        // Either path succeeded as long as the call returned. `forced=true`
        // means at least one child needed a hard kill — common when the
        // components hold long-lived gRPC streams that block tonic's
        // graceful shutdown. The stack is down either way.
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("stop: {error}")),
    }
}

fn run_status(args: StatusArgs) -> ExitCode {
    info!(json = args.json, "firma stack status invoked");
    let state_dir = match resolve_state_dir(args.state_dir, args.config.as_deref()) {
        Ok(path) => path,
        Err(error) => return fail(&error),
    };
    let status = match firma_stack::status(&state_dir) {
        Ok(status) => status,
        Err(error) => return fail(&format!("status: {error}")),
    };
    debug!(components = status.components.len(), "status loaded");
    if args.json {
        match serde_json::to_string(&status) {
            Ok(json) => println!("{json}"),
            Err(error) => return fail(&format!("status json: {error}")),
        }
    } else {
        print_pretty(&status);
    }
    classify(&status)
}

fn print_pretty(status: &firma_stack::StackStatus) {
    println!(
        "{:<11} {:<7} {:<10} {:<20} UPTIME",
        "COMPONENT", "PID", "STATE", "LISTEN"
    );
    for component in &status.components {
        let pid = component
            .pid
            .map_or_else(|| "-".to_string(), |pid| pid.to_string());
        let listen = component
            .listen
            .map_or_else(|| "-".to_string(), |addr| addr.to_string());
        let state = format!("{:?}", component.state).to_lowercase();
        let uptime = component.uptime_secs.map_or_else(
            || "-".to_string(),
            |uptime| {
                format!(
                    "{:02}:{:02}:{:02}",
                    uptime / 3600,
                    (uptime / 60) % 60,
                    uptime % 60
                )
            },
        );
        println!(
            "{:<11} {:<7} {:<10} {:<20} {}",
            component.name, pid, state, listen, uptime
        );
    }
}

fn classify(status: &firma_stack::StackStatus) -> ExitCode {
    let mut any_bad = false;
    for component in &status.components {
        match component.state {
            firma_stack::State::Running => {}
            firma_stack::State::Unhealthy | firma_stack::State::Stopped => any_bad = true,
            firma_stack::State::Unknown => return ExitCode::from(2),
        }
    }
    if any_bad {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("firma stack: {msg}");
    ExitCode::from(2)
}
