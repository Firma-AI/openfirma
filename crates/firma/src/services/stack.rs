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
    let Some(config_dir) = args
        .config_dir
        .clone()
        .or_else(|| firma_config::default_config_dir(&firma_config::SystemDirs))
    else {
        return fail("init: cannot resolve a default config dir; pass --config-dir");
    };
    let state_dir = match args
        .state_dir
        .clone()
        .map_or_else(|| firma_stack::resolve_state_dir(None), Ok)
    {
        Ok(d) => d,
        Err(error) => return fail(&format!("init: state_dir: {error}")),
    };
    match init_scaffold_at(
        &config_dir,
        &state_dir,
        args.force,
        &args.authority_listen,
        &args.sidecar_listen,
    ) {
        Ok(()) => {
            println!(
                "firma stack initialized\n  config_dir: {}\n  state_dir:  {}",
                config_dir.display(),
                state_dir.display(),
            );
            println!("next:\n  firma stack start");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("init: {error}")),
    }
}

#[cfg(test)]
fn init_scaffold(args: &InitArgs) -> Result<(), String> {
    let config_dir = args
        .config_dir
        .clone()
        .ok_or("config_dir required in test")?;
    let state_dir = args.state_dir.clone().ok_or("state_dir required in test")?;
    init_scaffold_at(
        &config_dir,
        &state_dir,
        args.force,
        &args.authority_listen,
        &args.sidecar_listen,
    )
}

#[allow(clippy::too_many_lines)]
fn init_scaffold_at(
    config_dir: &Path,
    state_dir: &Path,
    force: bool,
    authority_listen: &str,
    sidecar_listen: &str,
) -> Result<(), String> {
    // Absolutize the user-supplied paths once. Relative paths get re-joined
    // by the spawned children (against their CWD), which leads to surprising
    // double-joining. Writing absolute paths into the generated TOML keeps
    // resolution unambiguous regardless of where `firma stack start` runs.
    let config_dir = absolutize(config_dir)
        .map_err(|e| format!("resolve config_dir {}: {e}", config_dir.display()))?;
    let state_dir = absolutize(state_dir)
        .map_err(|e| format!("resolve state_dir {}: {e}", state_dir.display()))?;
    let config_dir = &config_dir;
    let state_dir = &state_dir;
    info!(
        config_dir = %config_dir.display(),
        state_dir = %state_dir.display(),
        force,
        "scaffolding firma stack"
    );

    for sub in ["", "policies", "issuance-policies"] {
        let path = config_dir.join(sub);
        debug!(path = %path.display(), "mkdir config subdir");
        std::fs::create_dir_all(&path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
        #[cfg(unix)]
        set_dir_mode_0700(&path)?;
    }
    for sub in ["", "generated-firma-ca"] {
        let path = state_dir.join(sub);
        debug!(path = %path.display(), "mkdir state subdir");
        std::fs::create_dir_all(&path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
        #[cfg(unix)]
        set_dir_mode_0700(&path)?;
    }

    debug!("writing revocations.txt");
    write_if_absent(&state_dir.join("revocations.txt"), b"", force)?;
    debug!("writing audit.key");
    write_if_absent(
        &config_dir.join("audit.key"),
        DEMO_AUDIT_KEY_PEM.as_bytes(),
        force,
    )?;

    let authority_key = config_dir.join("authority.key");
    if force || !authority_key.exists() {
        info!(path = %authority_key.display(), "generating authority signing key");
        crate::services::authority::run_generate_key(&authority_key)
            .map_err(|e| format!("generate-key: {e}"))?;
    } else {
        debug!(path = %authority_key.display(), "authority key already exists; preserving");
    }

    debug!("writing mapping-rules.toml");
    write_if_absent(
        &config_dir.join("mapping-rules.toml"),
        b"# Placeholder rule; replace with real mappings for your workload.\n\
          [[rules]]\n\
          host = \"example.invalid\"\n\
          action_class = \"filesystem.read\"\n",
        force,
    )?;

    let firma_toml = format!(
        r#"[authority]
listen_addr         = "{authority_listen}"
policy_dir          = '{policy_dir}'
issuance_policy_dir = '{issuance_dir}'
revocation_file     = '{revocation_file}'
key_file            = '{key_file}'
max_ttl_seconds     = 3600
bundle_ttl_seconds  = 30

[sidecar.interceptor]
mode        = "http_proxy"
listen_addr = "{sidecar_listen}"

[sidecar.policy]
authority_url = "http://{authority_listen}"

[sidecar.ca]
dir = '{ca_dir}'

[sidecar.audit]
signing_key_path = '{audit_key}'

[sidecar.mapping]
rules_path = '{rules_path}'
"#,
        policy_dir = config_dir.join("policies").display(),
        issuance_dir = config_dir.join("issuance-policies").display(),
        revocation_file = state_dir.join("revocations.txt").display(),
        key_file = config_dir.join("authority.key").display(),
        ca_dir = state_dir.join("generated-firma-ca").display(),
        audit_key = config_dir.join("audit.key").display(),
        rules_path = config_dir.join("mapping-rules.toml").display(),
    );
    debug!("writing firma.toml");
    write_if_absent(&config_dir.join("firma.toml"), firma_toml.as_bytes(), force)?;

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

/// Set directory mode to `0700` on Unix. No-op on other platforms (Windows
/// uses ACLs; the directory inherits the parent's ACL, which for user-owned
/// scaffolding is already restricted to the calling user).
///
/// Tighter than the default `create_dir_all` mode (`0777 & !umask`) because
/// the state and config dirs hold private keys, sockets, and audit material
/// that other local UIDs must not be able to read or attach to.
#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .map_err(|e| format!("chmod 0700 {}: {e}", path.display()))?;

    Ok(())
}

/// Resolve `state_dir` for stop/status/monitor/doctor.
///
/// Order: explicit `--state-dir` (or `FIRMA_STATE_DIR`) → XDG/platform
/// default via [`firma_stack::resolve_state_dir`]. State is never read
/// from the config file.
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

fn run_start(args: StartArgs) -> ExitCode {
    info!(
        detach = args.detach,
        config = ?args.config,
        state_dir = ?args.state_dir,
        "firma stack start invoked"
    );
    let cfg = match firma_stack::resolve_stack_config(args.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(error) => return fail(&format!("config: {error}")),
    };
    let state_dir = match resolve_state_dir(args.state_dir) {
        Ok(path) => path,
        Err(error) => return fail(&error),
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
    let state_dir = match resolve_state_dir(args.state_dir) {
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
    let state_dir = match resolve_state_dir(args.state_dir) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::args::stack::InitArgs;
    use tempfile::tempdir;

    fn init_args(cfg: &Path, state: &Path) -> InitArgs {
        InitArgs {
            config_dir: Some(cfg.to_path_buf()),
            state_dir: Some(state.to_path_buf()),
            force: true,
            authority_listen: "127.0.0.1:50051".into(),
            sidecar_listen: "127.0.0.1:8080".into(),
        }
    }

    #[test]
    fn scaffolds_one_sectioned_firma_toml() {
        let cfg = tempdir().unwrap();
        let state = tempdir().unwrap();
        init_scaffold(&init_args(cfg.path(), state.path())).unwrap();

        let firma_toml = cfg.path().join("firma.toml");
        assert!(firma_toml.is_file(), "firma.toml created");
        assert!(!cfg.path().join("authority.toml").exists());
        assert!(!cfg.path().join("sidecar.toml").exists());
        assert!(!cfg.path().join("firma-stack.toml").exists());

        let text = std::fs::read_to_string(&firma_toml).unwrap();
        let t: toml::Table = text.parse().unwrap();
        let auth = t.get("authority").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            auth.get("listen_addr").and_then(toml::Value::as_str),
            Some("127.0.0.1:50051")
        );
        let side = t.get("sidecar").and_then(toml::Value::as_table).unwrap();
        assert!(
            side.get("interceptor")
                .and_then(toml::Value::as_table)
                .is_some()
        );
        assert!(side.get("policy").and_then(toml::Value::as_table).is_some());

        let abody = firma_config::load_section(&firma_toml, "authority").unwrap();
        let _: firma_authority::AuthorityConfig = toml::from_str(&abody).unwrap();
        let sbody = firma_config::load_section(&firma_toml, "sidecar").unwrap();
        let _: firma_sidecar::config::SidecarConfig = toml::from_str(&sbody).unwrap();
    }
}
