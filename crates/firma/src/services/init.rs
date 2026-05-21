//! Wire `firma init` CLI args to the scaffolding routine.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::args::init::InitArgs;

const DEFAULT_AGENT: &str = "generic";
const DEFAULT_PROVIDER: &str = "anthropic";

/// Resolved scaffold parameters after CLI flags + wizard + defaults are
/// merged. Pure data — no I/O. Reused by `firma run` for implicit init.
#[derive(Debug, Clone)]
pub struct ScaffoldPlan {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub force: bool,
    pub authority_listen: String,
    pub sidecar_listen: String,
    pub agent: String,
    pub provider: String,
    /// Authority shape: either a local Mini Authority or a remote URL.
    pub authority: AuthorityShape,
}

/// What gets written into the `[authority]` section of firma.toml.
#[derive(Debug, Clone)]
pub enum AuthorityShape {
    /// Autostart a local Mini Authority bound to `authority_listen`.
    Local,
    /// Talk to an existing authority at the given URL.
    Remote(String),
}

/// Top-level entry point invoked from `main.rs`.
pub fn run(args: InitArgs) -> ExitCode {
    let plan = match build_plan(args) {
        Ok(plan) => plan,
        Err(error) => return fail(&error),
    };
    match scaffold_from_plan(&plan) {
        Ok(()) => {
            println!(
                "firma initialized\n  config_dir: {}\n  state_dir:  {}\n  agent:      {}\n  provider:   {}",
                plan.config_dir.display(),
                plan.state_dir.display(),
                plan.agent,
                plan.provider,
            );
            match &plan.authority {
                AuthorityShape::Local => {
                    println!("  authority:  local ({})", plan.authority_listen);
                    println!(
                        "  note:       local authority runs over loopback http:// for dev convenience (no mTLS)"
                    );
                }
                AuthorityShape::Remote(url) => println!("  authority:  remote ({url})"),
            }
            println!("\nnext:");
            println!("  firma run <agent>           # one-command path");
            println!("  firma sidecar start         # explicit daemon start");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("init: {error}")),
    }
}

fn build_plan(args: InitArgs) -> Result<ScaffoldPlan, String> {
    let interactive = !args.yes && stdin_is_tty();

    let mut workspace = args.workspace.clone();
    let mut agent = args.agent.clone();
    let mut provider = args.provider.clone();
    let mut authority_raw = args.authority.clone();

    // `--global` and `--config-dir` short-circuit the workspace prompt;
    // the wizard only asks about workspace when the resulting config dir
    // would still be project-local.
    let prompt_for_workspace = !args.global && args.config_dir.is_none();

    if interactive {
        if prompt_for_workspace && workspace.is_none() {
            workspace = Some(prompt_path(
                "workspace path",
                &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?);
        }
        if agent.is_none() {
            agent = Some(prompt_with_default(
                "agent (codex | claude | generic)",
                DEFAULT_AGENT,
            )?);
        }
        if provider.is_none() {
            provider = Some(prompt_with_default(
                "provider (anthropic | openai | other)",
                DEFAULT_PROVIDER,
            )?);
        }
        if authority_raw.is_none() {
            authority_raw = Some(prompt_with_default(
                "authority (`local` or URL like https://firma-auth.example)",
                "local",
            )?);
        }
    }

    let workspace =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let config_dir = if let Some(cd) = args.config_dir.clone() {
        cd
    } else if args.global {
        firma_config::default_config_dir(&firma_config::SystemDirs).ok_or_else(|| {
            "--global: no user-global config dir resolvable on this platform".to_string()
        })?
    } else {
        workspace.join(".firma")
    };

    let state_dir = match args
        .state_dir
        .clone()
        .map_or_else(|| firma_stack::resolve_state_dir(None), Ok)
    {
        Ok(d) => d,
        Err(error) => return Err(format!("state_dir: {error}")),
    };

    let authority = match authority_raw.as_deref() {
        None | Some("" | "local") => AuthorityShape::Local,
        Some(other) => AuthorityShape::Remote(other.to_string()),
    };

    Ok(ScaffoldPlan {
        config_dir,
        state_dir,
        force: args.force,
        authority_listen: args.authority_listen,
        sidecar_listen: args.sidecar_listen,
        agent: agent.unwrap_or_else(|| DEFAULT_AGENT.to_string()),
        provider: provider.unwrap_or_else(|| DEFAULT_PROVIDER.to_string()),
        authority,
    })
}

fn stdin_is_tty() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal()
}

fn prompt_with_default(label: &str, default: &str) -> Result<String, String> {
    print!("[firma init] {label} [{default}]: ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("stdout flush: {e}"))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("read prompt: {e}"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_path(label: &str, default: &Path) -> Result<PathBuf, String> {
    let default_str = default.display().to_string();
    Ok(PathBuf::from(prompt_with_default(label, &default_str)?))
}

/// Scaffold from an already-resolved plan. `firma run` calls this when it
/// detects a missing `firma.toml` at launch time.
///
/// # Errors
///
/// Returns a formatted string on any filesystem or key-generation
/// failure. Fail-closed: a partial scaffold is not retried implicitly.
pub fn scaffold_from_plan(plan: &ScaffoldPlan) -> Result<(), String> {
    scaffold_at(plan)
}

#[allow(clippy::too_many_lines)]
fn scaffold_at(plan: &ScaffoldPlan) -> Result<(), String> {
    // Absolutize the user-supplied paths once. Relative paths get re-joined
    // by the spawned children (against their CWD), which leads to surprising
    // double-joining. Writing absolute paths into the generated TOML keeps
    // resolution unambiguous regardless of where children run.
    let config_dir = absolutize(&plan.config_dir)
        .map_err(|e| format!("resolve config_dir {}: {e}", plan.config_dir.display()))?;
    let state_dir = absolutize(&plan.state_dir)
        .map_err(|e| format!("resolve state_dir {}: {e}", plan.state_dir.display()))?;
    let config_dir = &config_dir;
    let state_dir = &state_dir;
    info!(
        config_dir = %config_dir.display(),
        state_dir = %state_dir.display(),
        force = plan.force,
        "scaffolding firma"
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
    write_if_absent(&state_dir.join("revocations.txt"), b"", plan.force)?;
    let audit_key_path = config_dir.join("audit.key");
    if plan.force || !audit_key_path.exists() {
        info!(path = %audit_key_path.display(), "generating audit signing key");
        let pem = generate_audit_key_pem()?;
        write_if_absent(&audit_key_path, pem.as_bytes(), plan.force)?;
    } else {
        debug!(path = %audit_key_path.display(), "audit key already exists; preserving");
    }

    let authority_key = config_dir.join("authority.key");
    if plan.force || !authority_key.exists() {
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
        plan.force,
    )?;

    let authority_section = match &plan.authority {
        AuthorityShape::Local => format!(
            r#"[authority]
type                = "local"
listen_addr         = "{listen}"
policy_dir          = '{policy_dir}'
issuance_policy_dir = '{issuance_dir}'
revocation_file     = '{revocation_file}'
key_file            = '{key_file}'
max_ttl_seconds     = 3600
bundle_ttl_seconds  = 30

[sidecar.policy]
authority_url = "http://{listen}"
"#,
            listen = plan.authority_listen,
            policy_dir = config_dir.join("policies").display(),
            issuance_dir = config_dir.join("issuance-policies").display(),
            revocation_file = state_dir.join("revocations.txt").display(),
            key_file = config_dir.join("authority.key").display(),
        ),
        AuthorityShape::Remote(url) => format!(
            r#"[authority]
type = "remote"
url  = "{url}"

[sidecar.policy]
authority_url = "{url}"
"#
        ),
    };

    let project_section = format!(
        r#"[project]
agent    = "{agent}"
provider = "{provider}"

"#,
        agent = plan.agent,
        provider = plan.provider,
    );

    let firma_toml = format!(
        r#"{project}{authority}
[sidecar.interceptor]
mode        = "http_proxy"
listen_addr = "{sidecar_listen}"

[sidecar.ca]
dir = '{ca_dir}'

[sidecar.audit]
signing_key_path = '{audit_key}'

[sidecar.mapping]
rules_path = '{rules_path}'
"#,
        project = project_section,
        authority = authority_section,
        sidecar_listen = plan.sidecar_listen,
        ca_dir = state_dir.join("generated-firma-ca").display(),
        audit_key = config_dir.join("audit.key").display(),
        rules_path = config_dir.join("mapping-rules.toml").display(),
    );
    debug!("writing firma.toml");
    write_if_absent(
        &config_dir.join("firma.toml"),
        firma_toml.as_bytes(),
        plan.force,
    )?;

    info!("scaffold complete");
    Ok(())
}

fn absolutize(path: &Path) -> std::io::Result<PathBuf> {
    std::path::absolute(path)
}

/// Generate a fresh P-256 ECDSA private key in PKCS#8 PEM form for the
/// sidecar's audit signing material. Each `firma init` produces a unique key
/// so audit-log signatures are not forgeable from shared source material.
fn generate_audit_key_pem() -> Result<String, String> {
    let seed = Sha256::digest(uuid::Uuid::new_v4().as_bytes());
    let signing_key = SigningKey::from_slice(seed.as_ref())
        .map_err(|e| format!("generate audit signing key: {e}"))?;
    signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|e| format!("encode audit signing key pem: {e}"))
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

/// Resolve `state_dir` for sidecar start/stop, monitor, doctor.
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

fn fail(msg: &str) -> ExitCode {
    eprintln!("firma init: {msg}");
    ExitCode::from(2)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn plan(cfg: &Path, state: &Path) -> ScaffoldPlan {
        ScaffoldPlan {
            config_dir: cfg.to_path_buf(),
            state_dir: state.to_path_buf(),
            force: true,
            authority_listen: "127.0.0.1:50051".into(),
            sidecar_listen: "127.0.0.1:8080".into(),
            agent: "generic".into(),
            provider: "anthropic".into(),
            authority: AuthorityShape::Local,
        }
    }

    #[test]
    fn scaffolds_one_sectioned_firma_toml() {
        let cfg = tempdir().unwrap();
        let state = tempdir().unwrap();
        scaffold_from_plan(&plan(cfg.path(), state.path())).unwrap();

        let firma_toml = cfg.path().join("firma.toml");
        assert!(firma_toml.is_file(), "firma.toml created");
        assert!(!cfg.path().join("authority.toml").exists());
        assert!(!cfg.path().join("sidecar.toml").exists());

        let text = std::fs::read_to_string(&firma_toml).unwrap();
        let t: toml::Table = text.parse().unwrap();

        let project = t.get("project").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            project.get("agent").and_then(toml::Value::as_str),
            Some("generic")
        );
        assert_eq!(
            project.get("provider").and_then(toml::Value::as_str),
            Some("anthropic")
        );

        let auth = t.get("authority").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            auth.get("type").and_then(toml::Value::as_str),
            Some("local")
        );
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

    #[test]
    fn remote_authority_writes_url_section() {
        let cfg = tempdir().unwrap();
        let state = tempdir().unwrap();
        let mut p = plan(cfg.path(), state.path());
        p.authority = AuthorityShape::Remote("https://firma-auth.example".into());
        scaffold_from_plan(&p).unwrap();

        let text = std::fs::read_to_string(cfg.path().join("firma.toml")).unwrap();
        let t: toml::Table = text.parse().unwrap();
        let auth = t.get("authority").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            auth.get("type").and_then(toml::Value::as_str),
            Some("remote")
        );
        assert_eq!(
            auth.get("url").and_then(toml::Value::as_str),
            Some("https://firma-auth.example")
        );
    }
}
