use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::thread::{self, JoinHandle};

use crate::backend::SandboxHandle;
use crate::config::SidecarEndpoint;
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::sidecar::supervisor::{SidecarSupervisor, SpawnRequest};

#[cfg(unix)]
fn structural_proxy_listen_addr() -> &'static str {
    static ADDR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ADDR.get_or_init(|| {
        std::env::var("FIRMA_PROXY_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:18080".to_string())
    })
}

#[cfg(unix)]
fn structural_dns_stub_listen_addr() -> &'static str {
    static ADDR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ADDR.get_or_init(|| {
        std::env::var("FIRMA_DNS_STUB_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:53".to_string())
    })
}

/// Runtime-side network artifacts that must live while the wrapped process runs.
pub struct NetworkRuntime {
    env_overrides: BTreeMap<String, String>,
    sidecar_endpoint: SidecarEndpoint,
    // Drop order matters: the host bridge and adapter hold connections to the
    // sidecar, so they must drop before the sidecar supervisor.  The sidecar
    // supervisor streams policy from the authority, so it must drop before the
    // authority supervisor.  Rust drops fields top-to-bottom, so declaration
    // order here is load-bearing.
    #[cfg(unix)]
    _host_bridge: Option<crate::proxy_bridge::HostBridgeHandle>,
    #[cfg(unix)]
    _adapter: Option<SidecarAdapter>,
    _sidecar_supervisor: Option<SidecarSupervisor>,
    _authority_supervisor: Option<crate::authority::AuthoritySupervisor>,
}

impl NetworkRuntime {
    /// Returns environment values to merge into wrapped process launch env.
    #[must_use]
    pub fn env_overrides(&self) -> &BTreeMap<String, String> {
        &self.env_overrides
    }

    /// Endpoint the wrapped process should reach the sidecar through.
    /// May differ from the configured profile endpoint when autostart
    /// substituted a UDS path for the per-run sidecar.
    #[must_use]
    pub fn sidecar_endpoint(&self) -> &SidecarEndpoint {
        &self.sidecar_endpoint
    }
}

/// Inputs to [`prepare_network_runtime`] that gate autostart behaviour.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct AutostartFlags {
    /// `true` when the selection resolved to local autostart.
    pub sidecar_autostart: bool,
    pub no_autostart: bool,
    pub template_path: Option<PathBuf>,
    pub startup_timeout: std::time::Duration,
    /// Effective Authority URL — set by `resolve_authority` and threaded
    /// into the synthesized sidecar config.
    pub authority_url: Option<String>,
    /// Path to the CA cert that signed the authority's TLS cert — injected
    /// into `[sidecar.authority].ca_cert_path` during synthesis.
    pub authority_ca_cert: Option<PathBuf>,
    /// Path to the authority's Ed25519 public key — injected into
    /// `[sidecar.authority].public_key_path` and
    /// `[sidecar.preflight].authority_pub_key_path` during synthesis.
    pub authority_pub_key: Option<PathBuf>,
    /// When `true`, the autostarted sidecar is started in HTTP proxy
    /// interceptor mode rather than Unix socket mode.
    pub use_http_proxy_sidecar: bool,
    /// When `true`, inject `mode = "monitor"` into the synthesized sidecar
    /// config. Passed through from `RunInput.monitor_mode`.
    pub monitor_mode: bool,
}

impl Default for AutostartFlags {
    fn default() -> Self {
        Self {
            sidecar_autostart: false,
            no_autostart: false,
            template_path: None,
            startup_timeout: std::time::Duration::from_secs(2),
            authority_url: None,
            authority_ca_cert: None,
            authority_pub_key: None,
            use_http_proxy_sidecar: false,
            monitor_mode: false,
        }
    }
}

/// Resolved Authority for the current run.
pub struct ResolvedAuthority {
    pub url: String,
    /// CA cert path from `[sidecar.authority]`, if present.
    pub ca_cert_path: Option<PathBuf>,
    /// Authority public key path from `[sidecar.authority]`, if present.
    pub pub_key_path: Option<PathBuf>,
    pub supervisor: Option<crate::authority::AuthoritySupervisor>,
}

/// Prepare network runtime artifacts for a sandbox launch.
///
/// When `flags.sidecar_autostart == true` (local selection), autostarts a
/// per-run sidecar via
/// [`SidecarSupervisor`] and substitutes its endpoint into the returned
/// [`NetworkRuntime`]. The supervisor is held inside the returned struct so
/// [`Drop`] tears the sidecar down when the wrapped process exits.
///
/// # Errors
///
/// - [`RunError::SidecarUnreachable`] when the endpoint is unreachable and
///   autostart is disabled.
/// - [`RunError::SidecarReadyTimeout`] / [`RunError::SidecarStartupFailed`]
///   when the autostarted sidecar fails to come up.
/// - [`RunError::UnsupportedPlatform`] when autostart is required on a
///   platform that does not support it.
/// - [`RunError::Backend`] for adapter socket failures.
pub fn prepare_network_runtime(
    handle: &SandboxHandle,
    sidecar_endpoint: &SidecarEndpoint,
    identity: &RunIdentity,
    flags: &AutostartFlags,
    authority: ResolvedAuthority,
) -> Result<NetworkRuntime, RunError> {
    let mut flags = flags.clone();
    flags.authority_url = Some(authority.url.clone());
    flags.authority_ca_cert.clone_from(&authority.ca_cert_path);
    flags.authority_pub_key.clone_from(&authority.pub_key_path);

    let (effective_endpoint, sidecar_supervisor) =
        resolve_effective_endpoint(handle, sidecar_endpoint, identity, &flags)?;
    let autostart_trust_env = sidecar_trust_env_overrides(sidecar_supervisor.as_ref());

    if !handle.network_policy.enforce_network_namespace {
        let env_overrides = autostart_trust_env;
        #[cfg(unix)]
        let mut env_overrides = env_overrides;
        #[cfg(unix)]
        let host_bridge = setup_host_bridge(&effective_endpoint, identity, &mut env_overrides)?;

        return Ok(NetworkRuntime {
            env_overrides,
            sidecar_endpoint: effective_endpoint,
            #[cfg(unix)]
            _host_bridge: Some(host_bridge),
            #[cfg(unix)]
            _adapter: None,
            _sidecar_supervisor: sidecar_supervisor,
            _authority_supervisor: authority.supervisor,
        });
    }

    #[cfg(not(unix))]
    {
        let _ = (effective_endpoint, sidecar_supervisor, authority);
        Err(RunError::UnsupportedBackend {
            backend: handle.backend.to_string(),
            reason: "structural network confinement currently requires unix sockets".to_string(),
        })
    }

    #[cfg(unix)]
    {
        let adapter_path = handle.runtime_dir.join("sidecar-upstream.sock");
        let adapter = SidecarAdapter::start(&adapter_path, &effective_endpoint)?;
        let current_exe = std::env::current_exe().map_err(|error| {
            RunError::Internal(format!(
                "failed to resolve current executable path: {error}"
            ))
        })?;

        let proxy_addr = structural_proxy_listen_addr();
        let dns_addr = structural_dns_stub_listen_addr();
        let mut env_overrides = autostart_trust_env;
        env_overrides.insert("HTTP_PROXY".to_string(), format!("http://{proxy_addr}"));
        env_overrides.insert("HTTPS_PROXY".to_string(), format!("http://{proxy_addr}"));
        env_overrides.insert("http_proxy".to_string(), format!("http://{proxy_addr}"));
        env_overrides.insert("https_proxy".to_string(), format!("http://{proxy_addr}"));
        env_overrides.insert("ALL_PROXY".to_string(), format!("http://{proxy_addr}"));
        env_overrides.insert("all_proxy".to_string(), format!("http://{proxy_addr}"));
        env_overrides.insert(
            "FIRMA_RUN_PROXY_LISTEN_ADDR".to_string(),
            proxy_addr.to_string(),
        );
        env_overrides.insert(
            "FIRMA_RUN_DNS_STUB_LISTEN_ADDR".to_string(),
            dns_addr.to_string(),
        );
        env_overrides.insert(
            "FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS".to_string(),
            adapter_path.display().to_string(),
        );
        env_overrides.insert(
            "FIRMA_RUN_SELF_EXE".to_string(),
            current_exe.display().to_string(),
        );

        Ok(NetworkRuntime {
            env_overrides,
            sidecar_endpoint: effective_endpoint,
            _host_bridge: None,
            _adapter: Some(adapter),
            _sidecar_supervisor: sidecar_supervisor,
            _authority_supervisor: authority.supervisor,
        })
    }
}

/// Start a host-side proxy bridge for the non-structural (macOS / proxy-mediated)
/// network path and insert `HTTP_PROXY` / `HTTPS_PROXY` env overrides that
/// point the wrapped process at the bridge.
///
/// The bridge injects the full attribution-header set (including
/// `x-firma-session-id`) into every outbound HTTP/CONNECT request before
/// forwarding it to the sidecar's TCP endpoint.  This is the fix for FIR-213:
/// on macOS the entrypoint script that normally starts the in-sandbox bridge
/// subprocess is never run, so without this host-side bridge the sidecar
/// receives an empty `session_id` and denies every request.
///
#[cfg(unix)]
fn setup_host_bridge(
    endpoint: &SidecarEndpoint,
    identity: &RunIdentity,
    env_overrides: &mut BTreeMap<String, String>,
) -> Result<crate::proxy_bridge::HostBridgeHandle, RunError> {
    let SidecarEndpoint::Tcp { addr } = endpoint else {
        return Err(RunError::UnsupportedBackend {
            backend: "non_structural_proxy_bridge".to_string(),
            reason:
                "non-structural networking requires a TCP sidecar endpoint so the host bridge can inject attribution headers"
                    .to_string(),
        });
    };

    let bridge =
        crate::proxy_bridge::HostBridgeHandle::start(*addr, identity.full_attribution_headers())?;
    let bridge_addr = bridge.listen_addr();

    tracing::info!(
        %bridge_addr,
        sidecar_addr = %addr,
        "host proxy bridge started for non-structural network path"
    );

    env_overrides.insert("HTTP_PROXY".to_string(), format!("http://{bridge_addr}"));
    env_overrides.insert("HTTPS_PROXY".to_string(), format!("http://{bridge_addr}"));
    env_overrides.insert("http_proxy".to_string(), format!("http://{bridge_addr}"));
    env_overrides.insert("https_proxy".to_string(), format!("http://{bridge_addr}"));
    env_overrides.insert("ALL_PROXY".to_string(), format!("http://{bridge_addr}"));
    env_overrides.insert("all_proxy".to_string(), format!("http://{bridge_addr}"));

    Ok(bridge)
}

fn sidecar_trust_env_overrides(
    sidecar_supervisor: Option<&SidecarSupervisor>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let Some(supervisor) = sidecar_supervisor else {
        return env;
    };
    let ca_dir = supervisor.marker_dir().join("firma-ca");
    let ca_cert = ca_dir.join("firma-ca.crt");
    env.insert(
        "FIRMA_SIDECAR_CA_DIR".to_string(),
        ca_dir.display().to_string(),
    );
    env.insert(
        "FIRMA_SIDECAR_CA_CERT_PATH".to_string(),
        ca_cert.display().to_string(),
    );
    env
}

fn resolve_effective_endpoint(
    handle: &SandboxHandle,
    sidecar_endpoint: &SidecarEndpoint,
    identity: &RunIdentity,
    flags: &AutostartFlags,
) -> Result<(SidecarEndpoint, Option<SidecarSupervisor>), RunError> {
    // Local selection: autostart unconditionally. `--sidecar local` +
    // `--no-autostart` was already rejected during selection resolution.
    if flags.sidecar_autostart {
        let supervisor = autostart_sidecar(identity, flags)?;
        return Ok((supervisor.endpoint(), Some(supervisor)));
    }

    // External selection: never autostart.
    // `fail_closed = false` is an explicit dev/test escape that disables the
    // probe. It mirrors the pre-FIR-102 behaviour.
    if !handle.network_policy.fail_closed {
        return Ok((sidecar_endpoint.clone(), None));
    }

    match probe_sidecar(sidecar_endpoint) {
        Ok(()) => Ok((sidecar_endpoint.clone(), None)),
        Err(reason) => Err(RunError::SidecarUnreachable {
            endpoint: format_endpoint(sidecar_endpoint),
            reason,
        }),
    }
}

fn autostart_sidecar(
    identity: &RunIdentity,
    flags: &AutostartFlags,
) -> Result<SidecarSupervisor, RunError> {
    let runtime_dir = firma_stack::runtime_paths::default_runtime_dir();
    let marker_dir = firma_stack::runtime_paths::run_entry_from(&runtime_dir, &identity.sandbox_id);
    let firma_exe = std::env::current_exe().map_err(|error| {
        RunError::Internal(format!(
            "failed to resolve current executable path: {error}"
        ))
    })?;
    let env_template = std::env::var("FIRMA_SIDECAR_CONFIG_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let cwd_template = std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join("firma_sidecar.toml"));

    SidecarSupervisor::spawn(SpawnRequest {
        sandbox_id: &identity.sandbox_id,
        agent_id: &identity.profile,
        session_id: &identity.session_id,
        marker_dir,
        template_path: flags.template_path.as_deref(),
        env_template,
        cwd_template,
        firma_exe,
        startup_timeout: flags.startup_timeout,
        authority_url: flags.authority_url.as_deref(),
        authority_ca_cert: flags.authority_ca_cert.clone(),
        authority_pub_key: flags.authority_pub_key.clone(),
        use_http_proxy_interceptor: flags.use_http_proxy_sidecar,
        monitor_mode: flags.monitor_mode,
        // `runtime_dir` is the state dir `firma monitor` resolves, so a
        // per-run sidecar with no configured audit sink still writes a
        // monitorable `<state_dir>/audit.jsonl`.
        audit_fallback_path: Some(runtime_dir.join("audit.jsonl")),
    })
}

/// Step 0: resolve the Authority before any sidecar work.
///
/// CLI > persisted > prompt (only when both empty and TTY). On Local
/// selection, probe `[authority].listen_addr` (default `[::1]:50051`); on miss, spawn an
/// `AuthoritySupervisor`. Local mode is a dev convenience path and
/// intentionally uses plaintext loopback (`http://`), not TLS/mTLS.
/// EADDRINUSE recovery: on any spawn error, re-probe once; if the port
/// is now reachable, drop the (failed) supervisor handle and proceed
/// without one.
///
/// # Errors
///
/// Propagates any `RunError` raised by selection or spawn paths.
#[allow(
    clippy::too_many_arguments,
    reason = "every input is independent — bundling into a request struct only adds noise here"
)]
#[allow(
    clippy::too_many_lines,
    reason = "step-0 selection + plaintext-h2 transport probe + autostart fallback read more clearly inline than split"
)]
pub fn resolve_authority(
    identity: &RunIdentity,
    runtime_dir: &Path,
    flags: &AutostartFlags,
    cli: &crate::authority::AuthorityCli,
    profile_name: &str,
    user_config_path: Option<&Path>,
    user_config_dir: Option<&Path>,
    firma_exe: &Path,
    prompt: &mut dyn crate::authority::AuthorityPromptIo,
) -> Result<ResolvedAuthority, RunError> {
    let selection = crate::authority::resolve(cli, flags.no_autostart, user_config_path)?;

    // Snapshot [authority] / [sidecar.authority] once: we need both the
    // `local` flag (to distinguish a committed local choice from the
    // fall-through default that triggers the first-run prompt) and the
    // connect coordinates (ca/pub key) regardless of selection mode.
    let section = user_config_path
        .map(crate::authority::config::read_authority)
        .transpose()?
        .flatten()
        .unwrap_or_default();
    let ca_cert_path = section
        .connect
        .as_ref()
        .and_then(|c| c.ca_cert_path.as_deref())
        .map(|path| rebase_config_relative_path(path, user_config_dir));
    let pub_key_path = section
        .connect
        .as_ref()
        .and_then(|c| c.public_key_path.as_deref())
        .map(|path| rebase_config_relative_path(path, user_config_dir));
    let config_committed_local = section.local;

    maybe_regen_tls(ca_cert_path.as_deref(), firma_exe)?;

    match selection {
        crate::authority::AuthoritySelection::Remote(url) => {
            probe_authority_url(&url)?;
            Ok(ResolvedAuthority {
                url,
                ca_cert_path,
                pub_key_path,
                supervisor: None,
            })
        }
        crate::authority::AuthoritySelection::Local => {
            let target = section.listen_addr;
            if probe_authority_tcp(target).is_ok() {
                if probe_authority_plaintext_h2(target).is_err() {
                    return Err(RunError::AuthorityTransportAmbiguous {
                        endpoint: format!("http://{target}"),
                    });
                }
                tracing::info!(
                    sandbox_id = identity.sandbox_id.compact(),
                    url = %format!("http://{target}"),
                    "authority reused: existing local authority on plaintext loopback"
                );
                return Ok(ResolvedAuthority {
                    url: format!("http://{target}"),
                    ca_cert_path,
                    pub_key_path,
                    supervisor: None,
                });
            }
            if flags.no_autostart {
                return Err(RunError::MissingAuthority);
            }
            // First-run interactive bootstrap: when neither the CLI nor the
            // resolved firma.toml committed to local, prompt before creating
            // the user-global Ed25519 signing key. On `Y`, persist the
            // `[authority]` section so subsequent runs skip the prompt.
            let cli_committed = !matches!(cli, crate::authority::AuthorityCli::Unset);
            if !cli_committed && !config_committed_local {
                crate::authority::bootstrap::run_prompt(prompt)?;
                let target_path =
                    crate::authority::bootstrap::resolve_persist_target(user_config_path)?;
                crate::authority::bootstrap::persist_authority_section(&target_path)?;
            }
            let marker =
                firma_stack::runtime_paths::run_entry_from(runtime_dir, &identity.sandbox_id)
                    .join("authority");
            match crate::authority::AuthoritySupervisor::spawn(crate::authority::SpawnRequest {
                sandbox_id: &identity.sandbox_id,
                agent_id: &identity.profile,
                session_id: &identity.session_id,
                marker_dir: marker,
                profile_name,
                firma_exe: firma_exe.to_path_buf(),
                startup_timeout: flags.startup_timeout,
            }) {
                Ok(sup) => {
                    let ephemeral_pub_key = sup.pub_key_path();
                    Ok(ResolvedAuthority {
                        url: sup.url(),
                        ca_cert_path,
                        pub_key_path: Some(ephemeral_pub_key),
                        supervisor: Some(sup),
                    })
                }
                Err(spawn_err) => {
                    if probe_authority_tcp(target).is_ok() {
                        if probe_authority_plaintext_h2(target).is_err() {
                            return Err(RunError::AuthorityTransportAmbiguous {
                                endpoint: format!("http://{target}"),
                            });
                        }
                        tracing::info!(
                            sandbox_id = identity.sandbox_id.compact(),
                            url = %format!("http://{target}"),
                            "authority reused: port became reachable during autostart retry"
                        );
                        Ok(ResolvedAuthority {
                            url: format!("http://{target}"),
                            ca_cert_path,
                            pub_key_path,
                            supervisor: None,
                        })
                    } else {
                        Err(spawn_err)
                    }
                }
            }
        }
    }
}

/// Regenerate TLS material in-place when `ca_cert_path` is configured but
/// absent (common after a tmpfs reboot wipe of `$XDG_RUNTIME_DIR`).
/// Only called for local authority configurations.
fn maybe_regen_tls(ca_cert_path: Option<&Path>, firma_exe: &Path) -> Result<(), RunError> {
    let Some(path) = ca_cert_path else {
        return Ok(());
    };
    if path.is_file() {
        return Ok(());
    }
    let out_dir = path.parent().ok_or_else(|| {
        RunError::Internal(format!(
            "cannot resolve TLS dir from ca_cert_path {}",
            path.display()
        ))
    })?;
    tracing::warn!(
        tls_dir = %out_dir.display(),
        "authority CA cert missing; regenerating TLS material (likely post-reboot tmpfs wipe)"
    );
    let output = std::process::Command::new(firma_exe)
        .args(["authority", "init-tls", "--out-dir"])
        .arg(out_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| RunError::Internal(format!("spawn firma authority init-tls: {e}")))?;
    if output.status.success() {
        tracing::info!(tls_dir = %out_dir.display(), "TLS material regenerated");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(RunError::Internal(format!(
            "firma authority init-tls --out-dir {} exited with {}: {stderr}",
            out_dir.display(),
            output.status,
        )))
    }
}

fn rebase_config_relative_path(path: &Path, config_dir: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.unwrap_or_else(|| Path::new(".")).join(path)
    }
}

fn probe_authority_tcp(addr: std::net::SocketAddr) -> Result<(), String> {
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500))
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn probe_authority_plaintext_h2(addr: std::net::SocketAddr) -> Result<(), String> {
    const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500))
            .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    stream.write_all(H2_PREFACE).map_err(|e| e.to_string())?;

    // Plaintext h2 servers respond with frames after preface.
    // TLS endpoints or unrelated listeners usually won't.
    let mut probe = [0_u8; 1];
    let read = stream.read(&mut probe).map_err(|e| e.to_string())?;
    if read == 0 {
        return Err("connection closed without plaintext h2 response".to_string());
    }
    Ok(())
}

fn probe_authority_url(url_str: &str) -> Result<(), RunError> {
    let (host, port) = parse_host_port(url_str).ok_or_else(|| RunError::AuthorityUnreachable {
        url: url_str.to_string(),
        reason: "could not extract host:port".into(),
    })?;
    let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port)).map_err(|e| {
        RunError::AuthorityUnreachable {
            url: url_str.to_string(),
            reason: format!("resolve: {e}"),
        }
    })?;
    for addr in addrs {
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500))
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(RunError::AuthorityUnreachable {
        url: url_str.to_string(),
        reason: "connect refused on all resolved addresses".into(),
    })
}

fn parse_host_port(url_str: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url_str.find("://").map_or((None, url_str), |i| {
        (Some(&url_str[..i]), &url_str[i + 3..])
    });
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port_str) = match authority.rfind(':') {
        Some(i) if !authority[..i].contains(']') || authority.starts_with('[') => (
            authority[..i].trim_start_matches('[').trim_end_matches(']'),
            Some(&authority[i + 1..]),
        ),
        _ => (
            authority.trim_start_matches('[').trim_end_matches(']'),
            None,
        ),
    };
    let port = match port_str {
        Some(p) => p.parse::<u16>().ok()?,
        None => match scheme {
            Some("https") => 443,
            Some("http") => 80,
            _ => 50051,
        },
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn format_endpoint(endpoint: &SidecarEndpoint) -> String {
    match endpoint {
        SidecarEndpoint::Tcp { addr } => format!("tcp://{addr}"),
        SidecarEndpoint::Unix { path } => format!("unix://{}", path.display()),
    }
}

/// Connect-with-timeout probe used to decide whether the configured
/// endpoint is already serving. Returns `Err(reason)` so callers can
/// surface the OS error in the resulting [`RunError::SidecarUnreachable`].
fn probe_sidecar(endpoint: &SidecarEndpoint) -> Result<(), String> {
    match endpoint {
        SidecarEndpoint::Tcp { addr } => {
            TcpStream::connect_timeout(addr, Duration::from_millis(500))
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        SidecarEndpoint::Unix { path } => probe_unix(path),
    }
}

#[cfg(unix)]
fn probe_unix(path: &Path) -> Result<(), String> {
    UnixStream::connect(path)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn probe_unix(_path: &Path) -> Result<(), String> {
    Err("unix socket sidecar endpoints are unsupported on this host".to_string())
}

#[cfg(unix)]
struct SidecarAdapter {
    socket_path: PathBuf,
    stop_tx: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl SidecarAdapter {
    fn start(socket_path: &Path, upstream: &SidecarEndpoint) -> Result<Self, RunError> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| RunError::Backend {
                backend: "sidecar_adapter".to_string(),
                reason: format!(
                    "failed to create adapter socket dir {}: {error}",
                    parent.display()
                ),
            })?;
        }

        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).map_err(|error| RunError::Backend {
            backend: "sidecar_adapter".to_string(),
            reason: format!(
                "failed to bind adapter socket {}: {error}",
                socket_path.display()
            ),
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|error| RunError::Backend {
                backend: "sidecar_adapter".to_string(),
                reason: format!("failed to set adapter listener non-blocking: {error}"),
            })?;

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let socket_for_task = socket_path.to_path_buf();
        let upstream_for_task = upstream.clone();

        let task = thread::Builder::new()
            .name("firma-run-sidecar-adapter".to_string())
            .spawn(move || {
                loop {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }

                    match listener.accept() {
                        Ok((client, _)) => {
                            let upstream_target = upstream_for_task.clone();
                            thread::spawn(move || {
                                if let Err(error) = relay_to_sidecar(&client, &upstream_target) {
                                    tracing::warn!("sidecar adapter relay failed: {error}");
                                }
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(error) => {
                            tracing::warn!("sidecar adapter accept failed: {error}");
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
            .map_err(|error| RunError::Backend {
                backend: "sidecar_adapter".to_string(),
                reason: format!("failed to spawn adapter task: {error}"),
            })?;

        Ok(Self {
            socket_path: socket_for_task,
            stop_tx: Some(stop_tx),
            task: Some(task),
        })
    }
}

#[cfg(unix)]
impl Drop for SidecarAdapter {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }

        if let Some(task) = self.task.take() {
            let _ = task.join();
        }

        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn relay_to_sidecar(client: &UnixStream, upstream: &SidecarEndpoint) -> io::Result<()> {
    match upstream {
        SidecarEndpoint::Tcp { addr } => {
            let target = connect_tcp_with_retry(addr)?;
            relay_unix_to_tcp(client, &target)
        }
        SidecarEndpoint::Unix { path } => {
            let target = UnixStream::connect(path)?;
            relay_unix_to_unix(client, &target)
        }
    }
}

#[cfg(unix)]
fn connect_tcp_with_retry(addr: &std::net::SocketAddr) -> io::Result<TcpStream> {
    // On autostart we can race the sidecar's TCP listener by a few ms.
    // Retry briefly on ECONNREFUSED to smooth startup probes.
    const ATTEMPTS: usize = 20;
    const SLEEP_BETWEEN: Duration = Duration::from_millis(50);
    let mut last_error: Option<io::Error> = None;
    for attempt in 0..ATTEMPTS {
        match TcpStream::connect_timeout(addr, Duration::from_millis(250)) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                last_error = Some(error);
                if attempt + 1 < ATTEMPTS {
                    thread::sleep(SLEEP_BETWEEN);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("tcp connect failed")))
}

#[cfg(unix)]
fn relay_unix_to_tcp(client: &UnixStream, target: &TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    let c_to_t = thread::spawn(move || io::copy(&mut client_read, &mut target_write));
    let t_to_c = thread::spawn(move || io::copy(&mut target_read, &mut client_write));

    c_to_t
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    t_to_c
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    Ok(())
}

#[cfg(unix)]
fn relay_unix_to_unix(client: &UnixStream, target: &UnixStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    let c_to_t = thread::spawn(move || io::copy(&mut client_read, &mut target_write));
    let t_to_c = thread::spawn(move || io::copy(&mut target_read, &mut client_write));

    c_to_t
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    t_to_c
        .join()
        .map_err(|_| io::Error::other("relay panic"))??;
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod non_structural_env_tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::str::FromStr;
    use std::time::Duration;

    use crate::backend::{BackendKind, SandboxHandle};
    use crate::config::NetworkPolicy;
    use crate::config::SidecarEndpoint;
    use crate::identity::RunIdentity;

    use super::{AutostartFlags, ResolvedAuthority, prepare_network_runtime, setup_host_bridge};

    /// Verifies that `setup_host_bridge` inserts all proxy env vars pointing
    /// to the bridge, and that the bridge port is distinct from the sidecar
    /// port (FIR-213 regression guard).
    #[test]
    fn non_structural_tcp_overrides_http_proxy_to_bridge_port() {
        let fake_sidecar = TcpListener::bind("127.0.0.1:0").expect("bind");
        let sidecar_addr = fake_sidecar.local_addr().expect("local_addr");
        let endpoint = SidecarEndpoint::Tcp { addr: sidecar_addr };
        let identity = RunIdentity::new("test-agent");
        let mut env = BTreeMap::new();

        let bridge = setup_host_bridge(&endpoint, &identity, &mut env)
            .expect("setup_host_bridge should succeed");

        // All six proxy variants must be present.
        for key in &[
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            let val = env
                .get(*key)
                .unwrap_or_else(|| panic!("{key} missing from env_overrides"));
            assert!(
                val.starts_with("http://127.0.0.1:"),
                "{key} should point to loopback: {val}"
            );
        }

        // Bridge port must be distinct from the sidecar port.
        let bridge_port = bridge.listen_addr().port();
        assert_ne!(
            bridge_port,
            sidecar_addr.port(),
            "bridge listen port must differ from sidecar port"
        );

        // HTTP_PROXY value must embed the bridge port.
        let proxy_val = env.get("HTTP_PROXY").expect("HTTP_PROXY");
        assert!(
            proxy_val.contains(&bridge_port.to_string()),
            "HTTP_PROXY should reference bridge port {bridge_port}, got: {proxy_val}"
        );
    }

    /// Verifies that a Unix socket endpoint on the non-structural path fails
    /// closed because no host bridge can be started.
    #[test]
    fn non_structural_unix_endpoint_fails_closed() {
        let endpoint = SidecarEndpoint::Unix {
            path: std::path::PathBuf::from("/tmp/test.sock"),
        };
        let identity = RunIdentity::new("test-agent");
        let mut env = BTreeMap::new();

        let Err(error) = setup_host_bridge(&endpoint, &identity, &mut env) else {
            panic!("Unix endpoint should fail closed on non-structural path");
        };
        let rendered = error.to_string();
        assert!(
            rendered.contains("requires a TCP sidecar endpoint"),
            "unexpected error: {rendered}"
        );
        assert!(env.is_empty(), "No proxy env vars should be inserted");
    }

    /// Integration-style FIR-213 regression test across `prepare_network_runtime`:
    /// non-structural mode must wire an HTTP proxy bridge and point
    /// `HTTP_PROXY` at that bridge (not directly at the sidecar endpoint).
    #[test]
    fn prepare_network_runtime_non_structural_injects_session_id_for_connect() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let upstream_addr: SocketAddr = upstream_listener.local_addr().expect("local_addr");

        let _upstream_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut chunk = [0u8; 4096];
                let _ = stream.read(&mut chunk);
                let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            }
        });

        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: std::env::temp_dir().join("firma-routing-test-runtime"),
            identity: RunIdentity::new("test-agent"),
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let identity = RunIdentity::new("test-agent");
        let flags = AutostartFlags {
            sidecar_autostart: false,
            no_autostart: true,
            template_path: None,
            startup_timeout: Duration::from_secs(1),
            authority_url: None,
            authority_ca_cert: None,
            authority_pub_key: None,
            use_http_proxy_sidecar: false,
            monitor_mode: false,
        };
        let authority = ResolvedAuthority {
            url: "https://authority.test".to_string(),
            ca_cert_path: None,
            pub_key_path: None,
            supervisor: None,
        };
        let runtime = prepare_network_runtime(
            &handle,
            &SidecarEndpoint::Tcp {
                addr: upstream_addr,
            },
            &identity,
            &flags,
            authority,
        )
        .expect("prepare_network_runtime should succeed");

        let http_proxy = runtime
            .env_overrides()
            .get("HTTP_PROXY")
            .expect("HTTP_PROXY must be set");
        let proxy_addr = http_proxy
            .strip_prefix("http://")
            .expect("HTTP_PROXY must use http:// scheme");
        let proxy_sock = SocketAddr::from_str(proxy_addr).expect("valid proxy socket addr");
        assert_ne!(
            proxy_sock.port(),
            upstream_addr.port(),
            "HTTP_PROXY must point to host bridge, not directly to sidecar"
        );

        let connect_req =
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        let mut sent = false;
        for _ in 0..20 {
            if let Ok(mut client) = TcpStream::connect(proxy_sock) {
                client.set_read_timeout(Some(Duration::from_secs(2))).ok();
                if client.write_all(connect_req.as_bytes()).is_ok() {
                    let mut resp = [0u8; 256];
                    let _ = client.read(&mut resp);
                    let _ = client.shutdown(std::net::Shutdown::Write);
                    sent = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(sent, "failed to send CONNECT request to proxy bridge");
        drop(runtime);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod parse_host_port_tests {
    use std::path::{Path, PathBuf};

    use super::{parse_host_port, rebase_config_relative_path};

    #[test]
    fn parses_http_with_port() {
        assert_eq!(
            parse_host_port("http://localhost:50051").unwrap(),
            ("localhost".to_string(), 50051)
        );
    }
    #[test]
    fn parses_https_without_port() {
        assert_eq!(
            parse_host_port("https://authority.example.invariant").unwrap(),
            ("authority.example.invariant".to_string(), 443)
        );
    }
    #[test]
    fn parses_ipv6_bracketed() {
        assert_eq!(
            parse_host_port("http://[::1]:50051/").unwrap(),
            ("::1".to_string(), 50051)
        );
    }
    #[test]
    fn parses_bare_host_port() {
        assert_eq!(
            parse_host_port("localhost:50051").unwrap(),
            ("localhost".to_string(), 50051)
        );
    }
    #[test]
    fn rejects_empty() {
        assert!(parse_host_port("").is_none());
    }

    #[test]
    fn rebases_relative_config_paths_to_config_dir() {
        assert_eq!(
            rebase_config_relative_path(Path::new("authority-ca.crt"), Some(Path::new("/cfg"))),
            PathBuf::from("/cfg/authority-ca.crt")
        );
        assert_eq!(
            rebase_config_relative_path(Path::new("/abs/authority.pub"), Some(Path::new("/cfg"))),
            PathBuf::from("/abs/authority.pub")
        );
    }
}
