use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use firma_runtime_state::runtime_paths::{default_runtime_dir, run_entry_from};

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(unix)]
use std::thread::{self, JoinHandle};

#[cfg(unix)]
use crate::backend::{BackendKind, NetworkConfinement};
use crate::backend::{EnforcementProof, SandboxHandle};
use crate::capability::refresh::CapabilityRefresher;
use crate::config::{CapabilityLeaseConfig, CapabilitySource, SidecarEndpoint};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::sidecar::supervisor::{SidecarSupervisor, SpawnRequest};
use firma_sidecar::authority_credentials::{ResolvedSidecarCredentials, SidecarCredentialsConfig};

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

#[derive(Default)]
pub struct EnvOverrides(BTreeMap<String, String>);

// The builder methods are only invoked on Unix structural/non-structural paths;
// on Windows the runtime is assembled from `autostart_trust_env` alone, so the
// whole impl would be dead code there.
#[cfg(unix)]
impl EnvOverrides {
    /// Sets all six proxy environment variables (upper/lowercase HTTP, HTTPS,
    /// and ALL) to the same URL.
    fn set_proxy_url(&mut self, url: &str) {
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            self.0.insert(key.to_string(), url.to_string());
        }
    }

    fn structural_proxy_env(
        mut self,
        proxy_addr: &str,
        dns_addr: &str,
        adapter_path: &std::path::Path,
        current_exe: &std::path::Path,
    ) -> Self {
        self.set_proxy_url(&format!("http://{proxy_addr}"));
        self.0.insert(
            "FIRMA_RUN_PROXY_LISTEN_ADDR".to_string(),
            proxy_addr.to_string(),
        );
        self.0.insert(
            "FIRMA_RUN_DNS_STUB_LISTEN_ADDR".to_string(),
            dns_addr.to_string(),
        );
        self.0.insert(
            "FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS".to_string(),
            adapter_path.display().to_string(),
        );
        self.0.insert(
            "FIRMA_RUN_SELF_EXE".to_string(),
            current_exe.display().to_string(),
        );
        self
    }
    #[cfg(target_os = "linux")]
    fn with_egress_sock(mut self, guard_sock: &Path) -> Self {
        self.0.insert(
            "FIRMA_RUN_EGRESS_GUARD_SOCK".to_string(),
            guard_sock.display().to_string(),
        );
        self
    }

    fn with_bridge_address(mut self, bridge_addr: std::net::SocketAddr) -> Self {
        self.set_proxy_url(&format!("http://{bridge_addr}"));
        self
    }

    fn with_dns_stub_address(mut self, dns_stub_addr: Option<std::net::SocketAddr>) -> Self {
        if let Some(addr) = dns_stub_addr {
            self.0
                .insert("FIRMA_DNS_STUB_ADDR".to_string(), addr.to_string());
        }
        self
    }
}

impl std::ops::Deref for EnvOverrides {
    type Target = BTreeMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BTreeMap<String, String>> for EnvOverrides {
    fn from(value: BTreeMap<String, String>) -> Self {
        Self(value)
    }
}

/// Runtime-side network artifacts that must live while the wrapped process runs.
pub struct NetworkRuntime {
    env_overrides: EnvOverrides,
    sidecar_endpoint: SidecarEndpoint,
    // Drop order matters: the host bridge and adapter hold connections to the
    // sidecar, so they must drop before the sidecar supervisor.  The sidecar
    // supervisor streams policy from the authority, so it must drop before the
    // authority supervisor.  Rust drops fields top-to-bottom, so declaration
    // order here is load-bearing.
    #[cfg(unix)]
    _host_bridge: Option<crate::proxy_bridge::HostBridgeHandle>,
    /// Host-side DNS refusal stub for macOS structural paths that do not use a
    /// Linux network namespace. Null on Linux structural and non-structural paths.
    #[cfg(unix)]
    _host_dns_stub: Option<crate::dns_stub::HostDnsStubHandle>,
    #[cfg(unix)]
    _adapter: Option<SidecarAdapter>,
    /// Loopback egress guard supervisor. Held so the seccomp notify loop runs
    /// for the agent's lifetime and is torn down on Drop. Linux-only.
    #[cfg(target_os = "linux")]
    _egress_guard: Option<crate::egress_guard::EgressGuardHandle>,
    _sidecar_supervisor: Option<SidecarSupervisor>,
    _authority_supervisor: Option<crate::authority::AuthoritySupervisor>,
    // Stops the background re-mint thread. Declared before the guard so the
    // refresher halts (no further seed writes) before the file is deleted.
    _capability_refresher: Option<crate::capability::refresh::CapabilityRefresher>,
    // Declared last so it drops last: the sidecar reads the seed file, so the
    // guard that DELETES the file must outlive the sidecar supervisor above.
    _capability_guard: Option<crate::capability::guard::CapabilityFileGuard>,
}

impl NetworkRuntime {
    /// Returns environment values to merge into wrapped process launch env.
    #[must_use]
    pub fn env_overrides(&self) -> &EnvOverrides {
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "this type intentionally models independent CLI/runtime flags one-to-one"
)]
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
    /// `[sidecar.authority].public_key_path` during synthesis so the sidecar
    /// can verify the per-session capability seed.
    pub authority_pub_key: Option<PathBuf>,
    /// Sidecar credential config injected into `[sidecar.authority.credentials]`
    /// during sidecar config synthesis.
    pub authority_credentials: Option<SidecarCredentialsConfig>,
    /// Path of the per-session capability seed minted by `firma run`.
    pub capability_seed_path: Option<PathBuf>,
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
            authority_credentials: None,
            capability_seed_path: None,
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
    /// Resolved credentials used by `firma run` when issuing a capability.
    pub credentials: Option<ResolvedSidecarCredentials>,
    /// Unresolved credentials config passed to an autostarted Sidecar.
    pub credentials_config: Option<SidecarCredentialsConfig>,
    pub supervisor: Option<crate::authority::AuthoritySupervisor>,
}

/// Owned pieces threaded from [`prepare_network_runtime`] into the per-path
/// builders and finally moved into the returned [`NetworkRuntime`].
struct RuntimeParts {
    effective_endpoint: SidecarEndpoint,
    autostart_trust_env: BTreeMap<String, String>,
    sidecar_supervisor: Option<SidecarSupervisor>,
    authority_supervisor: Option<crate::authority::AuthoritySupervisor>,
    capability_guard: Option<crate::capability::guard::CapabilityFileGuard>,
    capability_refresher: Option<crate::capability::refresh::CapabilityRefresher>,
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
    proof: &EnforcementProof,
    sidecar_endpoint: &SidecarEndpoint,
    identity: &RunIdentity,
    flags: &AutostartFlags,
    authority: ResolvedAuthority,
    capability_lease: &CapabilityLeaseConfig,
) -> Result<NetworkRuntime, RunError> {
    #[cfg(not(unix))]
    let _ = proof;

    // When the user supplied their own capability file, `firma run` must
    // not mint a per-session seed during autostart.
    let mut flags = flags.clone();
    flags.authority_url = Some(authority.url.clone());
    flags.authority_ca_cert.clone_from(&authority.ca_cert_path);
    flags.authority_pub_key.clone_from(&authority.pub_key_path);
    flags
        .authority_credentials
        .clone_from(&authority.credentials_config);
    let is_source_file = matches!(capability_lease.source, CapabilitySource::File { .. });
    let should_manage_capability =
        flags.sidecar_autostart && !is_source_file && authority.pub_key_path.is_some();

    // Mint the per-session capability seed before resolving the endpoint so the
    // synthesized sidecar config can reference it. The guard is moved into the
    // returned `NetworkRuntime` so the seed file is removed on Drop — declared
    // last in the struct so it drops AFTER the sidecar supervisor that reads it.
    //
    // Only firma-minted runs set `capability_seed_path` here; a user-supplied
    // `--capability-file` path (already threaded into `flags` by the caller)
    // must survive, so it is left untouched when `should_manage_capability` is
    // false.
    let (capability_guard, capability_refresher) = if should_manage_capability {
        let capability_seed_path =
            firma_runtime_state::runtime_paths::capability_seed_path(&identity.sandbox_id);
        flags.capability_seed_path = Some(capability_seed_path.clone());
        let guard =
            crate::capability::guard::CapabilityFileGuard::new(capability_seed_path.clone());
        let refresher = mint_capability_seed(
            identity,
            &capability_seed_path,
            &authority,
            capability_lease,
        )?;
        (Some(guard), Some(refresher))
    } else {
        (None, None)
    };

    let (effective_endpoint, sidecar_supervisor) =
        resolve_effective_endpoint(handle, sidecar_endpoint, identity, &flags)?;
    let autostart_trust_env = sidecar_trust_env_overrides(sidecar_supervisor.as_ref());

    let parts = RuntimeParts {
        effective_endpoint,
        autostart_trust_env,
        sidecar_supervisor,
        authority_supervisor: authority.supervisor,
        capability_guard,
        capability_refresher,
    };

    if !handle.network_policy.enforce_network_namespace {
        return prepare_flat_runtime(handle, proof, identity, parts);
    }

    #[cfg(not(unix))]
    {
        let _ = parts;
        Err(RunError::UnsupportedBackend {
            backend: handle.backend.to_string(),
            reason: "structural network confinement currently requires unix sockets".to_string(),
        })
    }

    #[cfg(unix)]
    prepare_structural_runtime(handle, identity, parts)
}

/// Builds the [`NetworkRuntime`] for the non-structural path (no enforced
/// network namespace): the agent reaches the sidecar over a host bridge, plus a
/// host-side DNS refusal stub on Unix. No adapter or egress guard.
// On non-Unix targets the body performs no fallible work, so the `Result` looks
// redundant there; it is required on Unix, where the host bridge/DNS stub setup
// can fail.
#[cfg_attr(not(unix), expect(clippy::unnecessary_wraps))]
fn prepare_flat_runtime(
    handle: &SandboxHandle,
    proof: &EnforcementProof,
    identity: &RunIdentity,
    parts: RuntimeParts,
) -> Result<NetworkRuntime, RunError> {
    let RuntimeParts {
        effective_endpoint,
        autostart_trust_env,
        sidecar_supervisor,
        authority_supervisor,
        capability_guard,
        capability_refresher,
    } = parts;

    #[cfg(not(unix))]
    let _ = (handle, proof, identity);

    let env_overrides = EnvOverrides::from(autostart_trust_env);
    #[cfg(unix)]
    let (host_bridge, host_dns_stub, env_overrides) = {
        let host_bridge = setup_host_bridge(&effective_endpoint, identity)?;
        let dns_stub = maybe_start_host_dns_stub(handle, proof)?;
        let env_overrides = env_overrides
            .with_bridge_address(host_bridge.listen_addr())
            .with_dns_stub_address(
                dns_stub
                    .as_ref()
                    .map(crate::dns_stub::HostDnsStubHandle::listen_addr),
            );
        (host_bridge, dns_stub, env_overrides)
    };

    // macOS structural modes without a Linux network namespace also need a
    // host-side DNS refusal stub. sandbox-exec reaches it on loopback; the
    // VZ guest runner receives it through the launch contract and must wire
    // guest DNS to this endpoint.

    Ok(NetworkRuntime {
        env_overrides,
        sidecar_endpoint: effective_endpoint,
        #[cfg(unix)]
        _host_bridge: Some(host_bridge),
        #[cfg(unix)]
        _host_dns_stub: host_dns_stub,
        #[cfg(unix)]
        _adapter: None,
        #[cfg(target_os = "linux")]
        _egress_guard: None,
        _sidecar_supervisor: sidecar_supervisor,
        _authority_supervisor: authority_supervisor,
        _capability_refresher: capability_refresher,
        _capability_guard: capability_guard,
    })
}

/// Builds the [`NetworkRuntime`] for the structural Unix path: a sidecar
/// upstream adapter, proxy/DNS env overrides, and (on Linux) the loopback
/// egress guard.
#[cfg(unix)]
fn prepare_structural_runtime(
    handle: &SandboxHandle,
    identity: &RunIdentity,
    parts: RuntimeParts,
) -> Result<NetworkRuntime, RunError> {
    let RuntimeParts {
        effective_endpoint,
        autostart_trust_env,
        sidecar_supervisor,
        authority_supervisor,
        capability_guard,
        capability_refresher,
    } = parts;

    #[cfg(not(target_os = "linux"))]
    let _ = identity;

    let adapter_path = handle.runtime_dir.join("sidecar-upstream.sock");
    let adapter = SidecarAdapter::start(&adapter_path, &effective_endpoint)?;
    let current_exe = std::env::current_exe().map_err(|error| {
        RunError::Internal(format!(
            "failed to resolve current executable path: {error}"
        ))
    })?;

    let proxy_addr = structural_proxy_listen_addr();
    let dns_addr = structural_dns_stub_listen_addr();

    // Loopback egress guard: trap the agent's connect(2)s and block direct
    // connections to loopback addresses that are not the proxy bridge or
    // DNS stub. The supervisor runs here on the host; the in-sandbox
    // installer reaches it on a bind-mounted socket under runtime_dir.
    #[cfg(target_os = "linux")]
    let egress_guard = start_loopback_guard(
        handle,
        proxy_addr,
        dns_addr,
        sidecar_supervisor.as_ref(),
        identity,
    );

    let env_overrides = EnvOverrides::from(autostart_trust_env).structural_proxy_env(
        proxy_addr,
        dns_addr,
        &adapter_path,
        &current_exe,
    );

    // The egress guard is Linux-only; on other structural targets (macOS
    // sandbox-exec) there is no guard socket to advertise.
    #[cfg(target_os = "linux")]
    let env_overrides = if let Some(guard) = &egress_guard {
        env_overrides.with_egress_sock(guard.socket_path())
    } else {
        env_overrides
    };

    Ok(NetworkRuntime {
        env_overrides,
        sidecar_endpoint: effective_endpoint,
        _host_bridge: None,
        _host_dns_stub: None,
        _adapter: Some(adapter),
        #[cfg(target_os = "linux")]
        _egress_guard: egress_guard,
        _sidecar_supervisor: sidecar_supervisor,
        _authority_supervisor: authority_supervisor,
        _capability_refresher: capability_refresher,
        _capability_guard: capability_guard,
    })
}

/// Starts the loopback egress guard supervisor for the structural Linux path
/// and injects `FIRMA_RUN_EGRESS_GUARD_SOCK` so the in-sandbox entrypoint wraps
/// the agent through the installer.
///
/// Fails open with a warning: if the guard cannot start (e.g. a kernel without
/// seccomp user-notify), the run proceeds without it. In structural mode the
/// private network namespace already isolates the agent from host loopback
/// services, so the guard is defense in depth plus a direct-socket audit trail,
/// not the sole boundary.
#[cfg(target_os = "linux")]
fn start_loopback_guard(
    handle: &SandboxHandle,
    proxy_addr: &str,
    dns_addr: &str,
    sidecar_supervisor: Option<&SidecarSupervisor>,
    identity: &RunIdentity,
) -> Option<crate::egress_guard::EgressGuardHandle> {
    // Ports the agent may still reach on loopback. A parse failure here would
    // silently drop the endpoint from the allow-list, and the guard would then
    // BLOCK the agent's connect to the proxy/DNS stub — killing all egress with
    // no obvious cause. Warn loudly so that misconfiguration is diagnosable.
    let mut allow_ports = Vec::new();
    for (label, raw) in [("proxy", proxy_addr), ("dns stub", dns_addr)] {
        match raw.parse::<std::net::SocketAddr>() {
            Ok(addr) => allow_ports.push(addr.port()),
            Err(error) => tracing::warn!(
                %error,
                endpoint = raw,
                "egress guard: {label} address is not a socket addr; its port will \
                 NOT be allow-listed and the agent's connect to it will be blocked"
            ),
        }
    }

    // Report blocked attempts to the autostarted Sidecar over the `firma run`
    // audit channel so they become signed audit events. With an external
    // Sidecar we do not control its env, so reporting is skipped (blocks are
    // still enforced).
    let report = sidecar_supervisor.map(|supervisor| crate::egress_guard::AuditChannel {
        socket_path: firma_sidecar::run_audit::socket_path_in(supervisor.marker_dir()),
        session_id: identity.session_id.clone(),
        agent_id: identity.profile.clone(),
    });

    let guard_sock = handle.runtime_dir.join("egress-guard.sock");
    match crate::egress_guard::start(crate::egress_guard::SupervisorConfig {
        socket_path: guard_sock,
        allow_ports,
        report,
    }) {
        Ok(handle) => Some(handle),
        Err(error) => {
            tracing::warn!(
                %error,
                "loopback egress guard failed to start; continuing without direct-socket loopback blocking"
            );
            None
        }
    }
}

/// Mint the per-session capability seed at `capability_seed_path` and spawn the
/// background refresher that re-mints it before expiry.
///
/// The caller decides whether to mint (see `should_manage_capability` in
/// [`prepare_network_runtime`]) and records `capability_seed_path` in
/// `flags.capability_seed_path` so synthesis can append it to
/// `[sidecar.capability_seed].paths`.
///
/// # Errors
///
/// Returns [`RunError`] when the authority public key is missing, the seed
/// cannot be minted/written, or the refresh thread cannot be spawned.
fn mint_capability_seed(
    identity: &RunIdentity,
    capability_seed_path: &Path,
    authority: &ResolvedAuthority,
    capability_lease: &CapabilityLeaseConfig,
) -> Result<CapabilityRefresher, RunError> {
    let params = crate::capability::issue::IssueParams {
        authority_url: authority.url.clone(),
        authority_pub_key_path: authority
            .pub_key_path
            .clone()
            .ok_or_else(|| RunError::Internal("authority pub key missing after gate".into()))?,
        authority_ca_cert_path: authority.ca_cert_path.clone(),
        credentials: authority.credentials.clone(),
        agent_id: identity.profile.clone(),
        session_id: identity.session_id.clone(),
        requested_actions: crate::capability::issue::DEFAULT_REQUESTED_ACTIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        resource_scope: crate::capability::issue::DEFAULT_RESOURCE_SCOPE.to_string(),
        ttl_seconds: crate::capability::issue::DEFAULT_TTL_SECONDS,
    };
    let seed = crate::capability::issue::mint_and_write_seed(&params, capability_seed_path)?;

    // Spawn the background re-minter so the token is renewed before it expires.
    // Reuses the same `params` (session identity + credentials) — no interactive
    // re-auth.
    CapabilityRefresher::spawn(params, capability_seed_path, seed.expiry, capability_lease)
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
    Ok(bridge)
}

/// Start a host-side DNS refusal stub when the active confinement mechanism is
/// one of the macOS structural paths.
///
/// On the macOS sandbox-exec structural path the wrapped process can only reach
/// loopback. On the VZ guest path the runner must expose this endpoint as the
/// guest resolver. The stub refuses all DNS queries so the agent cannot resolve
/// external hostnames directly; it must use the proxy bridge, which the Sidecar
/// controls. This function is a no-op for all other network confinement modes.
#[cfg(unix)]
fn maybe_start_host_dns_stub(
    handle: &SandboxHandle,
    proof: &EnforcementProof,
) -> Result<Option<crate::dns_stub::HostDnsStubHandle>, RunError> {
    if handle.backend != BackendKind::Vz {
        return Ok(None);
    }
    if !matches!(
        proof.network_confinement,
        NetworkConfinement::MacosSandboxNetworkDeny | NetworkConfinement::MacosVzGuest
    ) {
        return Ok(None);
    }
    let stub = crate::dns_stub::HostDnsStubHandle::start()?;
    let stub_addr = stub.listen_addr();
    tracing::info!(
        %stub_addr,
        network_confinement = ?proof.network_confinement,
        "host DNS refusal stub wired for macOS structural network path"
    );
    Ok(Some(stub))
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
    let runtime_dir = default_runtime_dir();
    let marker_dir = run_entry_from(&runtime_dir, identity.sandbox_id.to_string());
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
        authority_credentials: flags.authority_credentials.clone(),
        capability_seed_path: flags.capability_seed_path.clone(),
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
#[expect(
    clippy::too_many_arguments,
    reason = "every input is independent — bundling into a request struct only adds noise here"
)]
#[expect(
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
    let credentials_config = section
        .connect
        .as_ref()
        .and_then(|connect| connect.credentials.as_ref())
        .cloned()
        .map(|mut credentials| {
            credentials.rebase_defaults(user_config_dir.unwrap_or_else(|| Path::new(".")));
            credentials
        });
    let credentials = credentials_config
        .as_ref()
        .map(SidecarCredentialsConfig::resolve)
        .transpose()
        .map_err(|reason| {
            RunError::ConfigValidation(format!("sidecar.authority.credentials: {reason}"))
        })?;
    let config_committed_local = section.local;

    maybe_regen_tls(ca_cert_path.as_deref(), firma_exe)?;

    match selection {
        crate::authority::AuthoritySelection::Remote(url) => {
            probe_authority_url(&url)?;
            Ok(ResolvedAuthority {
                url,
                ca_cert_path,
                pub_key_path,
                credentials,
                credentials_config,
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
                    sandbox_id = %identity.sandbox_id,
                    url = %format!("http://{target}"),
                    "authority reused: existing local authority on plaintext loopback"
                );
                return Ok(ResolvedAuthority {
                    url: format!("http://{target}"),
                    ca_cert_path,
                    pub_key_path,
                    credentials,
                    credentials_config,
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
                run_entry_from(runtime_dir, identity.sandbox_id.to_string()).join("authority");
            match crate::authority::AuthoritySupervisor::spawn(crate::authority::SpawnRequest {
                sandbox_id: &identity.sandbox_id,
                agent_id: &identity.profile,
                session_id: &identity.session_id,
                marker_dir: marker,
                profile_name,
                firma_exe: firma_exe.to_path_buf(),
                startup_timeout: flags.startup_timeout,
                user_config_path: user_config_path.map(Path::to_path_buf),
            }) {
                Ok(sup) => {
                    let ephemeral_pub_key = sup.pub_key_path();
                    Ok(ResolvedAuthority {
                        url: sup.url(),
                        ca_cert_path,
                        pub_key_path: Some(ephemeral_pub_key),
                        credentials,
                        credentials_config,
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
                            sandbox_id = %identity.sandbox_id,
                            url = %format!("http://{target}"),
                            "authority reused: port became reachable during autostart retry"
                        );
                        Ok(ResolvedAuthority {
                            url: format!("http://{target}"),
                            ca_cert_path,
                            pub_key_path,
                            credentials,
                            credentials_config,
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
const DEFAULT_SIDECAR_ADAPTER_MAX_CONNECTIONS: usize = 512;
#[cfg(unix)]
const DEFAULT_SIDECAR_ADAPTER_IDLE_TIMEOUT: Duration = Duration::from_mins(2);

#[cfg(unix)]
impl SidecarAdapter {
    fn start(socket_path: &Path, upstream: &SidecarEndpoint) -> Result<Self, RunError> {
        Self::start_with_connection_limit(
            socket_path,
            upstream,
            DEFAULT_SIDECAR_ADAPTER_MAX_CONNECTIONS,
        )
    }

    fn start_with_connection_limit(
        socket_path: &Path,
        upstream: &SidecarEndpoint,
        max_connections: usize,
    ) -> Result<Self, RunError> {
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
        let limiter = Arc::new(SidecarAdapterConnectionLimiter::new(max_connections.max(1)));

        let task = thread::Builder::new()
            .name("firma-run-sidecar-adapter".to_string())
            .spawn(move || {
                loop {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }

                    let Some(permit) = limiter.try_acquire() else {
                        thread::sleep(Duration::from_millis(25));
                        continue;
                    };

                    match listener.accept() {
                        Ok((client, _)) => {
                            if let Err(error) = client.set_nonblocking(false) {
                                tracing::warn!(
                                    "sidecar adapter failed to set accepted socket blocking mode: {error}"
                                );
                                continue;
                            }
                            let upstream_target = upstream_for_task.clone();
                            thread::spawn(move || {
                                let _permit = permit;
                                if let Err(error) = relay_to_sidecar(&client, &upstream_target) {
                                    log_sidecar_adapter_relay_error(&error);
                                }
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            drop(permit);
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(error) => {
                            drop(permit);
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
fn log_sidecar_adapter_relay_error(error: &io::Error) {
    if is_sidecar_adapter_transient_relay_error(error) {
        tracing::debug!("sidecar adapter relay closed/transient: {error}");
    } else {
        tracing::warn!("sidecar adapter relay failed: {error}");
    }
}

#[cfg(unix)]
fn is_sidecar_adapter_transient_relay_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(unix)]
#[derive(Debug)]
struct SidecarAdapterConnectionLimiter {
    limit: usize,
    in_flight: Mutex<usize>,
}

#[cfg(unix)]
impl SidecarAdapterConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: Mutex::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<SidecarAdapterConnectionPermit> {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return None;
        };
        if *in_flight >= self.limit {
            return None;
        }
        *in_flight += 1;
        Some(SidecarAdapterConnectionPermit {
            limiter: Arc::clone(self),
        })
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct SidecarAdapterConnectionPermit {
    limiter: Arc<SidecarAdapterConnectionLimiter>,
}

#[cfg(unix)]
impl Drop for SidecarAdapterConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.limiter.in_flight.lock() {
            *in_flight = in_flight.saturating_sub(1);
        }
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
    relay_unix_to_tcp_with_idle_timeout(client, target, DEFAULT_SIDECAR_ADAPTER_IDLE_TIMEOUT)
}

#[cfg(unix)]
fn relay_unix_to_tcp_with_idle_timeout(
    client: &UnixStream,
    target: &TcpStream,
    idle_timeout: Duration,
) -> io::Result<()> {
    client.set_read_timeout(Some(idle_timeout))?;
    target.set_read_timeout(Some(idle_timeout))?;
    let mut client_read = client.try_clone()?;
    let client_shutdown_for_upload = client.try_clone()?;
    let client_shutdown_for_download = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let target_shutdown_for_upload = target.try_clone()?;
    let target_shutdown_for_download = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    let c_to_t = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut target_write);
        let _ = client_shutdown_for_upload.shutdown(std::net::Shutdown::Both);
        let _ = target_shutdown_for_upload.shutdown(std::net::Shutdown::Both);
        result
    });
    let t_to_c = thread::spawn(move || {
        let result = io::copy(&mut target_read, &mut client_write);
        let _ = target_shutdown_for_download.shutdown(std::net::Shutdown::Both);
        let _ = client_shutdown_for_download.shutdown(std::net::Shutdown::Both);
        result
    });

    let upload_result = c_to_t.join().map_err(|_| io::Error::other("relay panic"))?;
    let download_result = t_to_c.join().map_err(|_| io::Error::other("relay panic"))?;
    finish_sidecar_adapter_relay(upload_result, download_result)
}

#[cfg(unix)]
fn relay_unix_to_unix(client: &UnixStream, target: &UnixStream) -> io::Result<()> {
    relay_unix_to_unix_with_idle_timeout(client, target, DEFAULT_SIDECAR_ADAPTER_IDLE_TIMEOUT)
}

#[cfg(unix)]
fn relay_unix_to_unix_with_idle_timeout(
    client: &UnixStream,
    target: &UnixStream,
    idle_timeout: Duration,
) -> io::Result<()> {
    client.set_read_timeout(Some(idle_timeout))?;
    target.set_read_timeout(Some(idle_timeout))?;
    let mut client_read = client.try_clone()?;
    let client_shutdown_for_upload = client.try_clone()?;
    let client_shutdown_for_download = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let target_shutdown_for_upload = target.try_clone()?;
    let target_shutdown_for_download = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    let c_to_t = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut target_write);
        let _ = client_shutdown_for_upload.shutdown(std::net::Shutdown::Both);
        let _ = target_shutdown_for_upload.shutdown(std::net::Shutdown::Both);
        result
    });
    let t_to_c = thread::spawn(move || {
        let result = io::copy(&mut target_read, &mut client_write);
        let _ = target_shutdown_for_download.shutdown(std::net::Shutdown::Both);
        let _ = client_shutdown_for_download.shutdown(std::net::Shutdown::Both);
        result
    });

    let upload_result = c_to_t.join().map_err(|_| io::Error::other("relay panic"))?;
    let download_result = t_to_c.join().map_err(|_| io::Error::other("relay panic"))?;
    finish_sidecar_adapter_relay(upload_result, download_result)
}

#[cfg(unix)]
fn finish_sidecar_adapter_relay(
    upload_result: io::Result<u64>,
    download_result: io::Result<u64>,
) -> io::Result<()> {
    for result in [upload_result, download_result] {
        if let Err(error) = result
            && !is_sidecar_adapter_transient_relay_error(&error)
        {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
mod non_structural_env_tests {
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::net::UnixStream;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::backend::{BackendKind, SandboxHandle};
    use crate::config::NetworkPolicy;
    use crate::config::SidecarEndpoint;
    use crate::config::{CapabilityLeaseConfig, CapabilitySource};
    use crate::identity::RunIdentity;

    use super::{
        AutostartFlags, EnvOverrides, ResolvedAuthority, SidecarAdapter, prepare_network_runtime,
        setup_host_bridge,
    };

    /// Default capability-lease config for `prepare_network_runtime` tests.
    fn capability_lease_conf() -> CapabilityLeaseConfig {
        CapabilityLeaseConfig {
            source: CapabilitySource::Disabled,
            refresh_ratio: 0.60,
            grace_seconds: 30,
        }
    }

    /// Verifies that `setup_host_bridge` inserts all proxy env vars pointing
    /// to the bridge, and that the bridge port is distinct from the sidecar
    /// port (FIR-213 regression guard).
    #[test]
    fn non_structural_tcp_overrides_http_proxy_to_bridge_port() {
        let fake_sidecar = TcpListener::bind("127.0.0.1:0").expect("bind");
        let sidecar_addr = fake_sidecar.local_addr().expect("local_addr");
        let endpoint = SidecarEndpoint::Tcp { addr: sidecar_addr };
        let identity = RunIdentity::new("test-agent");

        let bridge =
            setup_host_bridge(&endpoint, &identity).expect("setup_host_bridge should succeed");
        let env = EnvOverrides::default().with_bridge_address(bridge.listen_addr());

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
        let Err(error) = setup_host_bridge(&endpoint, &identity) else {
            panic!("Unix endpoint should fail closed on non-structural path");
        };
        let rendered = error.to_string();
        assert!(
            rendered.contains("requires a TCP sidecar endpoint"),
            "unexpected error: {rendered}"
        );
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
            no_autostart: true,
            startup_timeout: Duration::from_secs(1),
            ..AutostartFlags::default()
        };
        let authority = ResolvedAuthority {
            url: "https://authority.test".to_string(),
            ca_cert_path: None,
            pub_key_path: None,
            credentials: None,
            credentials_config: None,
            supervisor: None,
        };
        let proof = crate::backend::EnforcementProof {
            backend: BackendKind::Vz,
            structural: false,
            fail_closed: true,
            detail: "test non-structural".to_string(),
            network_confinement: crate::backend::NetworkConfinement::ProxyOnly,
        };
        let runtime = prepare_network_runtime(
            &handle,
            &proof,
            &SidecarEndpoint::Tcp {
                addr: upstream_addr,
            },
            &identity,
            &flags,
            authority,
            &capability_lease_conf(),
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

    /// When the proof carries a macOS structural mechanism, a host-side DNS
    /// refusal stub must be started and its address exposed as
    /// `FIRMA_DNS_STUB_ADDR`.
    #[test]
    fn macos_structural_paths_start_dns_stub_and_expose_env_var() {
        let fake_sidecar = TcpListener::bind("127.0.0.1:0").expect("bind");
        let sidecar_addr = fake_sidecar.local_addr().expect("local_addr");

        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: std::env::temp_dir().join("firma-routing-test-dns-stub"),
            identity: RunIdentity::new("test-agent"),
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let identity = RunIdentity::new("test-agent");
        let flags = AutostartFlags {
            no_autostart: true,
            startup_timeout: Duration::from_secs(1),
            ..AutostartFlags::default()
        };

        for mechanism in [
            crate::backend::NetworkConfinement::MacosSandboxNetworkDeny,
            crate::backend::NetworkConfinement::MacosVzGuest,
        ] {
            let authority = ResolvedAuthority {
                url: "https://authority.test".to_string(),
                ca_cert_path: None,
                pub_key_path: None,
                credentials: None,
                credentials_config: None,
                supervisor: None,
            };
            let structural_proof = crate::backend::EnforcementProof {
                backend: BackendKind::Vz,
                structural: true,
                fail_closed: true,
                detail: format!("test {mechanism:?}"),
                network_confinement: mechanism.clone(),
            };

            let runtime = prepare_network_runtime(
                &handle,
                &structural_proof,
                &SidecarEndpoint::Tcp { addr: sidecar_addr },
                &identity,
                &flags,
                authority,
                &capability_lease_conf(),
            )
            .expect("prepare_network_runtime must succeed for macOS structural proof");

            let overrides = runtime.env_overrides();
            assert!(
                overrides.contains_key("FIRMA_DNS_STUB_ADDR"),
                "FIRMA_DNS_STUB_ADDR must be set when {mechanism:?} is active; \
                 got keys: {:?}",
                overrides.keys().collect::<Vec<_>>()
            );

            let stub_addr_str = overrides.get("FIRMA_DNS_STUB_ADDR").expect("present");
            let stub_addr: SocketAddr = stub_addr_str
                .parse()
                .expect("FIRMA_DNS_STUB_ADDR must be a valid SocketAddr");
            assert!(
                stub_addr.ip().is_loopback(),
                "DNS stub must be on loopback: {stub_addr}"
            );
            assert_ne!(stub_addr.port(), 0, "DNS stub must have a real port");

            drop(runtime);
        }
    }

    #[test]
    fn macos_dns_stub_is_not_started_for_non_vz_backend() {
        let fake_sidecar = TcpListener::bind("127.0.0.1:0").expect("bind");
        let sidecar_addr = fake_sidecar.local_addr().expect("local_addr");

        let handle = SandboxHandle {
            backend: BackendKind::Bwrap,
            runtime_dir: std::env::temp_dir().join("firma-routing-test-no-macos-dns-stub"),
            identity: RunIdentity::new("test-agent"),
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let identity = RunIdentity::new("test-agent");
        let flags = AutostartFlags {
            no_autostart: true,
            startup_timeout: Duration::from_secs(1),
            ..AutostartFlags::default()
        };
        let authority = ResolvedAuthority {
            url: "https://authority.test".to_string(),
            ca_cert_path: None,
            pub_key_path: None,
            credentials: None,
            credentials_config: None,
            supervisor: None,
        };
        let proof = crate::backend::EnforcementProof {
            backend: BackendKind::Bwrap,
            structural: true,
            fail_closed: true,
            detail: "miswired macOS-looking proof on non-vz backend".to_string(),
            network_confinement: crate::backend::NetworkConfinement::MacosVzGuest,
        };

        let runtime = prepare_network_runtime(
            &handle,
            &proof,
            &SidecarEndpoint::Tcp { addr: sidecar_addr },
            &identity,
            &flags,
            authority,
            &capability_lease_conf(),
        )
        .expect("prepare_network_runtime must still prepare the host bridge");

        assert!(
            !runtime.env_overrides().contains_key("FIRMA_DNS_STUB_ADDR"),
            "macOS DNS stub must not start for non-vz backend"
        );

        drop(runtime);
    }

    // ── EnvOverrides pure builders ──────────────────────────────────────────

    #[test]
    fn env_overrides_bridge_sets_all_six_proxy_vars() {
        let addr: SocketAddr = "127.0.0.1:18080".parse().expect("addr");
        let env = EnvOverrides::default().with_bridge_address(addr);
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            assert_eq!(
                env.get(key).map(String::as_str),
                Some("http://127.0.0.1:18080"),
                "{key}"
            );
        }
    }

    #[test]
    fn env_overrides_structural_proxy_env_sets_runtime_vars() {
        let env = EnvOverrides::default().structural_proxy_env(
            "127.0.0.1:18080",
            "127.0.0.1:53",
            std::path::Path::new("/run/firma/adapter.sock"),
            std::path::Path::new("/usr/bin/firma"),
        );
        assert_eq!(
            env.get("HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:18080")
        );
        assert_eq!(
            env.get("FIRMA_RUN_PROXY_LISTEN_ADDR").map(String::as_str),
            Some("127.0.0.1:18080")
        );
        assert_eq!(
            env.get("FIRMA_RUN_DNS_STUB_LISTEN_ADDR")
                .map(String::as_str),
            Some("127.0.0.1:53")
        );
        assert_eq!(
            env.get("FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS")
                .map(String::as_str),
            Some("/run/firma/adapter.sock")
        );
        assert_eq!(
            env.get("FIRMA_RUN_SELF_EXE").map(String::as_str),
            Some("/usr/bin/firma")
        );
    }

    #[test]
    fn sidecar_adapter_disconnect_errors_are_transient() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = std::io::Error::from(kind);
            assert!(
                super::is_sidecar_adapter_transient_relay_error(&error),
                "{kind:?} should not be logged as an adapter relay warning"
            );
        }

        let error = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(
            !super::is_sidecar_adapter_transient_relay_error(&error),
            "connection failures before relay setup should remain warnings"
        );
    }

    #[test]
    fn env_overrides_dns_stub_address_is_optional() {
        let absent = EnvOverrides::default().with_dns_stub_address(None);
        assert!(!absent.contains_key("FIRMA_DNS_STUB_ADDR"));

        let addr: SocketAddr = "127.0.0.1:5354".parse().expect("addr");
        let present = EnvOverrides::default().with_dns_stub_address(Some(addr));
        assert_eq!(
            present.get("FIRMA_DNS_STUB_ADDR").map(String::as_str),
            Some("127.0.0.1:5354")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn env_overrides_with_egress_sock_sets_var() {
        let env =
            EnvOverrides::default().with_egress_sock(std::path::Path::new("/run/firma/guard.sock"));
        assert_eq!(
            env.get("FIRMA_RUN_EGRESS_GUARD_SOCK").map(String::as_str),
            Some("/run/firma/guard.sock")
        );
    }

    #[test]
    fn env_overrides_from_map_derefs_to_inner() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("K".to_string(), "V".to_string());
        let env = EnvOverrides::from(map);
        assert_eq!(env.get("K").map(String::as_str), Some("V"));
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn sidecar_adapter_relay_terminates_idle_connections() -> Result<(), Box<dyn Error>> {
        let (client_for_relay, _client_peer) = UnixStream::pair()?;
        let upstream_listener = TcpListener::bind("127.0.0.1:0")?;
        let _upstream_peer = TcpStream::connect(upstream_listener.local_addr()?)?;
        let (upstream_for_relay, _) = upstream_listener.accept()?;
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let result = super::relay_unix_to_tcp_with_idle_timeout(
                &client_for_relay,
                &upstream_for_relay,
                Duration::from_millis(100),
            );
            let _ = done_tx.send(result);
        });

        let relay_result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| std::io::Error::other("idle relay did not terminate"))?;
        relay_result?;
        Ok(())
    }

    #[test]
    fn sidecar_adapter_connection_limit_queues_extra_clients_before_upstream_connect()
    -> Result<(), Box<dyn Error>> {
        let tmp = tempfile::tempdir()?;
        let socket_path = tmp.path().join("sidecar-upstream.sock");
        let upstream_listener = TcpListener::bind("127.0.0.1:0")?;
        let upstream_addr = upstream_listener.local_addr()?;
        upstream_listener.set_nonblocking(true)?;
        let upstream_connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&upstream_connections);
        let upstream_task = std::thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..100 {
                match upstream_listener.accept() {
                    Ok((stream, _)) => {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        held.push(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            held
        });

        let adapter = SidecarAdapter::start_with_connection_limit(
            &socket_path,
            &SidecarEndpoint::Tcp {
                addr: upstream_addr,
            },
            1,
        )?;

        let first_client = UnixStream::connect(&socket_path)?;
        for _ in 0..50 {
            if upstream_connections.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(upstream_connections.load(Ordering::SeqCst), 1);

        let second_client = UnixStream::connect(&socket_path)?;
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            upstream_connections.load(Ordering::SeqCst),
            1,
            "adapter must not accept and connect a second relay while the single permit is held"
        );

        drop(second_client);
        drop(first_client);
        drop(adapter);
        let _held = upstream_task
            .join()
            .map_err(|_| std::io::Error::other("upstream task panicked"))?;
        Ok(())
    }

    #[test]
    fn sidecar_adapter_default_limit_supports_browser_like_clients() {
        let max_connections = std::hint::black_box(super::DEFAULT_SIDECAR_ADAPTER_MAX_CONNECTIONS);
        assert!(
            max_connections >= 256,
            "VS Code can hold many concurrent CONNECT/keep-alive sockets during extension installs"
        );
    }
}

#[cfg(test)]
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
