//! Secret-mediation shim injection into the sandbox.
//!
//! When a profile lists `secret_providers`, this wires the secret machinery
//! into a launch: it starts the per-run secret gateway and the out-of-sandbox
//! broker, bind-mounts the `firma-secret-shim` binary over each shimmed
//! executable, and injects the `FIRMA_BROKER_ADDR` environment variable so
//! the shim can reach the broker.
//!
//! The broker runs the real tool on the host (outside the sandbox) and returns
//! its redacted output to the shim. The sandbox never sees plaintext secrets:
//! the plaintext-holding gateway socket lives in the per-run control-plane
//! directory, which bwrap masks from the agent, while only the redaction-only
//! broker socket is reachable from inside the sandbox.
//!
//! The mount/env computation is pure and unit-tested inline; the service
//! startup and mount application are thin glue validated end-to-end on bwrap.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::Arc;

use firma_config_schema::{broker::BrokerConfig, gateway::GatewayConfig};
use firma_core::SecretMatcher;
use firma_secret_provider::{
    IntegrationSpec, broker::server::BrokerListener, endpoint::server::ServerEndpoint,
    gateway::server::GatewayListener, spec::cli::CliIntegrationSpec, store::SecretStore,
};
use tokio::sync::RwLock;

use crate::backend::{
    BrokerBridgeKind, ResolvedGuestShim, SandboxHandle, SandboxMount, SecretShimSupport, ShimTarget,
};
use crate::config::{MountSpec, ResolvedProfile};
use crate::error::RunError;
use crate::secret::accept::serve_forever;

const FIRMA_BROKER_ADDR: &str = "FIRMA_BROKER_ADDR";
const FIRMA_SECRET_PROVIDER_NAMES: &str = "FIRMA_SECRET_PROVIDER_NAMES";
const FIRMA_SECRET_SHIM_SHARE_DIRECTORY: &str = "FIRMA_SECRET_SHIM_SHARE_DIRECTORY";
const FIRMA_SECRET_BROKER_SOCKET_PATH: &str = "FIRMA_SECRET_BROKER_SOCKET_PATH";

/// File name of the shim binary shipped alongside the `firma` executable.
const SHIM_BIN_NAME: &str = "firma-secret-shim";

/// Private directory name (relative to `firma` install dir) containing
/// guest-target shim binaries organized by target triple.
const PRIVATE_SHIM_DIR: &str = "libexec/openfirma/secret-shims";

/// The mounts and env a shimmed launch needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShimPlan {
    /// Bind mounts: one shim overlay per tool.
    mounts: Vec<MountSpec>,
    /// Environment additions pointing the shim at the broker.
    env: Vec<(String, String)>,
}

/// Running secret services (gateway + broker) owned by one `firma run`.
///
/// Dropping the guard stops the service thread and joins it: the listeners are
/// dropped first (their `Drop` removes the Unix socket files), so in-flight
/// connections fail fast and the per-run plaintext `SecretStore` becomes
/// unreachable once the run finishes.
pub struct SecretServices {
    /// Formatted gateway address (`unix://<path>` or `tcp://<addr>`), passed
    /// to the Sidecar via `FIRMA_SECRET_GATEWAY_ADDR` before it starts.
    pub gateway_addr: String,
    /// Formatted broker address, injected into shimmed agent processes.
    broker_addr: String,
    broker_socket_path: Option<PathBuf>,
    control_dir: PathBuf,
    shutdown: Option<tokio::sync::mpsc::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl SecretServices {
    /// Start the secret gateway and broker for one run.
    ///
    /// The gateway socket — the only component holding plaintext secrets — is
    /// bound under the per-run control-plane directory, which the bwrap mount
    /// plan masks from the agent. The broker socket, which only ever returns
    /// redacted output, is bound inside the sandbox runtime directory so the
    /// shimmed processes can reach it.
    ///
    /// Returns once both listeners are bound and their addresses are known, so
    /// the caller can pass the gateway address to the Sidecar before it starts.
    ///
    /// # Errors
    ///
    /// Returns [`RunError`] if the socket directories cannot be created, the
    /// service thread cannot start, or either socket cannot be bound.
    #[expect(
        clippy::too_many_lines,
        reason = "shim spawn must stay linear for better comprehension"
    )]
    pub fn start(
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        identity: &crate::identity::RunIdentity,
        profile: &ResolvedProfile,
        shim_support: &SecretShimSupport,
    ) -> Result<Self, RunError> {
        let gateway_base = runtime_layout
            .run_entry_layout(&identity.sandbox_id)
            .into_root();
        firma_fs::create_private_dir_all(&gateway_base).map_err(|error| {
            RunError::Internal(format!(
                "create secret-gateway dir {}: {error}",
                gateway_base.display()
            ))
        })?;
        let broker_base = match shim_support {
            SecretShimSupport::IsolatedGuest { .. } => gateway_base.join("broker"),
            SecretShimSupport::HostBindMount { .. } | SecretShimSupport::Unsupported { .. } => {
                handle.runtime_dir.join("secret-shims")
            }
        };
        create_private_dir(&broker_base)?;
        let gateway_endpoint = server_endpoint(&gateway_base, "gateway.sock")?;
        let broker_endpoint = server_endpoint(&broker_base, "broker.sock")?;
        #[cfg(unix)]
        let broker_socket_path = Some(broker_base.join("broker.sock"));
        #[cfg(windows)]
        let broker_socket_path = None;

        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);
        let providers = profile.secret_providers.clone();
        let thread = std::thread::Builder::new()
            .name("firma-secret-services".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ =
                            startup_tx.send(Err(format!("build secret service runtime: {error}")));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let gateway =
                        match GatewayListener::bind(&gateway_endpoint, GatewayConfig::default())
                            .await
                        {
                            Ok(listener) => listener,
                            Err(error) => {
                                let _ =
                                    startup_tx.send(Err(format!("bind secret gateway: {error}")));
                                return;
                            }
                        };
                    let broker =
                        match BrokerListener::bind(&broker_endpoint, BrokerConfig::default()).await
                        {
                            Ok(listener) => listener,
                            Err(error) => {
                                let _ =
                                    startup_tx.send(Err(format!("bind secret broker: {error}")));
                                return;
                            }
                        };
                    let gateway_addr = match gateway.bound_endpoint() {
                        Ok(endpoint) => endpoint.to_string(),
                        Err(error) => {
                            let _ = startup_tx
                                .send(Err(format!("query secret gateway bound address: {error}")));
                            return;
                        }
                    };
                    let broker_addr = match broker.bound_endpoint() {
                        Ok(endpoint) => endpoint.to_string(),
                        Err(error) => {
                            let _ = startup_tx
                                .send(Err(format!("query secret broker bound address: {error}")));
                            return;
                        }
                    };
                    if startup_tx.send(Ok((gateway_addr, broker_addr))).is_err() {
                        return;
                    }

                    let store = Arc::new(RwLock::new(SecretStore::new()));
                    let providers = Arc::new(providers);
                    let spec_for = Arc::new(move |bin: &str| {
                        providers
                            .get(bin)
                            .and_then(IntegrationSpec::as_cli)
                            .cloned()
                    });
                    let gateway_store = Arc::clone(&store);
                    let broker_serve = serve_forever(broker, store, spec_for, None);
                    tokio::select! {
                        () = gateway.serve_forever(gateway_store) => {},
                        () = broker_serve => {},
                        _ = shutdown_rx.recv() => {},
                    }
                });
            })
            .map_err(|error| RunError::Internal(format!("start secret service thread: {error}")))?;

        let (gateway_addr, broker_addr) = startup_rx
            .recv()
            .map_err(|error| RunError::Internal(format!("secret service startup failed: {error}")))?
            .map_err(RunError::Internal)?;
        tracing::info!(
            gateway = %gateway_addr,
            broker = %broker_addr,
            "secret services started; Sidecar will read FIRMA_SECRET_GATEWAY_ADDR"
        );
        Ok(Self {
            gateway_addr,
            broker_addr,
            broker_socket_path,
            control_dir: gateway_base,
            shutdown: Some(shutdown_tx),
            join: Some(thread),
        })
    }

    /// Formatted broker address, injected into shimmed agent processes.
    #[must_use]
    pub fn broker_addr(&self) -> &str {
        &self.broker_addr
    }
}

impl Drop for SecretServices {
    fn drop(&mut self) {
        // Drop the shutdown sender first: `select!` sees the disconnect and
        // the runtime leaves `block_on`, dropping both listeners (removing
        // their socket files) and the plaintext store. Join last so the
        // sockets are guaranteed gone when `drop` returns.
        self.shutdown.take();
        if let Some(thread) = self.join.take()
            && thread.join().is_err()
        {
            tracing::warn!("secret service thread panicked during shutdown");
        }
    }
}

/// Prepare secret-shim injection for a launch, mutating `handle` and `env`.
///
/// A no-op when the profile lists no secret providers. Otherwise resolves
/// each shimmed tool on the host `PATH` and appends the shim's bind mounts and
/// environment.
///
/// `services` must be started for the same `profile`. If secret providers are
/// configured but `services` is `None`, returns [`RunError::Internal`] — the
/// caller skipped the start step.
///
/// # Errors
///
/// Returns [`RunError`] if the shim binary or a shimmed tool cannot be located
/// or the started service addresses are unavailable.
pub(super) fn prepare(
    handle: &mut Option<SandboxHandle>,
    profile: &ResolvedProfile,
    env: &mut BTreeMap<String, String>,
    firma_exe: &Path,
    host_path: Option<&OsStr>,
    services: Option<&SecretServices>,
    shim_support: &SecretShimSupport,
) -> Result<(), RunError> {
    if profile.secret_providers.is_empty() {
        return Ok(());
    }
    let handle = handle.as_mut().ok_or_else(|| {
        RunError::Internal("sandbox handle missing for shim injection".to_string())
    })?;
    let services = services.ok_or_else(|| {
        RunError::Internal(
            "secret_shims::prepare called with secret providers but no started services"
                .to_string(),
        )
    })?;

    // Only CLI entries need stdio shim injection (bind mounts over a real
    // executable on PATH); HTTP entries are irrelevant here — they're mirrored
    // into the Sidecar's own config instead (see sidecar::config::synthesize)
    // and intercepted on its MITM path, not via a shim.
    let cli_providers: BTreeMap<String, CliIntegrationSpec<SecretMatcher>> = profile
        .secret_providers
        .iter()
        .filter_map(|(name, spec)| spec.as_cli().map(|cli| (name.clone(), cli.clone())))
        .collect();

    if !cli_providers.is_empty() {
        match shim_support {
            SecretShimSupport::HostBindMount { guest_target } => {
                let shim_bin = locate_shim_binary(firma_exe, guest_target, true)?.path;
                let reals = resolve_real_binaries(&cli_providers, host_path)?;
                let plan = plan(&shim_bin, &reals, services.broker_addr());
                handle
                    .mounts
                    .extend(plan.mounts.into_iter().map(SandboxMount::framework));
                for (key, value) in plan.env {
                    env.insert(key, value);
                }
            }
            SecretShimSupport::IsolatedGuest {
                broker_bridge,
                guest_shim,
                ..
            } => {
                let guest_shim = guest_shim.as_ref().ok_or_else(|| {
                    RunError::Internal(
                        "isolated guest secret shim was not resolved for this run".to_string(),
                    )
                })?;
                let shim_share_directory = services.control_dir.join("guest-secret-shims");
                stage_guest_shim(guest_shim, &shim_share_directory)?;
                let broker_socket_path = services.broker_socket_path.as_ref().ok_or_else(|| {
                    RunError::Internal(
                        "VZ secret broker requires a host Unix socket path".to_string(),
                    )
                })?;
                let provider_names: Vec<String> = cli_providers.keys().cloned().collect();
                env.insert(
                    FIRMA_SECRET_PROVIDER_NAMES.to_string(),
                    serde_json::to_string(&provider_names).map_err(|error| {
                        RunError::Internal(format!(
                            "serialize internal VZ secret provider metadata: {error}"
                        ))
                    })?,
                );
                env.insert(
                    FIRMA_SECRET_SHIM_SHARE_DIRECTORY.to_string(),
                    shim_share_directory.display().to_string(),
                );
                env.insert(
                    FIRMA_SECRET_BROKER_SOCKET_PATH.to_string(),
                    broker_socket_path.display().to_string(),
                );
                env.insert(
                    FIRMA_BROKER_ADDR.to_string(),
                    broker_addr_for_bridge(services.broker_addr(), *broker_bridge),
                );
            }
            SecretShimSupport::Unsupported { .. } => {
                return Err(RunError::Internal(
                    "secret_shims::prepare called with CLI providers but backend does not support shim mediation".to_string(),
                ));
            }
        }
    }

    // Strip vault credential env vars for each shimmed CLI integration so they
    // can never enter the sandbox, even if an operator accidentally listed
    // them in `env_inherit` or `env_set`.
    for spec in cli_providers.values() {
        for var in spec.credential_env_vars() {
            env.remove(var.as_str());
        }
    }

    Ok(())
}

/// Compute the bind mounts and env for the resolved `(name, real path)` tools.
///
/// One mount per tool: the shim overlaid on the tool's own path. The env carries
/// `FIRMA_BROKER_ADDR` pointing at the already-bound broker.
fn plan(shim_bin: &Path, reals: &[(String, PathBuf)], broker_addr: &str) -> ShimPlan {
    let mounts = reals
        .iter()
        .map(|(_, real)| MountSpec {
            source: shim_bin.to_path_buf(),
            target: real.clone(),
            read_only: true,
        })
        .collect();

    let env = vec![(FIRMA_BROKER_ADDR.to_string(), broker_addr.to_string())];

    ShimPlan { mounts, env }
}

/// Returns the broker address that should be injected into the guest environment.
///
/// For `HostBindMount` the host broker is used directly. For `IsolatedGuest`
/// the host broker address is still used on the host side — the guest sees a
/// guest-local address injected by guest-init via the VSOCK bridge.
fn broker_addr_for_bridge(host_broker_addr: &str, _bridge: BrokerBridgeKind) -> String {
    host_broker_addr.to_string()
}

/// Resolve each shimmed tool name to its real host path via `PATH`.
fn resolve_real_binaries(
    providers: &BTreeMap<String, CliIntegrationSpec<SecretMatcher>>,
    host_path: Option<&OsStr>,
) -> Result<Vec<(String, PathBuf)>, RunError> {
    providers
        .keys()
        .map(|name| {
            let real = super::resolve_host_executable(name, host_path)?;
            Ok((name.clone(), real))
        })
        .collect()
}

/// Locate the `firma-secret-shim` binary for the given guest target.
///
/// Looks in the private target-qualified bundle directory first, then in the
/// repository installer's version-qualified Homebrew resource directory, and
/// finally next to `firma_exe` (the legacy bwrap layout).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedShimArtifact {
    target: ShimTarget,
    path: PathBuf,
}

fn locate_shim_binary(
    firma_exe: &Path,
    target: &ShimTarget,
    allow_sibling: bool,
) -> Result<ResolvedShimArtifact, RunError> {
    let shim_name = format!("{SHIM_BIN_NAME}{}", target.exe_suffix);
    let install_dir = firma_exe.with_file_name("");
    let private_dir = install_dir.join(PRIVATE_SHIM_DIR).join(target.triple);
    let private_candidate = private_dir.join(&shim_name);
    if private_candidate.is_file() {
        validate_shim_artifact(&private_candidate, target)?;
        return Ok(ResolvedShimArtifact {
            target: *target,
            path: private_candidate,
        });
    }
    let homebrew_candidate = homebrew_private_shim_candidate(firma_exe, target);
    if let Some(candidate) = &homebrew_candidate
        && candidate.is_file()
    {
        validate_shim_artifact(candidate, target)?;
        return Ok(ResolvedShimArtifact {
            target: *target,
            path: candidate.clone(),
        });
    }
    let sibling_candidate = firma_exe.with_file_name(&shim_name);
    if allow_sibling && sibling_candidate.is_file() {
        validate_shim_artifact(&sibling_candidate, target)?;
        return Ok(ResolvedShimArtifact {
            target: *target,
            path: sibling_candidate,
        });
    }
    let homebrew_display = homebrew_candidate.as_deref().map_or_else(
        || "no Homebrew resource path".to_string(),
        |path| path.display().to_string(),
    );
    Err(RunError::Internal(format!(
        "secret shim binary not found for target '{}' next to {} (tried {}, {}, and {})",
        target.triple,
        firma_exe.display(),
        private_candidate.display(),
        homebrew_display,
        sibling_candidate.display(),
    )))
}

fn homebrew_private_shim_candidate(firma_exe: &Path, target: &ShimTarget) -> Option<PathBuf> {
    let canonical_exe = firma_exe.canonicalize().ok();
    let prefix = homebrew_prefix_from_keg(firma_exe)
        .or_else(|| canonical_exe.as_deref().and_then(homebrew_prefix_from_keg))?;
    Some(
        prefix
            .join("var/openfirma/secret-shims")
            .join(env!("CARGO_PKG_VERSION"))
            .join(target.triple)
            .join(format!("{SHIM_BIN_NAME}{}", target.exe_suffix)),
    )
}

fn homebrew_prefix_from_keg(firma_exe: &Path) -> Option<PathBuf> {
    let bin_dir = firma_exe.parent()?;
    let keg = bin_dir.parent()?;
    let rack = keg.parent()?;
    let cellar = rack.parent()?;
    if bin_dir.file_name()? != "bin"
        || rack.file_name()? != "firma"
        || cellar.file_name()? != "Cellar"
    {
        return None;
    }
    Some(cellar.parent()?.to_path_buf())
}

fn stage_guest_shim(artifact: &ResolvedGuestShim, share_directory: &Path) -> Result<(), RunError> {
    create_private_dir(share_directory)?;
    let destination = share_directory.join(SHIM_BIN_NAME);
    std::fs::write(&destination, &artifact.bytes).map_err(|error| {
        RunError::Internal(format!(
            "stage secret shim {} for target '{}': {error}",
            artifact.source_path.display(),
            artifact.target.triple
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                RunError::Internal(format!(
                    "make staged secret shim executable {}: {error}",
                    destination.display()
                ))
            },
        )?;
    }
    Ok(())
}

pub(crate) fn resolve_guest_shim(
    firma_exe: &Path,
    target: ShimTarget,
    expected_sha256: &[u8; 32],
) -> Result<ResolvedGuestShim, RunError> {
    use sha2::{Digest as _, Sha256};

    let artifact = locate_shim_binary(firma_exe, &target, false)?;
    let bytes = std::fs::read(&artifact.path).map_err(|error| {
        RunError::Internal(format!(
            "read secret shim {} for SHA-256 verification: {error}",
            artifact.path.display()
        ))
    })?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != *expected_sha256 {
        return Err(RunError::Internal(format!(
            "secret shim {} for target '{}' does not match the VZ guest bundle: expected SHA-256 {}, got {}",
            artifact.path.display(),
            artifact.target.triple,
            hex::encode(expected_sha256),
            hex::encode(actual)
        )));
    }
    Ok(ResolvedGuestShim {
        target,
        source_path: artifact.path,
        bytes: bytes.into(),
    })
}

fn validate_shim_artifact(path: &Path, target: &ShimTarget) -> Result<(), RunError> {
    const ELF64_HEADER_SIZE: usize = 64;
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const EV_CURRENT: u8 = 1;
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;

    validate_executable(path)?;
    let mut bytes = [0_u8; ELF64_HEADER_SIZE];
    let mut file = std::fs::File::open(path).map_err(|error| {
        RunError::Internal(format!("read secret shim {}: {error}", path.display()))
    })?;
    if let Err(error) = file.read_exact(&mut bytes) {
        if error.kind() == ErrorKind::UnexpectedEof {
            return Err(RunError::Internal(format!(
                "secret shim {} has a truncated ELF header for target '{}'",
                path.display(),
                target.triple
            )));
        }
        return Err(RunError::Internal(format!(
            "read secret shim {}: {error}",
            path.display()
        )));
    }
    let expected_machine = match target.triple {
        "x86_64-unknown-linux-musl" => 62_u16,
        "aarch64-unknown-linux-musl" => 183_u16,
        other => {
            return Err(RunError::Internal(format!(
                "unsupported secret shim target '{other}'"
            )));
        }
    };
    let file_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    let elf_version = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let header_size = usize::from(u16::from_le_bytes([bytes[52], bytes[53]]));
    let valid = bytes[..4] == *b"\x7fELF"
        && bytes[4] == ELFCLASS64
        && bytes[5] == ELFDATA2LSB
        && bytes[6] == EV_CURRENT
        && matches!(file_type, ET_EXEC | ET_DYN)
        && machine == expected_machine
        && elf_version == u32::from(EV_CURRENT)
        && header_size == ELF64_HEADER_SIZE;
    if !valid {
        return Err(RunError::Internal(format!(
            "secret shim {} has an incompatible ELF header for target '{}'",
            path.display(),
            target.triple
        )));
    }
    Ok(())
}

fn validate_executable(path: &Path) -> Result<(), RunError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::metadata(path).map_err(|error| {
            RunError::Internal(format!("stat secret shim {}: {error}", path.display()))
        })?;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(RunError::Internal(format!(
                "secret shim is not executable: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn server_endpoint(base: &Path, socket_name: &str) -> Result<ServerEndpoint, RunError> {
    #[cfg(unix)]
    {
        ServerEndpoint::from_str(&format!("unix://{}", base.join(socket_name).display()))
            .map_err(|error| RunError::Internal(format!("build secret service endpoint: {error}")))
    }
    #[cfg(windows)]
    {
        let _ = (base, socket_name);
        ServerEndpoint::from_str("tcp://127.0.0.1:0")
            .map_err(|error| RunError::Internal(format!("build secret service endpoint: {error}")))
    }
}

fn create_private_dir(path: &Path) -> Result<(), RunError> {
    std::fs::create_dir_all(path).map_err(|error| {
        RunError::Internal(format!(
            "create secret-shim dir {}: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(path)
            .map_err(|error| RunError::Internal(format!("stat {}: {error}", path.display())))?
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).map_err(|error| {
            RunError::Internal(format!("chmod secret-shim dir {}: {error}", path.display()))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendKind, BrokerBridgeKind};
    use crate::config::resolve_profile;
    use crate::identity::RunIdentity;
    use crate::runtime::RunInput;
    use firma_runtime_state::RuntimeLayout;
    use firma_secret_provider::IntegrationRegistry;

    fn builtin_spec(name: &str) -> CliIntegrationSpec<SecretMatcher> {
        IntegrationRegistry::with_builtins()
            .for_binary(name)
            .cloned()
            .unwrap_or_else(|| panic!("missing built-in spec for {name}"))
    }

    fn vz_run_input(config: PathBuf) -> RunInput {
        RunInput {
            profile: "generic".to_string(),
            config: Some(config),
            backend: Some(BackendKind::Vz),
            sidecar_cli: crate::sidecar::SidecarCli::Unset,
            capability_file: None,
            identity_mode: None,
            preserve_host_user: false,
            print_effective_config: false,
            no_autostart: false,
            sidecar_template_path: None,
            sidecar_startup_timeout_secs: 10,
            command: vec!["true".to_string()],
            authority_cli: crate::authority::AuthorityCli::Unset,
            authority_profile: firma_authority::DEFAULT_PROFILE.to_string(),
            user_config_path: None,
            allow_non_structural: true,
            monitor_mode: false,
        }
    }

    fn resolve_vz_profile(root: &Path, secret_providers: &str) -> ResolvedProfile {
        let config = root.join("firma.toml");
        std::fs::write(
            &config,
            format!(
                r#"
[run.profiles.generic]
backend = "vz"

[run.profiles.generic.network]
enforce_network_namespace = false

[run.defaults]
secret_providers = {secret_providers}
"#
            ),
        )
        .expect("write VZ profile config");
        resolve_profile(&vz_run_input(config)).expect("resolve VZ profile")
    }

    fn isolated_guest_support() -> SecretShimSupport {
        SecretShimSupport::IsolatedGuest {
            guest_target: ShimTarget::from_linux_musl_triple("x86_64-unknown-linux-musl")
                .expect("supported test target"),
            broker_bridge: BrokerBridgeKind::VsockPort { port: 18_083 },
            guest_shim: None,
        }
    }

    #[test]
    fn empty_and_http_only_vz_profiles_prepare_without_secret_shim_metadata() {
        let profiles = [
            ("empty", "[]"),
            (
                "http-only",
                r#"[{ type = "http", provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", matchers = [{ type = "safe_command", path = "/health" }] }]"#,
            ),
        ];
        for (case, providers) in profiles {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let profile = resolve_vz_profile(tempdir.path(), providers);
            let identity = RunIdentity::new(crate::identity::test_agent_id(), "generic");
            let mut handle = Some(SandboxHandle {
                backend: BackendKind::Vz,
                runtime_dir: tempdir.path().join("sandbox"),
                identity: identity.clone(),
                mounts: Vec::new(),
                network_policy: profile.network.clone(),
            });
            let runtime_layout = RuntimeLayout::from_root(tempdir.path().join("runtime-state"));
            let support = isolated_guest_support();
            let services = if profile.secret_providers.is_empty() {
                None
            } else {
                Some(
                    SecretServices::start(
                        &runtime_layout,
                        handle.as_ref().expect("sandbox handle"),
                        &identity,
                        &profile,
                        &support,
                    )
                    .expect("start HTTP-only secret services"),
                )
            };
            let mut env = BTreeMap::new();

            prepare(
                &mut handle,
                &profile,
                &mut env,
                Path::new("/unused/firma"),
                None,
                services.as_ref(),
                &support,
            )
            .expect("prepare profile secret shims");

            for key in [
                FIRMA_SECRET_PROVIDER_NAMES,
                FIRMA_SECRET_SHIM_SHARE_DIRECTORY,
                FIRMA_SECRET_BROKER_SOCKET_PATH,
                FIRMA_BROKER_ADDR,
            ] {
                assert!(
                    !env.contains_key(key),
                    "{case} profile must not prepare VZ secret-shim metadata key {key}"
                );
            }
        }
    }

    #[test]
    fn plan_overlays_shim_with_broker_addr_env() {
        let shim_bin = PathBuf::from("/opt/firma/firma-secret-shim");
        let reals = vec![
            ("bws".to_string(), PathBuf::from("/usr/bin/bws")),
            ("npx".to_string(), PathBuf::from("/usr/local/bin/npx")),
        ];
        let broker_addr = "unix:///run/firma/secret-shims/broker.sock";

        let plan = plan(&shim_bin, &reals, broker_addr);

        // One mount per tool: shim overlaid on the tool's own path.
        assert_eq!(plan.mounts.len(), 2);
        assert!(plan.mounts.contains(&MountSpec {
            source: shim_bin.clone(),
            target: PathBuf::from("/usr/bin/bws"),
            read_only: true,
        }));
        assert!(plan.mounts.contains(&MountSpec {
            source: shim_bin,
            target: PathBuf::from("/usr/local/bin/npx"),
            read_only: true,
        }));

        // One env var: FIRMA_BROKER_ADDR set to the given broker address.
        assert_eq!(plan.env.len(), 1);
        assert_eq!(plan.env[0].0, FIRMA_BROKER_ADDR);
        assert_eq!(plan.env[0].1, broker_addr);
    }

    #[test]
    fn resolve_real_binaries_finds_tools_on_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tool = dir.path().join("bws");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write fake tool");

        let providers = BTreeMap::from([("bws".to_string(), builtin_spec("bws"))]);
        let reals =
            resolve_real_binaries(&providers, Some(dir.path().as_os_str())).expect("resolve");
        assert_eq!(reals, vec![("bws".to_string(), tool)]);
    }

    #[test]
    fn resolve_real_binaries_errors_on_missing_tool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let providers = BTreeMap::from([("does-not-exist".to_string(), builtin_spec("bws"))]);

        let error = resolve_real_binaries(&providers, Some(dir.path().as_os_str())).unwrap_err();
        assert!(matches!(error, RunError::ConfigValidation(_)));
    }

    #[test]
    fn credential_env_vars_are_stripped_for_shimmed_integrations() {
        let registry = IntegrationRegistry::with_builtins();
        let mut env = BTreeMap::from([
            ("BWS_ACCESS_TOKEN".to_string(), "secret-token".to_string()),
            ("VAULT_TOKEN".to_string(), "s.abc123".to_string()),
            ("HOME".to_string(), "/home/agent".to_string()),
        ]);

        // Simulate stripping for "bws" only.
        if let Some(spec) = registry.for_binary("bws") {
            for var in spec.credential_env_vars() {
                env.remove(var.as_str());
            }
        }

        assert!(
            !env.contains_key("BWS_ACCESS_TOKEN"),
            "bws token must be stripped"
        );
        // VAULT_TOKEN is not stripped since vault is not shimmed here.
        assert!(env.contains_key("VAULT_TOKEN"), "vault token untouched");
        // Non-credential vars pass through.
        assert!(env.contains_key("HOME"));
    }

    #[test]
    fn locate_shim_binary_finds_sibling_when_no_private_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firma = dir
            .path()
            .join(format!("firma{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&firma, b"").expect("write firma");
        let host_target = ShimTarget::linux_musl();
        assert!(
            locate_shim_binary(&firma, &host_target, true).is_err(),
            "missing sibling must fail"
        );

        let shim = dir
            .path()
            .join(format!("{SHIM_BIN_NAME}{}", std::env::consts::EXE_SUFFIX));
        write_test_elf(&shim, &host_target);
        assert_eq!(
            locate_shim_binary(&firma, &host_target, true)
                .expect("locate")
                .path,
            shim
        );
    }

    #[test]
    fn locate_shim_binary_prefers_local_then_homebrew_bundle_over_sibling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firma = dir
            .path()
            .join("Cellar/firma/current/bin")
            .join(format!("firma{}", std::env::consts::EXE_SUFFIX));
        std::fs::create_dir_all(firma.parent().expect("firma bin dir"))
            .expect("create firma bin dir");
        std::fs::write(&firma, b"").expect("write firma");

        let target = ShimTarget {
            triple: "x86_64-unknown-linux-musl",
            exe_suffix: "",
        };
        let sibling = firma.with_file_name(format!("{SHIM_BIN_NAME}{}", target.exe_suffix));
        write_test_elf(&sibling, &target);
        let private_dir = firma
            .parent()
            .expect("firma bin dir")
            .join(PRIVATE_SHIM_DIR)
            .join(target.triple);
        std::fs::create_dir_all(&private_dir).expect("create private dir");
        let private_shim = private_dir.join(format!("{SHIM_BIN_NAME}{}", target.exe_suffix));
        write_test_elf(&private_shim, &target);

        let homebrew_shim = dir
            .path()
            .join("var/openfirma/secret-shims")
            .join(env!("CARGO_PKG_VERSION"))
            .join(target.triple)
            .join(format!("{SHIM_BIN_NAME}{}", target.exe_suffix));
        std::fs::create_dir_all(homebrew_shim.parent().expect("Homebrew shim dir"))
            .expect("create Homebrew shim dir");
        write_test_elf(&homebrew_shim, &target);

        let resolved = locate_shim_binary(&firma, &target, true).expect("locate");
        assert_eq!(
            resolved.path, private_shim,
            "private bundle takes priority over sibling"
        );

        std::fs::remove_file(&private_shim).expect("remove private shim");
        assert_eq!(
            locate_shim_binary(&firma, &target, true)
                .expect("locate Homebrew resource")
                .path,
            homebrew_shim,
            "version-qualified Homebrew resource takes priority over sibling"
        );

        std::fs::remove_file(&homebrew_shim).expect("remove Homebrew shim");
        assert_eq!(
            locate_shim_binary(&firma, &target, true)
                .expect("locate sibling")
                .path,
            sibling
        );
    }

    #[test]
    fn shim_lookup_rejects_malformed_and_incompatible_elf_headers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firma = dir.path().join("firma");
        std::fs::write(&firma, b"").expect("write firma");
        let target = ShimTarget::from_linux_musl_triple("x86_64-unknown-linux-musl")
            .expect("supported target");
        let shim = firma.with_file_name(SHIM_BIN_NAME);
        let valid_header = test_elf_header(&target);

        let invalid_headers = [
            ("truncated", valid_header[..63].to_vec()),
            ("bad magic", mutated_header(&valid_header, 0, 0)),
            ("32-bit class", mutated_header(&valid_header, 4, 1)),
            ("big endian", mutated_header(&valid_header, 5, 2)),
            ("stale ident version", mutated_header(&valid_header, 6, 0)),
            ("unsupported type", mutated_header(&valid_header, 16, 1)),
            ("stale ELF version", mutated_header(&valid_header, 20, 0)),
            ("wrong machine", mutated_header(&valid_header, 18, 183)),
            ("wrong header size", mutated_header(&valid_header, 52, 63)),
        ];

        for (case, header) in invalid_headers {
            std::fs::write(&shim, header).expect("write invalid ELF");
            make_executable(&shim);
            assert!(
                locate_shim_binary(&firma, &target, true).is_err(),
                "{case} ELF header must be rejected"
            );
        }
    }

    #[test]
    fn isolated_guest_staging_uses_the_resolved_shim_bytes_after_source_replacement() {
        use sha2::{Digest as _, Sha256};

        let dir = tempfile::tempdir().expect("tempdir");
        let target = ShimTarget::from_linux_musl_triple("x86_64-unknown-linux-musl")
            .expect("supported target");
        let firma = dir.path().join("firma");
        let private_dir = dir.path().join(PRIVATE_SHIM_DIR).join(target.triple);
        std::fs::create_dir_all(&private_dir).expect("create private shim dir");
        let source = private_dir.join(SHIM_BIN_NAME);
        write_test_elf(&source, &target);
        let original = std::fs::read(&source).expect("read shim");
        let expected: [u8; 32] = Sha256::digest(&original).into();
        let artifact = resolve_guest_shim(&firma, target, &expected).expect("resolve guest shim");
        std::fs::write(&source, b"replaced after resolution").expect("replace source shim");
        let share_directory = dir.path().join("share");

        stage_guest_shim(&artifact, &share_directory).expect("matching shim should stage");

        assert_eq!(
            std::fs::read(share_directory.join(SHIM_BIN_NAME)).expect("read staged shim"),
            original
        );
    }

    #[test]
    fn isolated_guest_resolution_rejects_mismatched_shim_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = ShimTarget::from_linux_musl_triple("x86_64-unknown-linux-musl")
            .expect("supported target");
        let firma = dir.path().join("firma");
        let private_dir = dir.path().join(PRIVATE_SHIM_DIR).join(target.triple);
        std::fs::create_dir_all(&private_dir).expect("create private shim dir");
        write_test_elf(&private_dir.join(SHIM_BIN_NAME), &target);

        let error = resolve_guest_shim(&firma, target, &[0_u8; 32])
            .expect_err("mismatched shim must not resolve");

        assert!(
            error
                .to_string()
                .contains("does not match the VZ guest bundle")
        );
    }

    fn write_test_elf(path: &Path, target: &ShimTarget) {
        std::fs::write(path, test_elf_header(target)).expect("write test ELF");
        make_executable(path);
    }

    fn test_elf_header(target: &ShimTarget) -> Vec<u8> {
        let machine = match target.triple {
            "x86_64-unknown-linux-musl" => 62_u16,
            "aarch64-unknown-linux-musl" => 183_u16,
            other => panic!("unsupported test target {other}"),
        };
        let mut bytes = vec![0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes
    }

    fn mutated_header(header: &[u8], offset: usize, value: u8) -> Vec<u8> {
        let mut mutated = header.to_vec();
        mutated[offset] = value;
        mutated
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod test executable");
        }
        #[cfg(windows)]
        let _ = path;
    }
}
