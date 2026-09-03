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

use crate::backend::{SandboxHandle, SandboxMount};
use crate::config::{MountSpec, ResolvedProfile};
use crate::error::RunError;
use crate::secret::accept::serve_forever;

const FIRMA_BROKER_ADDR: &str = "FIRMA_BROKER_ADDR";

/// File name of the shim binary shipped alongside the `firma` executable.
const SHIM_BIN_NAME: &str = "firma-secret-shim";

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
        let broker_base = handle.runtime_dir.join("secret-shims");
        create_private_dir(&broker_base)?;
        let gateway_endpoint = server_endpoint(&gateway_base, "gateway.sock")?;
        let broker_endpoint = server_endpoint(&broker_base, "broker.sock")?;

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
        let shim_bin = locate_shim_binary(firma_exe)?;
        let reals = resolve_real_binaries(&cli_providers, host_path)?;
        let plan = plan(&shim_bin, &reals, services.broker_addr());
        handle
            .mounts
            .extend(plan.mounts.into_iter().map(SandboxMount::framework));
        for (key, value) in plan.env {
            env.insert(key, value);
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

/// Locate the `firma-secret-shim` binary shipped alongside `firma_exe`.
///
/// On Windows the sibling carries the `.exe` suffix Cargo appends to every
/// binary, matching how the installers place it next to `firma.exe`.
fn locate_shim_binary(firma_exe: &Path) -> Result<PathBuf, RunError> {
    let shim_name = format!("{SHIM_BIN_NAME}{}", std::env::consts::EXE_SUFFIX);
    let candidate = firma_exe.with_file_name(shim_name);
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(RunError::Internal(format!(
            "secret shim binary not found next to {} (expected {})",
            firma_exe.display(),
            candidate.display()
        )))
    }
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
    use firma_secret_provider::IntegrationRegistry;

    fn builtin_spec(name: &str) -> CliIntegrationSpec<SecretMatcher> {
        IntegrationRegistry::with_builtins()
            .for_binary(name)
            .cloned()
            .unwrap_or_else(|| panic!("missing built-in spec for {name}"))
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
    fn locate_shim_binary_requires_a_platform_named_sibling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firma = dir
            .path()
            .join(format!("firma{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&firma, b"").expect("write firma");
        assert!(
            locate_shim_binary(&firma).is_err(),
            "missing sibling must fail"
        );

        let shim = dir
            .path()
            .join(format!("{SHIM_BIN_NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&shim, b"").expect("write shim");
        assert_eq!(locate_shim_binary(&firma).expect("locate"), shim);
    }
}
