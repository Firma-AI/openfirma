//! Secret-mediation shim injection into the sandbox.
//!
//! When a profile lists `secret_providers`, this wires the secret machinery
//! into a launch: it starts the out-of-sandbox broker, bind-mounts the
//! `firma-secret-shim` binary over each shimmed executable, and injects the
//! `FIRMA_BROKER_ADDR` environment variable so the shim can reach the broker.
//!
//! The broker runs the real tool on the host (outside the sandbox) and returns
//! its intercepted stdout to the shim. The sandbox never sees plaintext secrets.
//!
//! The mount/env computation ([`plan`]) is pure and unit-tested; the broker
//! startup and mount application are thin glue validated end-to-end on bwrap.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::backend::SandboxHandle;
use crate::config::{CommandMediatorConfig, CommandMediatorEndpoint, MountSpec, ResolvedProfile};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::secret::SecretStore;
use crate::secret::accept::serve_forever;
use crate::secret::broker::BrokerListener;
use crate::secret::gateway::SecretGatewayListener;
use crate::secret::integration::IntegrationSpec;
use crate::secret::pep::{SecretMediationRequest, SecretPepOutcome, request_secret_decision};
use crate::secret::shim::FIRMA_BROKER_ADDR;

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

/// Pre-bound gateway listener returned by [`pre_bind_gateway`].
///
/// Holds the socket open until [`prepare`] starts serving it. The address
/// string is already formatted for `FIRMA_SECRET_GATEWAY_ADDR` and can be
/// passed to the Sidecar before it starts.
pub struct BoundGateway {
    listener: SecretGatewayListener,
    /// Formatted gateway address (`unix:<path>` or `tcp:<addr>`).
    pub addr: String,
}

/// Bind the secret gateway socket before the Sidecar starts.
///
/// Returns `None` when the profile lists no secret providers (no gateway needed).
/// Otherwise binds the gateway socket and returns a [`BoundGateway`] whose
/// `addr` can be set as `FIRMA_SECRET_GATEWAY_ADDR` on the Sidecar process.
/// The socket is held open until [`prepare`] starts serving it.
///
/// Call this before the Sidecar is spawned so the Sidecar can read the address
/// at startup. Pass the returned [`BoundGateway`] to [`prepare`].
///
/// # Errors
///
/// Returns [`RunError`] if the shim directory cannot be created or the gateway
/// socket cannot be bound.
pub fn pre_bind_gateway(
    handle: &SandboxHandle,
    profile: &ResolvedProfile,
) -> Result<Option<BoundGateway>, RunError> {
    if profile.secret_providers.is_empty() {
        return Ok(None);
    }
    let base = handle.runtime_dir.join("secret-shims");
    std::fs::create_dir_all(&base).map_err(|error| {
        RunError::Internal(format!(
            "create secret-shim dir {}: {error}",
            base.display()
        ))
    })?;
    let gateway_endpoint = gateway_endpoint(&base);
    let listener = SecretGatewayListener::bind(&gateway_endpoint)
        .map_err(|error| RunError::Internal(format!("bind secret gateway: {error}")))?;
    let bound = listener.bound_endpoint().map_err(|error| {
        RunError::Internal(format!("query secret gateway bound address: {error}"))
    })?;
    let addr = format_endpoint(&bound);
    tracing::info!(
        gateway = %addr,
        "secret gateway bound; Sidecar will read FIRMA_SECRET_GATEWAY_ADDR"
    );
    Ok(Some(BoundGateway { listener, addr }))
}

/// Prepare secret-shim injection for a launch, mutating `handle` and `env`.
///
/// A no-op when the profile lists no secret providers. Otherwise resolves
/// each shimmed tool on the host `PATH`, starts the broker and the pre-bound
/// gateway, and appends the shim's bind mounts and environment.
///
/// `gateway` must be the value returned by [`pre_bind_gateway`] for the same
/// `profile`. If secret providers are configured but `gateway` is `None`,
/// returns [`RunError::Internal`] — the caller skipped the pre-bind step.
///
/// # Errors
///
/// Returns [`RunError`] if the shim binary or a shimmed tool cannot be located
/// or the broker socket cannot be bound.
pub fn prepare(
    handle: &mut Option<SandboxHandle>,
    profile: &ResolvedProfile,
    identity: &RunIdentity,
    env: &mut BTreeMap<String, String>,
    firma_exe: &Path,
    host_path: Option<&OsStr>,
    gateway: Option<BoundGateway>,
) -> Result<(), RunError> {
    if profile.secret_providers.is_empty() {
        return Ok(());
    }
    let handle = handle.as_mut().ok_or_else(|| {
        RunError::Internal("sandbox handle missing for shim injection".to_string())
    })?;
    let gateway = gateway.ok_or_else(|| {
        RunError::Internal(
            "secret_shims::prepare called with secret providers but no pre-bound gateway"
                .to_string(),
        )
    })?;

    let shim_bin = locate_shim_binary(firma_exe)?;
    let reals = resolve_real_binaries(&profile.secret_providers, host_path)?;
    let base = handle.runtime_dir.join("secret-shims");
    // Directory was already created by pre_bind_gateway; this is idempotent.
    std::fs::create_dir_all(&base).map_err(|error| {
        RunError::Internal(format!(
            "create secret-shim dir {}: {error}",
            base.display()
        ))
    })?;

    let broker_listener = bind_broker(&base)?;
    let broker_bound = broker_listener
        .bound_endpoint()
        .map_err(|error| RunError::Internal(format!("query broker bound address: {error}")))?;
    let broker_addr = format_endpoint(&broker_bound);

    let plan = plan(&shim_bin, &reals, &broker_addr);
    start_broker(
        broker_listener,
        gateway.listener,
        profile.sidecar_local_exec.clone(),
        identity,
        profile.secret_providers.clone(),
    );

    handle.mounts.extend(plan.mounts);
    for (key, value) in plan.env {
        env.insert(key, value);
    }

    // Strip vault credential env vars for each shimmed integration so they
    // can never enter the sandbox, even if an operator accidentally listed
    // them in `env_inherit` or `env_set`.
    for spec in profile.secret_providers.values() {
        for var in &spec.credential_env_vars {
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
    providers: &BTreeMap<String, IntegrationSpec>,
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
fn locate_shim_binary(firma_exe: &Path) -> Result<PathBuf, RunError> {
    let candidate = firma_exe.with_file_name(SHIM_BIN_NAME);
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

/// Choose the gateway endpoint for the current platform.
///
/// On Unix a Unix domain socket in `base` is used (stays in the filesystem
/// namespace, not the network namespace, which matters for bwrap sandboxes
/// with `--unshare-net`). On other platforms TCP loopback with an
/// OS-assigned port is used.
fn gateway_endpoint(base: &Path) -> CommandMediatorEndpoint {
    #[cfg(unix)]
    {
        CommandMediatorEndpoint::Unix {
            path: base.join("gateway.sock"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = base;
        CommandMediatorEndpoint::Tcp {
            addr: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::LOCALHOST,
                0,
            )),
        }
    }
}

/// Bind the broker listener using the platform-appropriate transport.
///
/// On Unix: a Unix domain socket in `base`. On other platforms: TCP loopback
/// with an OS-assigned port.
fn bind_broker(base: &Path) -> Result<BrokerListener, RunError> {
    #[cfg(unix)]
    let endpoint = CommandMediatorEndpoint::Unix {
        path: base.join("broker.sock"),
    };
    #[cfg(not(unix))]
    let endpoint = {
        let _ = base;
        CommandMediatorEndpoint::Tcp {
            addr: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::LOCALHOST,
                0,
            )),
        }
    };
    BrokerListener::bind(&endpoint)
        .map_err(|error| RunError::Internal(format!("bind secret broker: {error}")))
}

/// Bind the broker socket and start serving on detached threads.
///
/// Takes the `gateway_listener` pre-bound by [`pre_bind_gateway`] so the
/// gateway address is already known to the Sidecar before this call.
/// Threads run for the lifetime of the process. `providers` is the fully
/// resolved `binary_name -> IntegrationSpec` map from
/// [`ResolvedProfile::secret_providers`] — built-in lookups and custom specs
/// are already merged by config resolution, so no registry rebuilding is
/// needed here.
fn start_broker(
    listener: BrokerListener,
    gateway_listener: SecretGatewayListener,
    mediator: Option<CommandMediatorConfig>,
    identity: &RunIdentity,
    providers: BTreeMap<String, IntegrationSpec>,
) {
    let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));

    let gateway_store = Arc::clone(&store);
    std::thread::spawn(move || {
        gateway_listener.serve_forever(&gateway_store);
    });

    let session_id = identity.session_id.clone();
    let agent_id = identity.agent_id.to_string();
    let providers = Arc::new(providers);
    let decide_providers = Arc::clone(&providers);
    let decide = Arc::new(move |bin: &str, args: &str| {
        let provider_id = decide_providers
            .get(bin)
            .map_or_else(|| bin.to_string(), |spec| spec.provider_id.clone());
        decide_secret(
            mediator.as_ref(),
            &session_id,
            &agent_id,
            &provider_id,
            bin,
            args,
        )
    });
    let spec_for =
        Arc::new(move |bin: &str| -> Option<IntegrationSpec> { providers.get(bin).cloned() });
    std::thread::spawn(move || {
        serve_forever(listener, store, decide, spec_for, None);
    });
}

/// Render a gateway endpoint as a `unix:<path>` or `tcp:<addr>` address string.
fn format_endpoint(endpoint: &CommandMediatorEndpoint) -> String {
    match endpoint {
        CommandMediatorEndpoint::Unix { path } => format!("unix:{}", path.display()),
        CommandMediatorEndpoint::Tcp { addr } => format!("tcp:{addr}"),
    }
}

/// Ask the Sidecar (via the local-exec governance endpoint) for a decision,
/// failing closed when no endpoint is configured.
fn decide_secret(
    mediator: Option<&CommandMediatorConfig>,
    session_id: &str,
    agent_id: &str,
    provider_id: &str,
    bin: &str,
    args: &str,
) -> SecretPepOutcome {
    let Some(mediator) = mediator else {
        return SecretPepOutcome::Deny(
            "secret mediation requires a sidecar local-exec endpoint, but none is configured"
                .to_string(),
        );
    };
    let request = SecretMediationRequest::new(
        provider_id.to_string(),
        bin.to_string(),
        args.to_string(),
        session_id.to_string(),
        Some(agent_id.to_string()),
    );
    request_secret_decision(&mediator.endpoint, mediator.timeout_ms, &request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::integration::IntegrationRegistry;

    /// Minimal `IntegrationSpec` for tests that only care about the binary
    /// name (e.g. resolving it on `PATH`), not its extraction behavior.
    fn dummy_spec(name: &str) -> IntegrationSpec {
        IntegrationSpec {
            binary_name: name.to_string(),
            provider_id: name.to_string(),
            credential_env_vars: vec![],
            matcher: firma_core::SecretMatcher::Regex {
                pattern: String::new(),
                domain_is_url: false,
            },
            placeholder_template: String::new(),
            strip_arg_flags: vec![],
            forced_args: vec![],
        }
    }

    #[test]
    fn plan_overlays_shim_with_broker_addr_env() {
        let shim_bin = PathBuf::from("/opt/firma/firma-secret-shim");
        let reals = vec![
            ("bws".to_string(), PathBuf::from("/usr/bin/bws")),
            ("npx".to_string(), PathBuf::from("/usr/local/bin/npx")),
        ];
        let broker_addr = "unix:/run/firma/secret-shims/broker.sock";

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

        let providers = BTreeMap::from([("bws".to_string(), dummy_spec("bws"))]);
        let reals =
            resolve_real_binaries(&providers, Some(dir.path().as_os_str())).expect("resolve");
        assert_eq!(reals, vec![("bws".to_string(), tool)]);
    }

    #[test]
    fn resolve_real_binaries_errors_on_missing_tool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let providers =
            BTreeMap::from([("does-not-exist".to_string(), dummy_spec("does-not-exist"))]);

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
        if let Some(spec) = registry.get("bws") {
            for var in &spec.credential_env_vars {
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
    fn locate_shim_binary_requires_a_sibling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firma = dir.path().join("firma");
        std::fs::write(&firma, b"").expect("write firma");
        assert!(locate_shim_binary(&firma).is_err());

        std::fs::write(dir.path().join(SHIM_BIN_NAME), b"").expect("write shim");
        assert_eq!(
            locate_shim_binary(&firma).unwrap(),
            dir.path().join(SHIM_BIN_NAME)
        );
    }
}
