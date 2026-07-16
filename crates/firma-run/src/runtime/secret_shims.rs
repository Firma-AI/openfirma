//! Secret-mediation shim injection into the sandbox.
//!
//! When a profile lists `shims`, this wires the secret machinery into a launch:
//! it starts the out-of-sandbox broker, bind-mounts the `firma-secret-shim`
//! binary over each shimmed executable (so absolute-path or renamed invocations
//! still hit it), preserves the real binaries under a lookup dir, and injects
//! the env the shim needs to reach the broker.
//!
//! The mount/env computation ([`plan`]) is pure and unit-tested; the broker
//! startup and mount application are thin glue validated end-to-end on bwrap.
//! See `docs/architecture/secrets-interception.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::backend::SandboxHandle;
use crate::config::{CommandMediatorConfig, MountSpec, ResolvedProfile};
use crate::error::RunError;
use crate::identity::RunIdentity;
use crate::secret::SecretStore;
use crate::secret::accept::serve_forever;
use crate::secret::broker::BrokerListener;
use crate::secret::pep::{SecretMediationRequest, SecretPepOutcome, request_secret_decision};
use crate::secret::shim::{BROKER_SOCK_ENV, REAL_DIR_ENV};

/// File name of the shim binary shipped alongside the `firma` executable.
const SHIM_BIN_NAME: &str = "firma-secret-shim";

/// The mounts and env a shimmed launch needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShimPlan {
    /// Bind mounts: the shim over each tool, and each real tool preserved.
    mounts: Vec<MountSpec>,
    /// Environment additions pointing the shim at the broker and real binaries.
    env: Vec<(String, String)>,
    /// Host path where the broker binds its Unix socket.
    broker_sock: PathBuf,
}

/// Prepare secret-shim injection for a launch, mutating `handle` and `env`.
///
/// A no-op when the profile lists no shims. Otherwise it resolves each shimmed
/// tool on the host `PATH`, starts the broker, and appends the shim's bind
/// mounts and environment.
///
/// # Errors
///
/// Returns [`RunError`] if the shim binary or a shimmed tool cannot be located,
/// the broker socket directory cannot be created, or the broker cannot bind.
pub fn prepare(
    handle: &mut SandboxHandle,
    profile: &ResolvedProfile,
    identity: &RunIdentity,
    env: &mut BTreeMap<String, String>,
    firma_exe: &Path,
    host_path: Option<&OsStr>,
) -> Result<(), RunError> {
    if profile.shims.is_empty() {
        return Ok(());
    }

    let shim_bin = locate_shim_binary(firma_exe)?;
    let reals = resolve_real_binaries(&profile.shims, host_path)?;
    let base = handle.runtime_dir.join("secret-shims");
    std::fs::create_dir_all(base.join("real")).map_err(|error| {
        RunError::Internal(format!(
            "create secret-shim dir {}: {error}",
            base.display()
        ))
    })?;

    let plan = plan(&shim_bin, &reals, &base);
    start_broker(
        &plan.broker_sock,
        profile.sidecar_local_exec.clone(),
        identity,
    )?;

    handle.mounts.extend(plan.mounts);
    for (key, value) in plan.env {
        env.insert(key, value);
    }
    Ok(())
}

/// Compute the bind mounts and env for the resolved `(name, real path)` tools.
fn plan(shim_bin: &Path, reals: &[(String, PathBuf)], base: &Path) -> ShimPlan {
    let real_dir = base.join("real");
    let broker_sock = base.join("broker.sock");

    let mut mounts = Vec::with_capacity(reals.len() * 2);
    for (name, real) in reals {
        // Overlay the shim onto the tool's own path so absolute-path, renamed,
        // or copied invocations still hit it.
        mounts.push(MountSpec {
            source: shim_bin.to_path_buf(),
            target: real.clone(),
            read_only: true,
        });
        // Preserve the real binary where the shim looks it up (by basename).
        mounts.push(MountSpec {
            source: real.clone(),
            target: real_dir.join(name),
            read_only: true,
        });
    }

    let env = vec![
        (
            BROKER_SOCK_ENV.to_string(),
            broker_sock.display().to_string(),
        ),
        (REAL_DIR_ENV.to_string(), real_dir.display().to_string()),
    ];

    ShimPlan {
        mounts,
        env,
        broker_sock,
    }
}

/// Resolve each shimmed tool name to its real host path via `PATH`.
fn resolve_real_binaries(
    shims: &BTreeSet<String>,
    host_path: Option<&OsStr>,
) -> Result<Vec<(String, PathBuf)>, RunError> {
    shims
        .iter()
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

/// Bind the broker socket and serve mediation on a detached thread.
///
/// The thread runs for the lifetime of the process; on a one-shot `firma run`
/// it is torn down when the process exits after the agent finishes.
fn start_broker(
    sock: &Path,
    mediator: Option<CommandMediatorConfig>,
    identity: &RunIdentity,
) -> Result<(), RunError> {
    let listener = BrokerListener::bind(sock).map_err(|error| {
        RunError::Internal(format!(
            "bind secret broker socket {}: {error}",
            sock.display()
        ))
    })?;
    let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
    let session_id = identity.session_id.clone();
    let decide =
        Arc::new(move |argv: &[String]| decide_secret(mediator.as_ref(), &session_id, argv));
    std::thread::spawn(move || serve_forever(listener, store, decide));
    Ok(())
}

/// Ask the Sidecar (via the local-exec governance endpoint) for a decision,
/// failing closed when no endpoint is configured.
fn decide_secret(
    mediator: Option<&CommandMediatorConfig>,
    session_id: &str,
    argv: &[String],
) -> SecretPepOutcome {
    let Some(mediator) = mediator else {
        return SecretPepOutcome::Deny(
            "secret mediation requires a sidecar local-exec endpoint, but none is configured"
                .to_string(),
        );
    };
    let request = SecretMediationRequest::new(argv.to_vec(), session_id.to_string(), None);
    request_secret_decision(&mediator.endpoint, mediator.timeout_ms, &request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_overlays_shim_and_preserves_real_with_env() {
        let shim_bin = PathBuf::from("/opt/firma/firma-secret-shim");
        let reals = vec![
            ("bws".to_string(), PathBuf::from("/usr/bin/bws")),
            ("npx".to_string(), PathBuf::from("/usr/local/bin/npx")),
        ];
        let base = PathBuf::from("/run/firma/secret-shims");

        let plan = plan(&shim_bin, &reals, &base);

        // Two mounts per tool: shim-over-tool, and real preserved by basename.
        assert!(plan.mounts.contains(&MountSpec {
            source: shim_bin.clone(),
            target: PathBuf::from("/usr/bin/bws"),
            read_only: true,
        }));
        assert!(plan.mounts.contains(&MountSpec {
            source: PathBuf::from("/usr/bin/bws"),
            target: PathBuf::from("/run/firma/secret-shims/real/bws"),
            read_only: true,
        }));
        assert!(plan.mounts.contains(&MountSpec {
            source: shim_bin,
            target: PathBuf::from("/usr/local/bin/npx"),
            read_only: true,
        }));
        assert_eq!(plan.mounts.len(), 4);

        assert!(plan.env.contains(&(
            BROKER_SOCK_ENV.to_string(),
            "/run/firma/secret-shims/broker.sock".to_string()
        )));
        assert!(plan.env.contains(&(
            REAL_DIR_ENV.to_string(),
            "/run/firma/secret-shims/real".to_string()
        )));
        assert_eq!(plan.broker_sock, base.join("broker.sock"));
    }

    #[test]
    fn resolve_real_binaries_finds_tools_on_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tool = dir.path().join("bws");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write fake tool");

        let shims = BTreeSet::from(["bws".to_string()]);
        let reals = resolve_real_binaries(&shims, Some(dir.path().as_os_str())).expect("resolve");
        assert_eq!(reals, vec![("bws".to_string(), tool)]);
    }

    #[test]
    fn resolve_real_binaries_errors_on_missing_tool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shims = BTreeSet::from(["does-not-exist".to_string()]);

        let error = resolve_real_binaries(&shims, Some(dir.path().as_os_str())).unwrap_err();
        assert!(matches!(error, RunError::ConfigValidation(_)));
    }

    #[test]
    fn locate_shim_binary_requires_a_sibling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firma = dir.path().join("firma");
        std::fs::write(&firma, b"").expect("write firma");
        // No sibling shim yet.
        assert!(locate_shim_binary(&firma).is_err());

        std::fs::write(dir.path().join(SHIM_BIN_NAME), b"").expect("write shim");
        assert_eq!(
            locate_shim_binary(&firma).unwrap(),
            dir.path().join(SHIM_BIN_NAME)
        );
    }
}
