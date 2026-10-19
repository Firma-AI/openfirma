//! Enforcement pipeline construction.
//!
//! Assembles an initially protected empty normalizer, both
//! enforcement stages, and the credential injector, and wraps them in
//! an [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline).

use std::sync::Arc;

use firma_core::{RevocationStore, TokenVerifier};

use crate::authority_client::readiness::{ReadinessFlag, ReadinessState};
use crate::authority_client::swappable_policy::{RuntimeSnapshot, SwappablePolicyEvaluation};
use crate::config;
use crate::enforcement::capability_validation::CapabilityMapHandle;
use crate::enforcement::constraint_enforcement::PolicyEvaluation as _;
use crate::enforcement::revocation::BloomLruRevocationStore;
use crate::pipeline;
use crate::startup::capability::{build_token_verifier, load_capability_map};
use crate::startup::credential::build_credential_injector;

/// Runtime state produced while building the enforcement pipeline.
pub struct PipelineRuntime {
    /// Request enforcement pipeline.
    pub pipeline: Arc<pipeline::EnforcementPipeline>,
    /// Store shared by Stage 1 and the Authority revocation task.
    pub(crate) revocation_store: Arc<dyn RevocationStore + Send + Sync>,
    /// Policy snapshot shared by Stage 2 and the Authority bundle task.
    pub(crate) swappable_policy: Arc<SwappablePolicyEvaluation>,
    /// Writable readiness flag for Authority tasks.
    pub readiness: Arc<ReadinessFlag>,
    /// Hot-swappable Stage 1 capability map, shared with the background
    /// seed-file reload task so a re-minted token is picked up without restart.
    pub capability_handle: CapabilityMapHandle,
    /// Stage 1 token verifier, shared with the seed-reload task so re-minted
    /// tokens are re-verified with the same verifier the hot path uses.
    pub token_verifier: Arc<dyn TokenVerifier + Send + Sync>,
}

impl PipelineRuntime {
    /// Version and TTL of the currently enforced Authority bundle.
    ///
    /// The version is `None` until the first Authority bundle is accepted.
    #[must_use]
    pub fn enforced_bundle(&self) -> (Option<String>, u32) {
        let snapshot = self.swappable_policy.load();
        (snapshot.version(), snapshot.ttl_seconds())
    }
}

/// Build the session-state store from the configured backend and capacity.
///
/// `lru` (default) selects the in-memory [`LruSessionStateStore`].
/// `persistent` selects the file-backed
/// [`PersistentSessionStateStore`] so per-session context survives
/// eviction and process restart (AARM R2 G4).
///
/// # Errors
///
/// Returns an error when the persistent backend is selected but its log
/// file cannot be created or opened at the resolved path.
fn build_session_state_store(
    runtime_layout: &firma_runtime_state::RuntimeLayout,
    config: &config::SidecarConfig,
) -> anyhow::Result<Arc<dyn crate::enforcement::SessionStateStore>> {
    use firma_config_schema::sidecar::SessionStateBackend;
    let ce = &config.enforcement.constraint_enforcement;
    let capacity = ce.capacity;
    match ce.backend {
        SessionStateBackend::Lru => {
            tracing::debug!(capacity, "session-state backend: lru (in-memory)");
            Ok(Arc::new(crate::enforcement::LruSessionStateStore::new(
                capacity,
            )))
        }
        SessionStateBackend::Persistent => {
            let path = match &ce.path {
                Some(p) if !p.as_os_str().is_empty() => p.clone(),
                _ => runtime_layout.session_state(),
            };
            tracing::debug!(capacity, ?path, "session-state backend: persistent");
            let store = crate::enforcement::PersistentSessionStateStore::open(&path, capacity)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to open persistent session-state log at {}: {e}",
                        path.display()
                    )
                })?;
            Ok(Arc::new(store))
        }
    }
}

/// Return whether any mapping rule host would match a protected Composio
/// host at runtime.
///
/// Rule hosts speak the normalizer's glob language (a `*` may appear
/// anywhere, including a bare catch-all) and may be uppercase or carry a
/// port or trailing dot. Each host is therefore canonicalized exactly like
/// the decoder canonicalizes request hosts, then matched with the same glob
/// the mapping table applies at runtime, so a rule that would classify
/// Composio traffic can never evade this check through its spelling. A
/// catch-all `*` rule counts: it does govern Composio traffic.
#[must_use]
pub fn mapping_hosts_reference_composio<'a>(hosts: impl IntoIterator<Item = &'a str>) -> bool {
    hosts.into_iter().any(|host| {
        let pattern = canonical_rule_host_pattern(host);
        crate::composio::PROTECTED_HOSTS
            .iter()
            .any(|host| crate::normalizer::mapping::glob_match(&pattern, host))
    })
}

/// Canonicalize a mapping-rule host pattern for the coverage check.
///
/// On top of the decoder's canonicalization (lowercase, trailing dot,
/// numeric port), a rule may glob the port (`backend.composio.dev:8*`) and
/// still match Composio traffic on a nonstandard port at runtime, so a port
/// segment made of digits and wildcards is stripped as well before the host
/// part is matched against the protected names.
fn canonical_rule_host_pattern(host: &str) -> String {
    let canonical = crate::composio::canonical_host(host);
    match canonical.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty()
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit() || b == b'*') =>
        {
            name.to_string()
        }
        _ => canonical,
    }
}

/// Build the enforcement pipeline plus stream-client shared state.
///
/// # Errors
///
/// Returns an error when pipeline component construction fails.
pub fn build_pipeline_runtime(
    runtime_layout: &firma_runtime_state::RuntimeLayout,
    config: &config::SidecarConfig,
) -> anyhow::Result<PipelineRuntime> {
    config.authority.target()?;
    let table = pipeline::MappingTable::empty_protected();

    let normalizer = pipeline::IntentNormalizer::with_custom_query_params(
        table,
        config.audit.redact_query_params.clone(),
    );

    let revocation_store = Arc::new(BloomLruRevocationStore::new(config.revocation.into()));
    tracing::debug!(
        initial_metrics = ?revocation_store.metrics(),
        "revocation cache initialized"
    );
    let revocation_store_dyn: Arc<dyn RevocationStore + Send + Sync> = revocation_store;

    tracing::debug!("Stage 1 using configured capability seed and authority public key");
    let token_verifier: Arc<dyn TokenVerifier + Send + Sync> =
        build_token_verifier(config.authority.public_key_path.as_deref())?.into();
    let capability_map = load_capability_map(
        &config.capability_seed,
        token_verifier.as_ref(),
        &runtime_layout.capabilities_dir(),
    )?;

    // Shared handle: the reload task swaps in a fresh map on seed-file changes.
    let capability_handle = CapabilityMapHandle::new(capability_map);
    let capability_validator = pipeline::CapabilityValidator::new(
        capability_handle.clone(),
        Arc::clone(&token_verifier),
        Arc::clone(&revocation_store_dyn),
    );

    let initial_policy: Box<dyn pipeline::PolicyEvaluation + Send + Sync> =
        Box::new(crate::authority_client::swappable_policy::DenyAllPolicyEvaluation);
    let swappable_policy = Arc::new(SwappablePolicyEvaluation::from_snapshot(
        RuntimeSnapshot::new(normalizer.clone(), initial_policy.into(), 0, None),
    ));
    let policy_for_stage: Arc<dyn pipeline::PolicyEvaluation + Send + Sync> =
        Arc::clone(&swappable_policy) as Arc<dyn pipeline::PolicyEvaluation + Send + Sync>;
    let constraint_enforcer = pipeline::ConstraintEnforcer::new(policy_for_stage);

    let credential_injector = build_credential_injector(&config.credentials)?;

    let initial_readiness = ReadinessState::default();
    let (readiness, readiness_view) = ReadinessFlag::new(initial_readiness);
    let readiness = Arc::new(readiness);

    let session_state_store: Arc<dyn crate::enforcement::SessionStateStore> =
        build_session_state_store(runtime_layout, config)?;

    let pipeline = pipeline::EnforcementPipeline::new(pipeline::PipelineArgs {
        normalizer,
        capability_validator,
        constraint_enforcer,
        credential_injector,
        session_state_store,
    })
    .with_readiness(readiness_view)
    .with_runtime_snapshot(Arc::clone(&swappable_policy));
    tracing::debug!("enforcement pipeline initialized");

    Ok(PipelineRuntime {
        pipeline: Arc::new(pipeline),
        revocation_store: revocation_store_dyn,
        swappable_policy,
        readiness,
        capability_handle,
        token_verifier,
    })
}
