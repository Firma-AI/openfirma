//! Enforcement pipeline construction.
//!
//! Reads the mapping rules file, assembles the normalizer, both
//! enforcement stages, and the credential injector, and wraps them in
//! an [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline).

use std::sync::Arc;

use firma_core::{RevocationStore, TokenVerifier};

use crate::authority_client::readiness::{ReadinessFlag, ReadinessState};
use crate::authority_client::swappable_policy::SwappablePolicyEvaluation;
use crate::config;
use crate::enforcement::capability_validation::CapabilityMapHandle;
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
    /// Total mapping rule count loaded across primary + extra files.
    /// Surfaced for the standalone-startup log contract (line 2).
    pub mapping_rules_loaded: usize,
}

/// Load and merge mapping rule files from `config`.
fn load_mapping_rules(config: &config::SidecarConfig) -> anyhow::Result<config::MappingRulesFile> {
    let mut all_rules: Vec<config::MappingRuleConfig> = Vec::new();

    let primary_path = &config.enforcement.mapping.rules_path;
    let primary_content = std::fs::read_to_string(primary_path)
        .map_err(|e| anyhow::anyhow!("failed to read mapping rules from '{primary_path}': {e}"))?;
    let primary_file: config::MappingRulesFile = toml::from_str(&primary_content)
        .map_err(|e| anyhow::anyhow!("failed to parse mapping rules '{primary_path}': {e}"))?;
    primary_file
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid mapping rules '{primary_path}': {e}"))?;
    all_rules.extend(primary_file.rules);

    for extra_path in &config.enforcement.mapping.rules_paths {
        let extra_content = std::fs::read_to_string(extra_path).map_err(|e| {
            anyhow::anyhow!("failed to read mapping rules from '{extra_path}': {e}")
        })?;
        let extra_file: config::MappingRulesFile = toml::from_str(&extra_content)
            .map_err(|e| anyhow::anyhow!("failed to parse mapping rules '{extra_path}': {e}"))?;
        extra_file
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid mapping rules '{extra_path}': {e}"))?;
        all_rules.extend(extra_file.rules);
    }

    Ok(config::MappingRulesFile { rules: all_rules })
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
    config: &config::SidecarConfig,
) -> anyhow::Result<Arc<dyn crate::enforcement::SessionStateStore>> {
    use crate::config::SessionStateBackend;
    let ce = &config.enforcement.constraint_enforcement;
    let capacity = ce.session_state_capacity;
    match ce.session_state_backend {
        SessionStateBackend::Lru => {
            tracing::debug!(capacity, "session-state backend: lru (in-memory)");
            Ok(Arc::new(crate::enforcement::LruSessionStateStore::new(
                capacity,
            )))
        }
        SessionStateBackend::Persistent => {
            let runtime_dir = firma_runtime_state::runtime_paths::default_runtime_dir();
            let path = match &ce.session_state_path {
                Some(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
                _ => crate::enforcement::PersistentSessionStateStore::default_path(&runtime_dir),
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

/// Name of the environment variable that must be set to `"1"` to honor a
/// configured `monitor` mode. Prevents an accidental enforcement bypass when
/// `mode = "monitor"` is left set in a production config.
const MONITOR_MODE_ENV: &str = "FIRMA_ALLOW_MONITOR_MODE";

/// Resolve the effective enforcement mode, gating `monitor` behind an
/// explicit env-var opt-in.
///
/// Monitor mode is a silent enforcement bypass (every DENY → ALLOW). Requiring
/// `FIRMA_ALLOW_MONITOR_MODE=1` ensures a dev config that leaves
/// `mode = "monitor"` set cannot accidentally disable enforcement in
/// production. Returns [`config::SidecarMode::Enforce`] when monitor mode is
/// requested without the opt-in; otherwise returns the configured mode
/// unchanged.
#[must_use]
fn resolve_effective_mode(
    configured: &config::SidecarMode,
    monitor_env_value: Option<&str>,
) -> config::SidecarMode {
    if *configured == config::SidecarMode::Monitor && monitor_env_value != Some("1") {
        config::SidecarMode::Enforce
    } else {
        configured.clone()
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
pub fn mapping_references_composio_hosts(rules: &config::MappingRulesFile) -> bool {
    rules.rules.iter().any(|rule| {
        let pattern = crate::composio::canonical_host(&rule.host);
        crate::composio::PROTECTED_HOSTS
            .iter()
            .any(|host| crate::normalizer::mapping::glob_match(&pattern, host))
    })
}

/// Warn when mapping rules opt into Composio governance but the HTTPS MITM
/// configuration cannot decode traffic to the protected Composio hosts.
///
/// The pinned catalogs load unconditionally, yet the decoder only sees
/// requests the proxy terminates. A deployment whose mapping rules would
/// match the Composio hosts (including through wildcards and catch-alls)
/// intends to govern that traffic, so every coverage gap is surfaced at
/// startup instead of silently degrading to opaque tunnels. Deployments
/// whose rules cannot match those hosts stay quiet.
fn warn_on_composio_mitm_gaps(config: &config::SidecarConfig, rules: &config::MappingRulesFile) {
    if config.interceptor.mode != config::InterceptorMode::HttpProxy
        || !mapping_references_composio_hosts(rules)
    {
        return;
    }
    for warning in
        crate::startup::interceptor::composio_mitm_coverage_warnings(&config.interceptor.https_mitm)
    {
        tracing::warn!("{warning}");
    }
}

/// Build the enforcement pipeline plus stream-client shared state.
///
/// # Errors
///
/// Returns an error when pipeline component construction fails.
pub fn build_pipeline_runtime(config: &config::SidecarConfig) -> anyhow::Result<PipelineRuntime> {
    let merged_file = load_mapping_rules(config)?;
    let mapping_rules_loaded = merged_file.rule_count();
    warn_on_composio_mitm_gaps(config, &merged_file);

    let registry = pipeline::ActionClassRegistry::v0_1();
    let table = pipeline::MappingTable::from_config(
        &merged_file,
        &registry,
        config.enforcement.mapping.default_protected,
    )
    .map_err(|e| anyhow::anyhow!("failed to build mapping table: {e}"))?;

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
    let runtime_dir = firma_runtime_state::runtime_paths::default_runtime_dir();
    let capabilities_dir = firma_runtime_state::runtime_paths::capabilities_dir_from(&runtime_dir);
    let capability_map = load_capability_map(
        &config.capability_seed,
        token_verifier.as_ref(),
        &capabilities_dir,
    )?;

    // Shared handle: the reload task swaps in a fresh map on seed-file changes.
    let capability_handle = CapabilityMapHandle::new(capability_map);
    let capability_validator = pipeline::CapabilityValidator::new(
        capability_handle.clone(),
        Arc::clone(&token_verifier),
        Arc::clone(&revocation_store_dyn),
        std::time::Duration::from_secs(
            config
                .enforcement
                .capability_validation
                .clock_skew_tolerance_seconds,
        ),
        config.tenancy.mode.clone(),
    );

    let initial_policy: Box<dyn pipeline::PolicyEvaluation + Send + Sync> =
        Box::new(crate::authority_client::swappable_policy::DenyAllPolicyEvaluation);
    let swappable_policy = Arc::new(SwappablePolicyEvaluation::new(initial_policy));
    let policy_for_stage: Arc<dyn pipeline::PolicyEvaluation + Send + Sync> =
        Arc::clone(&swappable_policy) as Arc<dyn pipeline::PolicyEvaluation + Send + Sync>;
    let constraint_enforcer = pipeline::ConstraintEnforcer::new(policy_for_stage);

    let credential_injector = build_credential_injector(&config.credentials)?;

    let initial_readiness = if config.authority.url.is_some() {
        ReadinessState::default()
    } else {
        ReadinessState {
            policy_bundle_ready: true,
            revocation_ready: true,
        }
    };
    let (readiness, readiness_view) = ReadinessFlag::new(initial_readiness);
    let readiness = Arc::new(readiness);

    let session_state_store: Arc<dyn crate::enforcement::SessionStateStore> =
        build_session_state_store(config)?;

    let monitor_env_value = std::env::var(MONITOR_MODE_ENV).ok();
    let effective_mode = resolve_effective_mode(&config.mode, monitor_env_value.as_deref());
    if effective_mode == config::SidecarMode::Monitor {
        tracing::warn!(
            "MONITOR MODE ACTIVE — enforcement is observing only; all calls \
             are allowed through. Never use in production."
        );
    } else if config.mode == config::SidecarMode::Monitor {
        tracing::error!(
            "monitor mode requested via config but {MONITOR_MODE_ENV} is not set \
             to '1'; downgrading to enforce mode for safety. Set \
             {MONITOR_MODE_ENV}=1 to honor monitor mode."
        );
    }

    let pipeline = pipeline::EnforcementPipeline::new(pipeline::PipelineArgs {
        normalizer,
        capability_validator,
        constraint_enforcer,
        credential_injector,
        session_state_store,
    })
    .with_readiness(readiness_view)
    .with_mode(effective_mode);
    tracing::debug!("enforcement pipeline initialized");

    Ok(PipelineRuntime {
        pipeline: Arc::new(pipeline),
        revocation_store: revocation_store_dyn,
        swappable_policy,
        readiness,
        capability_handle,
        token_verifier,
        mapping_rules_loaded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SidecarMode;

    #[test]
    fn enforce_mode_is_unchanged_without_env_opt_in() {
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Enforce, None),
            SidecarMode::Enforce
        );
    }

    #[test]
    fn monitor_mode_downgrades_without_env_opt_in() {
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Monitor, None),
            SidecarMode::Enforce
        );
    }

    #[test]
    fn monitor_mode_downgrades_with_wrong_env_value() {
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Monitor, Some("0")),
            SidecarMode::Enforce
        );
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Monitor, Some("true")),
            SidecarMode::Enforce
        );
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Monitor, Some("")),
            SidecarMode::Enforce
        );
    }

    #[test]
    fn monitor_mode_honored_only_with_explicit_opt_in() {
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Monitor, Some("1")),
            SidecarMode::Monitor
        );
        // Enforce mode is never upgraded to monitor regardless of the env var.
        assert_eq!(
            resolve_effective_mode(&SidecarMode::Enforce, Some("1")),
            SidecarMode::Enforce
        );
    }
}
