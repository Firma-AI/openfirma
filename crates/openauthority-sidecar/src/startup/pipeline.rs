//! Enforcement pipeline construction.
//!
//! Reads the mapping rules file, assembles the normalizer, both
//! enforcement stages, and the credential injector, and wraps them in
//! an [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline).
//!
//! When `[preflight]` is configured, the caller must call
//! [`startup::run_preflight`](crate::startup::preflight::run_preflight)
//! first and pass the result to
//! [`build_pipeline_runtime`] via the `preflight` argument.
//! Without it, Stage 1 falls back to the stub verifier (always deny).

use std::sync::Arc;

use openauthority_core::RevocationStore;

use crate::authority_client::readiness::{ReadinessFlag, ReadinessState};
use crate::authority_client::swappable_policy::SwappablePolicyEvaluation;
use crate::config;
use crate::enforcement::revocation::BloomLruRevocationStore;
use crate::pipeline;
use crate::startup::credential::build_credential_injector;
use crate::startup::preflight::PreflightResult;

/// Runtime state produced while building the enforcement pipeline.
pub struct PipelineRuntime {
    /// Request enforcement pipeline.
    pub pipeline: Arc<pipeline::EnforcementPipeline>,
    /// Store shared by Stage 1 and the Authority revocation task.
    pub revocation_store: Arc<dyn RevocationStore + Send + Sync>,
    /// Policy snapshot shared by Stage 2 and the Authority bundle task.
    pub swappable_policy: Arc<SwappablePolicyEvaluation>,
    /// Writable readiness flag for Authority tasks.
    pub readiness: Arc<ReadinessFlag>,
    /// Total mapping rule count loaded across primary + extra files.
    /// Surfaced for the standalone-startup log contract (line 2).
    pub mapping_rules_loaded: usize,
}

/// Build the enforcement pipeline plus stream-client shared state.
///
/// Pass a [`PreflightResult`] to populate Stage 1 with a real token and
/// verifier. Without it, Stage 1 uses the stub verifier (always deny).
///
/// # Errors
///
/// Returns an error when pipeline component construction fails.
pub fn build_pipeline_runtime(
    config: &config::SidecarConfig,
    preflight: Option<PreflightResult>,
) -> anyhow::Result<PipelineRuntime> {
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

    let merged_file = config::MappingRulesFile { rules: all_rules };
    let mapping_rules_loaded = merged_file.rules.len();

    let registry = pipeline::ActionClassRegistry::v0_1();
    let table = pipeline::MappingTable::from_config(
        &merged_file,
        &registry,
        config.enforcement.mapping.default_protected,
    )
    .map_err(|e| anyhow::anyhow!("failed to build mapping table: {e}"))?;

    let normalizer = pipeline::IntentNormalizer::new(table);

    let revocation_store = Arc::new(BloomLruRevocationStore::new(config.revocation.into()));
    tracing::debug!(
        initial_metrics = ?revocation_store.metrics(),
        "revocation cache initialized"
    );
    let revocation_store_dyn: Arc<dyn RevocationStore + Send + Sync> = revocation_store;

    let (capability_map, token_verifier) = if let Some(pf) = preflight {
        tracing::info!("Stage 1 using pre-flight capability token and PasetoV4Verifier");
        (pf.capability_map, pf.token_verifier)
    } else {
        tracing::debug!("Stage 1 using configured capability seed and authority public key");
        (
            crate::startup::capability::load_capability_map(&config.capability_seed)?,
            crate::startup::capability::build_token_verifier(
                config.authority.public_key_path.as_deref(),
            )?,
        )
    };

    let capability_validator = pipeline::CapabilityValidator::new(
        capability_map,
        token_verifier,
        Arc::clone(&revocation_store_dyn),
        std::time::Duration::from_secs(
            config
                .enforcement
                .capability_validation
                .clock_skew_tolerance_seconds,
        ),
    );

    let initial_policy: Box<dyn pipeline::PolicyEvaluation + Send + Sync> =
        Box::new(crate::authority_client::swappable_policy::DenyAllPolicyEvaluation);
    let swappable_policy = Arc::new(SwappablePolicyEvaluation::new(initial_policy));
    let policy_for_stage: Arc<dyn pipeline::PolicyEvaluation + Send + Sync> =
        Arc::clone(&swappable_policy) as Arc<dyn pipeline::PolicyEvaluation + Send + Sync>;
    let constraint_enforcer = pipeline::ConstraintEnforcer::new(policy_for_stage);

    let credential_injector = build_credential_injector(&config.credentials)?;

    let initial_readiness = if config.policy.authority_url.is_some() {
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
        Arc::new(crate::enforcement::LruSessionStateStore::with_default_capacity());

    let pipeline = pipeline::EnforcementPipeline::new(pipeline::PipelineArgs {
        normalizer,
        capability_validator,
        constraint_enforcer,
        credential_injector,
        session_state_store,
    })
    .with_readiness(readiness_view);
    tracing::debug!("enforcement pipeline initialized");

    Ok(PipelineRuntime {
        pipeline: Arc::new(pipeline),
        revocation_store: revocation_store_dyn,
        swappable_policy,
        readiness,
        mapping_rules_loaded,
    })
}
