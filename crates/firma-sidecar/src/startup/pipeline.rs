//! Enforcement pipeline construction.
//!
//! Reads the mapping rules file, assembles the normalizer, both
//! enforcement stages, and the credential injector, and wraps them in
//! an [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline).
//!
//! Authority-backed token verification and Cedar policy evaluation are
//! stubbed until the corresponding integration tasks land (task 007+).
//! The revocation cache is real (task 006) but stays empty until the
//! `WatchRevocations` writer is wired up in task 007.

use std::sync::Arc;

use firma_core::RevocationStore;

use crate::authority_client::readiness::{ReadinessFlag, ReadinessState};
use crate::authority_client::swappable_policy::SwappablePolicyEvaluation;
use crate::config;
use crate::enforcement::revocation::BloomLruRevocationStore;
use crate::pipeline;
use crate::startup::credential::build_credential_injector;

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
}

/// Build the enforcement pipeline plus stream-client shared state.
///
/// # Errors
///
/// Returns an error when pipeline component construction fails.
pub fn build_pipeline_runtime(config: &config::SidecarConfig) -> anyhow::Result<PipelineRuntime> {
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

    let registry = pipeline::ActionClassRegistry::v0_1();
    let table = pipeline::MappingTable::from_config(
        &merged_file,
        &registry,
        config.enforcement.mapping.default_protected,
    )
    .map_err(|e| anyhow::anyhow!("failed to build mapping table: {e}"))?;

    let normalizer = pipeline::IntentNormalizer::new(table);

    // Capability map and token verifier are populated from the Authority
    // at pre-flight; for now use empty defaults so the binary starts.
    // Authority integration (task 007+) will populate these.
    let revocation_store = Arc::new(BloomLruRevocationStore::new(config.revocation.into()));
    tracing::debug!(
        initial_metrics = ?revocation_store.metrics(),
        "revocation cache initialized"
    );
    let revocation_store_dyn: Arc<dyn RevocationStore + Send + Sync> = revocation_store;
    let capability_validator = pipeline::CapabilityValidator::new(
        pipeline::CapabilityMap::new(vec![]),
        Box::new(StubTokenVerifier),
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
    tracing::info!("enforcement pipeline initialized");

    Ok(PipelineRuntime {
        pipeline: Arc::new(pipeline),
        revocation_store: revocation_store_dyn,
        swappable_policy,
        readiness,
    })
}

/// Stub token verifier that always rejects. Replaced once Authority
/// integration is wired in.
struct StubTokenVerifier;

impl firma_core::TokenVerifier for StubTokenVerifier {
    fn verify(
        &self,
        _raw_token: &str,
    ) -> Result<firma_core::CapabilityClaims, firma_core::TokenError> {
        Err(firma_core::TokenError::SignatureInvalid {
            reason: "stub verifier: no Authority configured".to_string(),
        })
    }
}
