//! Enforcement pipeline construction.
//!
//! Reads the mapping rules file, assembles the normalizer, both
//! enforcement stages, and the credential injector, and wraps them in
//! an [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline).
//!
//! The Cedar evaluator boots empty: Stage 2 fails closed with
//! `POLICY_BUNDLE_STALE` until the Authority pushes a valid bundle over
//! `WatchPolicyBundle` (task 007) and the [`BundleLoader`] atomically
//! installs the first snapshot. When `policy.authority_url` is unset,
//! the evaluator stays empty for the life of the process — Stage 2
//! remains fail-closed unless tests / dev tooling invoke the loader
//! directly.

use std::sync::Arc;
use std::time::Duration;

use firma_core::RevocationStore;

use crate::authority_client::readiness::{ReadinessFlag, ReadinessState};
use crate::config;
use crate::enforcement::policy::{BundleLoader, CedarPolicyEvaluator};
use crate::enforcement::revocation::BloomLruRevocationStore;
use crate::pipeline;
use crate::startup::credential::build_credential_injector;

/// Runtime state produced while building the enforcement pipeline.
pub struct PipelineRuntime {
    /// Request enforcement pipeline.
    pub pipeline: Arc<pipeline::EnforcementPipeline>,
    /// Store shared by Stage 1 and the Authority revocation task.
    pub revocation_store: Arc<dyn RevocationStore + Send + Sync>,
    /// Bundle loader shared with the Authority `WatchPolicyBundle` task.
    pub bundle_loader: Arc<BundleLoader>,
    /// Writable readiness flag for Authority tasks.
    pub readiness: Arc<ReadinessFlag>,
}

/// Build the enforcement pipeline plus stream-client shared state.
///
/// # Errors
///
/// Returns an error when pipeline component construction fails.
pub fn build_pipeline_runtime(config: &config::SidecarConfig) -> anyhow::Result<PipelineRuntime> {
    let rules_content =
        std::fs::read_to_string(&config.enforcement.mapping.rules_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read mapping rules from '{}': {e}",
                config.enforcement.mapping.rules_path
            )
        })?;
    let rules_file: config::MappingRulesFile = toml::from_str(&rules_content).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse mapping rules '{}': {e}",
            config.enforcement.mapping.rules_path
        )
    })?;
    rules_file.validate().map_err(|e| {
        anyhow::anyhow!(
            "invalid mapping rules '{}': {e}",
            config.enforcement.mapping.rules_path
        )
    })?;

    let registry = pipeline::ActionClassRegistry::v0_1();
    let table = pipeline::MappingTable::from_config(
        &rules_file,
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
    let capability_validator = pipeline::CapabilityValidator::new(
        pipeline::CapabilityMap::new(vec![]),
        Box::new(StubTokenVerifier),
        Arc::clone(&revocation_store_dyn),
        Duration::from_secs(
            config
                .enforcement
                .capability_validation
                .clock_skew_tolerance_seconds,
        ),
    );

    let policy_evaluator = Arc::new(CedarPolicyEvaluator::empty(Duration::from_secs(
        config.enforcement.constraint_enforcement.bundle_ttl_seconds,
    )));
    let bundle_loader = Arc::new(BundleLoader::new(Arc::clone(&policy_evaluator)));
    let policy_for_stage: Arc<dyn pipeline::PolicyEvaluation + Send + Sync> =
        policy_evaluator as Arc<dyn pipeline::PolicyEvaluation + Send + Sync>;
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

    let pipeline = pipeline::EnforcementPipeline::new(pipeline::PipelineArgs {
        normalizer,
        capability_validator,
        constraint_enforcer,
        credential_injector,
    })
    .with_readiness(readiness_view);
    tracing::info!("enforcement pipeline initialized");

    Ok(PipelineRuntime {
        pipeline: Arc::new(pipeline),
        revocation_store: revocation_store_dyn,
        bundle_loader,
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
