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

use crate::config;
use crate::pipeline;
use crate::startup::credential::build_credential_injector;

/// Build the [`pipeline::EnforcementPipeline`] from a validated
/// [`config::SidecarConfig`].
///
/// Reads the mapping rules file referenced in the config, constructs
/// the action-class registry, normalizer, and both enforcement stages.
///
/// # Errors
///
/// Returns an error when the mapping rules file cannot be read or
/// parsed, or when pipeline components fail to initialize.
pub fn build_pipeline(
    config: &config::SidecarConfig,
) -> anyhow::Result<Arc<pipeline::EnforcementPipeline>> {
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

    // Capability map and token verifier are populated from the Authority
    // at pre-flight; for now use empty defaults so the binary starts.
    // Authority integration (task 007+) will populate these.
    let revocation_store =
        crate::enforcement::revocation::BloomLruRevocationStore::new(config.revocation.into());
    tracing::debug!(
        initial_metrics = ?revocation_store.metrics(),
        "revocation cache initialized"
    );
    let capability_validator = pipeline::CapabilityValidator::new(
        pipeline::CapabilityMap::new(vec![]),
        Box::new(StubTokenVerifier),
        Box::new(revocation_store),
        std::time::Duration::from_secs(
            config
                .enforcement
                .capability_validation
                .clock_skew_tolerance_seconds,
        ),
    );

    // Policy evaluation will be populated from Cedar bundle loading;
    // stub accepts everything for now.
    let constraint_enforcer = pipeline::ConstraintEnforcer::new(Box::new(StubPolicyEvaluation));

    let credential_injector = build_credential_injector(&config.credentials)?;

    let pipeline = pipeline::EnforcementPipeline::new(pipeline::PipelineArgs {
        normalizer,
        capability_validator,
        constraint_enforcer,
        credential_injector,
    });
    tracing::info!("enforcement pipeline initialized");

    Ok(Arc::new(pipeline))
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

/// Stub policy evaluator that accepts everything. Replaced once Cedar
/// bundle loading is wired in.
struct StubPolicyEvaluation;

impl pipeline::PolicyEvaluation for StubPolicyEvaluation {
    fn evaluate(
        &self,
        _principal: &str,
        _action: &str,
        _resource: &str,
        _context: &serde_json::Value,
    ) -> Result<bool, String> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        None
    }
}
