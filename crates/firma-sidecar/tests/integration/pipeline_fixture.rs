use std::num::NonZeroUsize;
use std::sync::Arc;

use firma_core::{CapabilityClaims, TokenError, TokenVerifier};
use firma_identifiers::AgentId;
use firma_sidecar::audit::AuditPayload;
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::credential::NullCredentialInjector;
use firma_sidecar::enforcement::LruSessionStateStore;
use firma_sidecar::enforcement::revocation::{BloomLruRevocationStore, RevocationConfig};
use firma_sidecar::pipeline::{
    ActionClassRegistry, CapabilityMap, CapabilityValidator, ConstraintEnforcer,
    EnforcementPipeline, IntentNormalizer, MappingTable, PipelineArgs, PolicyEvaluation,
};

struct RejectVerifier;

impl TokenVerifier for RejectVerifier {
    fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
        Err(TokenError::SignatureInvalid {
            reason: "fixture has no capabilities".into(),
        })
    }
}

struct RejectPolicy;

impl PolicyEvaluation for RejectPolicy {
    fn evaluate(
        &self,
        _: &AgentId,
        _: &str,
        _: &str,
        _: serde_json::Value,
    ) -> Result<bool, String> {
        Ok(false)
    }
    fn is_fresh(&self) -> bool {
        true
    }
    fn version(&self) -> Option<String> {
        None
    }
}

/// Narrow handler fixtures inject a table directly, without production startup.
pub fn pipeline() -> anyhow::Result<Arc<EnforcementPipeline>> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: None,
                host: "unused.test".into(),
                path: None,
                action_class: "communication.external.read".into(),
            }],
        },
        &ActionClassRegistry::v0_1(),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(Arc::new(EnforcementPipeline::new(PipelineArgs {
        normalizer: IntentNormalizer::new(table),
        capability_validator: CapabilityValidator::new(
            CapabilityMap::new(Vec::new()),
            Arc::new(RejectVerifier),
            Arc::new(BloomLruRevocationStore::new(RevocationConfig::default())),
        ),
        constraint_enforcer: ConstraintEnforcer::new(Arc::new(RejectPolicy)),
        credential_injector: Box::new(NullCredentialInjector),
        session_state_store: Arc::new(LruSessionStateStore::new(
            const { NonZeroUsize::new(16).unwrap() },
        )),
    })))
}

/// The audit payload one enforced request produces, for feeding a sink.
pub async fn audit_payload() -> anyhow::Result<AuditPayload> {
    let request = firma_sidecar::normalizer::RawRequest {
        method: firma_http::Method::GET,
        host: firma_http::Authority::from_static("example.test"),
        path: "/new-event".to_owned(),
        headers: firma_http::HeaderMap::new(),
        body: None,
        is_https: true,
    };
    Ok(pipeline()?.enforce(&request, "new-run").await.1)
}
