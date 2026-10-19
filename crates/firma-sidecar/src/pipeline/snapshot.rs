//! Final admission checks against the request's pinned runtime generation.

use firma_core::DenyReason;

use crate::authority_client::swappable_policy::PublishedSnapshot;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;
use crate::enforcement::decision::{
    ConstraintEnforcementStage, DenyIdentity, EnforcementDecision, EnforcementStage,
};
use crate::normalizer::NormalizedEnvelope;

// Credential injection can await after Stage 2 checks freshness. A replacement
// must not lend its deadline to this request's pin when that wait finishes.
pub(super) fn reject_expired_pin(
    decision: EnforcementDecision,
    snapshot: Option<&PublishedSnapshot>,
) -> EnforcementDecision {
    if snapshot.is_none_or(PolicyEvaluation::is_fresh) {
        return decision;
    }
    match decision {
        EnforcementDecision::Allow {
            claims, envelope, ..
        }
        | EnforcementDecision::Modify {
            claims, envelope, ..
        } => stale_bundle_deny(
            Some(NormalizedEnvelope::new(
                envelope.intent().clone(),
                envelope.metadata().timestamp,
            )),
            Some(DenyIdentity::from_claims(&claims)),
        ),
        EnforcementDecision::Passthrough { .. } => stale_bundle_deny(None, None),
        other => other,
    }
}

/// Deny a request whose pinned generation is past its freshness deadline.
pub(super) fn stale_bundle_deny(
    envelope: Option<NormalizedEnvelope>,
    identity: Option<DenyIdentity>,
) -> EnforcementDecision {
    EnforcementDecision::Deny {
        reason: DenyReason::PolicyBundleStale,
        stage: EnforcementStage::ConstraintEnforcement(ConstraintEnforcementStage::BundleFreshness),
        detail: "policy bundle unavailable or stale".to_string(),
        envelope,
        identity,
    }
}
