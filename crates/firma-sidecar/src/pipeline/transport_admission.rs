//! Admission for catalog-classified transports against their pinned mappings.

use super::snapshot::stale_bundle_deny;
use super::{EnforcementPipeline, audit_payload_from_decision};
use crate::audit::AuditPayload;
use crate::authority_client::swappable_policy::PublishedSnapshot;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;
use crate::enforcement::decision::EnforcementDecision;
use crate::normalizer::RawRequest;

impl EnforcementPipeline {
    /// Admit a request against its pinned generation before anything is
    /// classified with it: an unready or expired generation cannot classify,
    /// so its mapping verdict would only mislead.
    #[expect(
        clippy::result_large_err,
        reason = "pipeline decisions carry denial context"
    )]
    pub(super) fn pinned_generation_admission(
        &self,
        snapshot: Option<&PublishedSnapshot>,
    ) -> Result<(), EnforcementDecision> {
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        self.check_readiness()?;
        if snapshot.is_fresh() {
            Ok(())
        } else {
            Err(stale_bundle_deny(None, None))
        }
    }

    /// Admit a catalog-classified transport only when its pinned mappings
    /// classify the transport request itself.
    #[expect(
        clippy::result_large_err,
        reason = "pipeline decisions carry denial context"
    )]
    pub(super) fn managed_transport_admission(
        &self,
        request: &RawRequest,
        snapshot: Option<&PublishedSnapshot>,
    ) -> Result<(), EnforcementDecision> {
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        self.pinned_generation_admission(Some(snapshot))?;
        snapshot.normalizer().normalize(request).map(|_| ())
    }

    /// Audit a handler-level protocol denial using one runtime generation.
    pub(crate) fn audit_protocol_denial(
        &self,
        decision: &EnforcementDecision,
        request: &RawRequest,
        session_id: &str,
    ) -> AuditPayload {
        let snapshot = self.runtime_snapshot.as_ref().map(|handle| handle.load());
        let version = snapshot.as_ref().map_or_else(
            || self.constraint_enforcer.policy_version(),
            |pin| pin.version(),
        );
        let mut audit = audit_payload_from_decision(
            decision,
            request,
            session_id,
            std::time::Duration::ZERO,
            version.as_deref(),
        );
        redact_managed_audit(snapshot.as_deref(), &mut audit);
        audit
    }

    /// Catalog discovery passthrough still needs managed transport admission.
    pub(crate) fn composio_passthrough(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> (EnforcementDecision, AuditPayload) {
        let snapshot = self.runtime_snapshot.as_ref().map(|handle| handle.load());
        let mut decision = self
            .managed_transport_admission(request, snapshot.as_deref())
            .err()
            .unwrap_or_else(|| EnforcementDecision::Passthrough {
                detail: "recognized Composio non-execution request".to_string(),
            });
        let version = snapshot.as_ref().and_then(|pin| pin.version());
        let mut audit = audit_payload_from_decision(
            &decision,
            request,
            session_id,
            std::time::Duration::ZERO,
            version.as_deref(),
        );
        redact_managed_audit(snapshot.as_deref(), &mut audit);
        // Normalization and diagnostic preparation can consume the pin's TTL.
        // Discovery has its own forwarding path, so it needs final admission too.
        if snapshot.as_ref().is_some_and(|pin| !pin.is_fresh()) {
            decision = super::snapshot::reject_expired_pin(decision, snapshot.as_deref());
            audit = audit_payload_from_decision(
                &decision,
                request,
                session_id,
                std::time::Duration::ZERO,
                version.as_deref(),
            );
            redact_managed_audit(snapshot.as_deref(), &mut audit);
        }
        (decision, audit)
    }
}

pub(super) fn redact_managed_audit(snapshot: Option<&PublishedSnapshot>, audit: &mut AuditPayload) {
    ManagedAuditRedaction::new(snapshot).apply(audit);
}

/// Generation-owned redaction applied independently to each child's diagnostics.
pub(super) struct ManagedAuditRedaction<'a> {
    normalizer: Option<&'a crate::normalizer::IntentNormalizer>,
}

impl<'a> ManagedAuditRedaction<'a> {
    pub(super) fn new(snapshot: Option<&'a PublishedSnapshot>) -> Self {
        Self {
            normalizer: snapshot.map(PublishedSnapshot::normalizer),
        }
    }

    pub(super) fn apply(&self, audit: &mut AuditPayload) {
        if let Some(normalizer) = self.normalizer {
            audit.resource = normalizer.redact_query(&audit.resource);
            audit.deny_reason = normalizer.redact_query(&audit.deny_reason);
        }
    }
}
