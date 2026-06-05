//! Enforcement decision types.
//!
//! Every `enforce()` call produces exactly one [`EnforcementDecision`]:
//! ALLOW, DENY, ABORT, or PASSTHROUGH. ALLOW carries the verified claims and normalized envelope
//! for downstream use (credential injection, connector dispatch, audit).
//! DENY carries a structured reason, the originating stage, and a detail
//! message for audit and agent error reporting.
//!
//! ABORT may be produced by the pipeline only for post-ALLOW local failures
//! such as credential injection. Authority-pushed ABORT remains out of scope
//! for V1.

use firma_core::{
    AbortReason, CapabilityClaims, DenyReason, ExecutionEnvelope, InjectedCredentials,
};

use crate::normalizer::NormalizedEnvelope;

/// Sub-stages within Stage 1 (Capability Validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityValidationStage {
    /// Token selection from the capability map.
    TokenSelection,
    /// Token validation — parse, signature verify, expiry, revocation.
    TokenValidation,
}

/// Sub-stages within Stage 2 (Constraint Enforcement Engine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintEnforcementStage {
    /// Scope check — action class within token's allowed set.
    ScopeCheck,
    /// Policy bundle freshness check.
    BundleFreshness,
    /// Cedar policy evaluation.
    PolicyEvaluation,
}

/// Identifies which pipeline stage produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStage {
    /// Intent normalization — raw request → canonical `ExecutionEnvelope`.
    Normalization,
    /// Stage 1: Capability Validation.
    CapabilityValidation(CapabilityValidationStage),
    /// Stage 2: Constraint Enforcement Engine (CEE).
    ConstraintEnforcement(ConstraintEnforcementStage),
    /// Credential injection — post-enforcement credential fetch failed.
    CredentialInjection,
}

/// Verified agent/token attribution carried by a [`EnforcementDecision::Deny`]
/// raised after capability validation.
///
/// The enforcement pipeline discards the validated `CapabilityClaims` on the
/// denial path, so without this the audit record for a Stage-2 (policy) or
/// credential-injection denial has empty `agent_id`/`token_id`. That made
/// `firma monitor --agent <id>` drop every deny while keeping allows — the
/// gap reported in FIR-208.
#[derive(Debug, Clone)]
pub struct DenyIdentity {
    /// Verified token id.
    pub token_id: String,
    /// Verified agent id.
    pub agent_id: String,
    /// Context hash bound to the verified capability.
    pub context_hash: String,
}

impl DenyIdentity {
    /// Builds a [`DenyIdentity`] from verified capability claims.
    #[must_use]
    pub fn from_claims(claims: &CapabilityClaims) -> Self {
        Self {
            token_id: claims.token_id.to_string(),
            agent_id: claims.agent_id.to_string(),
            context_hash: claims.context_hash.clone(),
        }
    }
}

/// Unified result of the enforcement pipeline.
///
/// Every `enforce()` call produces exactly one of these. Carries enough
/// information for the caller to construct the response, emit audit events,
/// and proceed with credential injection on ALLOW, or forward the request
/// unmodified on PASSTHROUGH.
#[derive(Debug)]
pub enum EnforcementDecision {
    /// Request authorized. Proceed to connector dispatch.
    Allow {
        claims: CapabilityClaims,
        envelope: Box<ExecutionEnvelope>,
        /// Credentials injected after enforcement passed, ready for
        /// the connector layer to merge into the outbound request.
        credentials: InjectedCredentials,
    },
    /// Request denied. Return structured denial to agent.
    Deny {
        reason: DenyReason,
        stage: EnforcementStage,
        detail: String,
        envelope: Option<NormalizedEnvelope>,
        /// Verified agent/token attribution, present only when the
        /// denial is raised AFTER capability validation (Stage 2,
        /// credential injection). `None` for pre-validation denials
        /// (malformed intent, token invalid/expired) where no identity
        /// is known. Carried into the audit record so denies remain
        /// filterable by `--agent` in `firma monitor` (FIR-208).
        identity: Option<DenyIdentity>,
    },
    /// Request was authorized, then aborted before completion.
    Abort {
        reason: AbortReason,
        detail: String,
        /// Verified agent/token attribution. ABORT is only raised after
        /// capability validation, so this should be present for audit.
        identity: Option<DenyIdentity>,
    },
    /// Non-protected traffic. Forward the request without enforcement.
    Passthrough { detail: String },
}

impl EnforcementDecision {
    /// Attaches verified [`DenyIdentity`] to a `Deny` decision so the
    /// audit record carries agent/token attribution. No-op for `Allow`
    /// and `Passthrough`.
    #[must_use]
    pub fn with_identity(mut self, identity: DenyIdentity) -> Self {
        match &mut self {
            Self::Deny { identity: slot, .. } | Self::Abort { identity: slot, .. } => {
                *slot = Some(identity);
            }
            Self::Allow { .. } | Self::Passthrough { .. } => {}
        }
        self
    }

    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    #[must_use]
    pub fn is_abort(&self) -> bool {
        matches!(self, Self::Abort { .. })
    }

    #[must_use]
    pub fn is_passthrough(&self) -> bool {
        matches!(self, Self::Passthrough { .. })
    }

    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Deny { reason, .. } => Some(*reason),
            Self::Allow { .. } | Self::Abort { .. } | Self::Passthrough { .. } => None,
        }
    }

    #[must_use]
    pub fn stage(&self) -> Option<EnforcementStage> {
        match self {
            Self::Deny { stage, .. } => Some(*stage),
            Self::Allow { .. } | Self::Abort { .. } | Self::Passthrough { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_has_reason() {
        let decision = EnforcementDecision::Deny {
            reason: DenyReason::TokenExpired,
            stage: EnforcementStage::CapabilityValidation(
                CapabilityValidationStage::TokenValidation,
            ),
            detail: "token has expired".to_string(),
            envelope: None,
            identity: None,
        };
        assert!(decision.is_deny());
        assert!(!decision.is_allow());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenExpired));
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::CapabilityValidation(
                CapabilityValidationStage::TokenValidation
            ))
        );
    }

    #[test]
    fn test_abort_helpers() {
        let decision = EnforcementDecision::Abort {
            reason: AbortReason::CredentialInjectionFailed,
            detail: "connector api.openai.com: vault unavailable".to_string(),
            identity: None,
        };

        assert!(decision.is_abort());
        assert!(!decision.is_allow());
        assert!(!decision.is_deny());
        assert!(!decision.is_passthrough());
        assert_eq!(decision.deny_reason(), None);
        assert_eq!(decision.stage(), None);
    }

    #[test]
    fn test_allow_helpers() {
        let decision = EnforcementDecision::Allow {
            credentials: InjectedCredentials::empty(),
            claims: CapabilityClaims {
                token_id: "3713c5fc-b569-650c-c780-c64051473370"
                    .parse()
                    .expect("literal token id"),
                agent_id: "agent".parse().expect("literal agent id"),
                session_id: "sess".parse().expect("literal session id"),
                action_set: vec![],
                resource_scope: String::new(),
                issued_at: chrono::Utc::now(),
                expiry: chrono::Utc::now(),
                context_hash: String::new(),
                budget_ceiling: None,
            },
            envelope: Box::new(ExecutionEnvelope::new(
                firma_core::ExecutionIntent {
                    action_class: "filesystem.read".to_string(),
                    resource: firma_core::ExecutionIntent::resource_map_from("example.com"),
                    params: firma_core::ActionParams::Http(firma_core::HttpParams {
                        method: firma_core::HttpMethod::GET,
                        headers: std::collections::HashMap::new(),
                        body: None,
                        query: std::collections::HashMap::new(),
                    }),
                    raw_transport: "https".to_string(),
                    raw_action_ref: "GET /".to_string(),
                },
                "token".to_string(),
                firma_core::ExecutionMetadata {
                    session_id: "sess".parse().expect("literal session id"),
                    agent_id: "agent".parse().expect("literal agent id"),
                    timestamp: chrono::Utc::now(),
                    trace_id: None,
                    budget_consumed: 0.0,
                    risk_score: None,
                },
                None,
            )),
        };

        assert!(decision.is_allow());
        assert!(!decision.is_deny());
        assert!(!decision.is_abort());
        assert!(!decision.is_passthrough());
        assert_eq!(decision.deny_reason(), None);
        assert_eq!(decision.stage(), None);
    }

    #[test]
    fn test_passthrough_helpers() {
        let decision = EnforcementDecision::Passthrough {
            detail: "non-protected host".to_string(),
        };

        assert!(decision.is_passthrough());
        assert!(!decision.is_allow());
        assert!(!decision.is_deny());
        assert!(!decision.is_abort());
        assert_eq!(decision.deny_reason(), None);
        assert_eq!(decision.stage(), None);
    }

    #[test]
    fn test_deny_all_stages() {
        let stages = [
            EnforcementStage::Normalization,
            EnforcementStage::CapabilityValidation(CapabilityValidationStage::TokenSelection),
            EnforcementStage::CapabilityValidation(CapabilityValidationStage::TokenValidation),
            EnforcementStage::ConstraintEnforcement(ConstraintEnforcementStage::ScopeCheck),
            EnforcementStage::ConstraintEnforcement(ConstraintEnforcementStage::BundleFreshness),
            EnforcementStage::ConstraintEnforcement(ConstraintEnforcementStage::PolicyEvaluation),
        ];

        for stage in stages {
            let decision = EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage,
                detail: "test".to_string(),
                envelope: None,
                identity: None,
            };
            assert_eq!(decision.stage(), Some(stage));
        }
    }
}
