//! Enforcement decision types.
//!
//! Every `enforce()` call produces exactly one [`EnforcementDecision`]:
//! ALLOW or DENY. ALLOW carries the verified claims and normalized envelope
//! for downstream use (credential injection, connector dispatch, audit).
//! DENY carries a structured reason, the originating stage, and a detail
//! message for audit and agent error reporting.
//!
//! ABORT is an asynchronous in-flight kill signal emitted by the Authority
//! via `WatchAborts`, not produced by the enforcement pipeline itself.

use firma_core::{CapabilityClaims, DenyReason, ExecutionEnvelope};

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
}

/// Unified result of the enforcement pipeline.
///
/// Every `enforce()` call produces exactly one of these. Carries enough
/// information for the caller to construct the response, emit audit events,
/// and proceed with credential injection on ALLOW.
#[derive(Debug)]
pub enum EnforcementDecision {
    /// Request authorized. Proceed to credential injection + connector.
    Allow {
        claims: CapabilityClaims,
        envelope: ExecutionEnvelope,
    },
    /// Request denied. Return structured denial to agent.
    Deny {
        reason: DenyReason,
        stage: EnforcementStage,
        detail: String,
        envelope: Option<ExecutionEnvelope>,
    },
}

impl EnforcementDecision {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Deny { reason, .. } => Some(*reason),
            Self::Allow { .. } => None,
        }
    }

    #[must_use]
    pub fn stage(&self) -> Option<EnforcementStage> {
        match self {
            Self::Deny { stage, .. } => Some(*stage),
            Self::Allow { .. } => None,
        }
    }
}

#[cfg(test)]
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
}
