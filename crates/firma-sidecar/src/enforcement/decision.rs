use firma_core::{CapabilityClaims, DenyReason, ExecutionEnvelope};

/// Identifies which pipeline stage produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStage {
    /// Intent normalization (pre-Stage-1).
    Normalization,
    /// Token selection from capability map.
    TokenSelection,
    /// Stage 1: token validation.
    Stage1,
    /// Stage 2: Cedar policy evaluation.
    Stage2,
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
            stage: EnforcementStage::Stage1,
            detail: "token has expired".to_string(),
            envelope: None,
        };
        assert!(decision.is_deny());
        assert!(!decision.is_allow());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenExpired));
        assert_eq!(decision.stage(), Some(EnforcementStage::Stage1));
    }
}
