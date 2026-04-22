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

use firma_core::{CapabilityClaims, DenyReason, ExecutionEnvelope, InjectedCredentials};

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

/// Unified result of the enforcement pipeline.
///
/// Every `enforce()` call produces exactly one of these. Carries enough
/// information for the caller to construct the response, emit audit events,
/// and proceed with credential injection on ALLOW, or forward the request
/// unmodified on PASSTHROUGH.
#[expect(
    dead_code,
    reason = "variant fields consumed by audit/connector once wired"
)]
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
    },
    /// Non-protected traffic. Forward the request without enforcement.
    Passthrough { detail: String },
}

#[expect(dead_code, reason = "public API consumed by interceptor/audit callers")]
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
    pub fn is_passthrough(&self) -> bool {
        matches!(self, Self::Passthrough { .. })
    }

    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Deny { reason, .. } => Some(*reason),
            Self::Allow { .. } | Self::Passthrough { .. } => None,
        }
    }

    #[must_use]
    pub fn stage(&self) -> Option<EnforcementStage> {
        match self {
            Self::Deny { stage, .. } => Some(*stage),
            Self::Allow { .. } | Self::Passthrough { .. } => None,
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
            },
            envelope: Box::new(ExecutionEnvelope::new(
                firma_core::ExecutionIntent {
                    action_class: "filesystem.read".to_string(),
                    resource: "example.com".to_string(),
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
            };
            assert_eq!(decision.stage(), Some(stage));
        }
    }
}
