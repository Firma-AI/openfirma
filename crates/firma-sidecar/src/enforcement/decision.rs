//! Enforcement decision types.
//!
//! Every `enforce()` call produces exactly one [`EnforcementDecision`]:
//! the AARM R4 five-decision set — `ALLOW`, `DENY`, `MODIFY`, `STEP_UP`,
//! `DEFER` — plus `ABORT` (post-ALLOW local failure) and `PASSTHROUGH`
//! (non-protected traffic). `ALLOW` carries the verified claims, immutable
//! envelope, and injected credentials for downstream use (connector
//! dispatch, audit). `DENY` carries a structured reason, the originating
//! stage, and a detail message for audit and agent error reporting.
//! `MODIFY`, `STEP_UP`, and `DEFER` are sourced from the `@modify("…")` /
//! `@step_up("…")` / `@defer("…")` Cedar policy annotations and lifted
//! into the corresponding variants.
//!
//! `ABORT` may be produced by the pipeline only for post-ALLOW local
//! failures such as credential injection. Authority-pushed `ABORT` remains
//! out of scope for V1.

use firma_core::{
    AbortReason, CapabilityClaims, DenyReason, ExecutionEnvelope, InjectedCredentials,
    ModificationSpec,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// AARM R4 `MODIFY`: the request is authorized but a transformation must
    /// be applied before dispatch. Carries the same payloads as [`Self::Allow`]
    /// (verified claims, immutable envelope, injected credentials) plus a
    /// [`ModificationSpec`] describing the transformation sourced from the
    /// `@modify("…")` Cedar policy annotation. The connector dispatch path
    /// treats `MODIFY` identically to `ALLOW` for forwarding; the modification
    /// description is recorded in the audit trail so operators can reconcile
    /// the transformed execution against policy intent.
    Modify {
        claims: CapabilityClaims,
        envelope: Box<ExecutionEnvelope>,
        modifications: ModificationSpec,
        credentials: InjectedCredentials,
    },
    /// AARM R4 `STEP_UP`: the request is blocked pending human approval or
    /// stronger authentication. The call does not proceed; the agent should
    /// request approval and retry. Carries the verified identity (when raised
    /// after Stage 1) and the originating normalized envelope for audit.
    /// `claims`/`envelope` are `Option` because `STEP_UP` may also originate
    /// from the local-exec HITL path, which has no capability envelope.
    StepUp {
        claims: Option<CapabilityClaims>,
        envelope: Option<NormalizedEnvelope>,
        challenge: String,
        retry_after_ms: u64,
        identity: Option<DenyIdentity>,
    },
    /// AARM R4 `DEFER`: the request is blocked and should be retried after
    /// `retry_after_ms`, pending additional context or a rate-limit window. The call
    /// does not proceed. Like [`Self::StepUp`], `claims`/`envelope` are
    /// `Option` for audit-only origination paths without a capability.
    Defer {
        claims: Option<CapabilityClaims>,
        envelope: Option<NormalizedEnvelope>,
        retry_after_ms: u64,
        identity: Option<DenyIdentity>,
    },
}

impl EnforcementDecision {
    /// Attaches verified [`DenyIdentity`] to a decision that carries an
    /// identity slot (`Deny`, `Abort`, `StepUp`, `Defer`) so the audit record
    /// carries agent/token attribution. No-op for `Allow`, `Modify`, and
    /// `Passthrough`.
    #[must_use]
    pub fn with_identity(mut self, identity: DenyIdentity) -> Self {
        match &mut self {
            Self::Deny { identity: slot, .. }
            | Self::Abort { identity: slot, .. }
            | Self::StepUp { identity: slot, .. }
            | Self::Defer { identity: slot, .. } => {
                *slot = Some(identity);
            }
            Self::Allow { .. } | Self::Modify { .. } | Self::Passthrough { .. } => {}
        }
        self
    }

    /// Bridge the local-exec HITL pending outcome onto the unified
    /// enforcement decision surface as an AARM R4 `STEP_UP`.
    ///
    /// The local-exec UDS wire format still serializes `pending_hitl`
    /// (so `firma-run` is unchanged), but this constructor lets the
    /// local-exec path project its outcome onto the same audit/wire
    /// vocabulary used by the general enforcement pipeline. `claims` and
    /// `envelope` are `None` because the local-exec path carries no
    /// capability envelope; the approval token (if any) is surfaced as
    /// the `challenge`.
    #[must_use]
    pub fn step_up_pending_hitl(
        approval_token: Option<String>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self::StepUp {
            claims: None,
            envelope: None,
            challenge: approval_token.unwrap_or_default(),
            retry_after_ms: retry_after_ms.unwrap_or(0),
            identity: None,
        }
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

    /// `true` for the AARM R4 `MODIFY` decision.
    #[must_use]
    pub fn is_modify(&self) -> bool {
        matches!(self, Self::Modify { .. })
    }

    /// `true` for the AARM R4 `STEP_UP` decision.
    #[must_use]
    pub fn is_step_up(&self) -> bool {
        matches!(self, Self::StepUp { .. })
    }

    /// `true` for the AARM R4 `DEFER` decision.
    #[must_use]
    pub fn is_defer(&self) -> bool {
        matches!(self, Self::Defer { .. })
    }

    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Deny { reason, .. } => Some(*reason),
            Self::Allow { .. }
            | Self::Abort { .. }
            | Self::Passthrough { .. }
            | Self::Modify { .. }
            | Self::StepUp { .. }
            | Self::Defer { .. } => None,
        }
    }

    #[must_use]
    pub fn stage(&self) -> Option<EnforcementStage> {
        match self {
            Self::Deny { stage, .. } => Some(*stage),
            Self::Allow { .. }
            | Self::Abort { .. }
            | Self::Passthrough { .. }
            | Self::Modify { .. }
            | Self::StepUp { .. }
            | Self::Defer { .. } => None,
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
                token_id: "ctok_01j0000000e008000000000001"
                    .parse()
                    .expect("literal token id"),
                agent_id: "agt_01j0000000e008000000000001"
                    .parse()
                    .expect("literal agent id"),
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
                    agent_id: "agt_01j0000000e008000000000001"
                        .parse()
                        .expect("literal agent id"),
                    timestamp: chrono::Utc::now(),
                    trace_id: None,
                    risk_score: None,
                    thread_id: None,
                    parent_action_id: None,
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

    #[test]
    fn step_up_defer_carry_identity_and_predicate_helpers() {
        let identity = DenyIdentity {
            token_id: "tok".to_string(),
            agent_id: "agent".to_string(),
            context_hash: "ctx".to_string(),
        };

        let step_up = EnforcementDecision::StepUp {
            claims: None,
            envelope: None,
            challenge: "require admin approval".to_string(),
            retry_after_ms: 500,
            identity: None,
        }
        .with_identity(identity.clone());

        assert!(step_up.is_step_up());
        assert!(!step_up.is_allow());
        assert!(!step_up.is_modify());
        assert!(!step_up.is_defer());
        assert_eq!(step_up.deny_reason(), None);
        assert_eq!(step_up.stage(), None);
        match step_up {
            EnforcementDecision::StepUp {
                identity: Some(id), ..
            } => assert_eq!(id, identity),
            _ => panic!("expected StepUp with identity"),
        }

        let defer = EnforcementDecision::Defer {
            claims: None,
            envelope: None,
            retry_after_ms: 1_000,
            identity: Some(identity.clone()),
        };
        assert!(defer.is_defer());
        assert!(!defer.is_step_up());
        match defer {
            EnforcementDecision::Defer {
                identity: Some(id),
                retry_after_ms,
                ..
            } => {
                assert_eq!(id, identity);
                assert_eq!(retry_after_ms, 1_000);
            }
            _ => panic!("expected Defer"),
        }
    }

    #[test]
    fn step_up_pending_hitl_bridge_constructor() {
        let bridged =
            EnforcementDecision::step_up_pending_hitl(Some("tok-42".to_string()), Some(750));
        assert!(bridged.is_step_up());
        match bridged {
            EnforcementDecision::StepUp {
                challenge,
                retry_after_ms,
                claims,
                envelope,
                identity,
            } => {
                assert_eq!(challenge, "tok-42");
                assert_eq!(retry_after_ms, 750);
                assert!(claims.is_none());
                assert!(envelope.is_none());
                assert!(identity.is_none());
            }
            _ => panic!("expected StepUp"),
        }

        // Without an approval token or retry hint the bridge still yields a
        // well-formed STEP_UP with an empty challenge and zero retry.
        let empty = EnforcementDecision::step_up_pending_hitl(None, None);
        assert!(empty.is_step_up());
    }
}
