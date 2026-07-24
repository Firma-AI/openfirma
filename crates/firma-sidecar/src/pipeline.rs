//! Enforcement pipeline orchestrator.
//!
//! Wires the [`IntentNormalizer`],
//! Stage 1 ([`CapabilityValidator`]), and Stage 2 ([`ConstraintEnforcer`])
//! into a single `enforce()` entry point.
//!
//! The pipeline is the ONLY public entry point for enforcement; callers
//! never interact with individual stages directly.
//!
//! Every code path returns ALLOW, DENY, ABORT, or PASSTHROUGH.
//! PASSTHROUGH means the request targets a non-protected host and should
//! be forwarded without enforcement. The pipeline short-circuits on any
//! DENY or PASSTHROUGH.
//!
//! Target: < 3 ms p95 end-to-end overhead (interceptor + Stage 1 +
//! Stage 2 + credential injection + audit emit, excluding connector and
//! external system latency).

use std::time::Duration;

use firma_core::{
    AbortReason, CapabilityClaims, DenyReason, ExecutionEnvelope, ExecutionMetadata,
    InjectedCredentials,
};
use firma_http::Method;

use std::sync::Arc;

use crate::audit::{AuditPayload, Decision};
use crate::authority_client::readiness::ReadinessView;
use crate::config::SidecarMode;
use crate::credential::{CredentialInjectionError, CredentialInjector};
use crate::enforcement::SessionStateStore;
pub use crate::enforcement::capability_map::CapabilityMap;
pub use crate::enforcement::capability_validation::CapabilityValidator;
pub use crate::enforcement::constraint_enforcement::{
    ConstraintEnforcer, PolicyEvaluation, PolicyVerdict,
};
pub use crate::enforcement::decision::EnforcementDecision;
use crate::enforcement::decision::{ConstraintEnforcementStage, DenyIdentity, EnforcementStage};
pub use crate::enforcement::registry::ActionClassRegistry;
use crate::enforcement::session::Outcome;
use crate::normalizer::NormalizedEnvelope;
pub use crate::normalizer::{IntentNormalizer, MappingTable, RawRequest};

/// Default `retry_after_ms` surfaced to the agent for an AARM R4 `STEP_UP`
/// decision raised by the general enforcement pipeline. Mirrors the
/// local-exec default so the agent retry cadence is consistent across both
/// enforcement surfaces.
const STEP_UP_RETRY_AFTER_MS: u64 = 500;

/// Construction arguments for [`EnforcementPipeline`].
///
/// Bundles every component the pipeline needs so the constructor
/// stays readable as new stages (e.g. credential injection) are added.
pub struct PipelineArgs {
    /// Intent normalizer (raw request → canonical envelope).
    pub normalizer: IntentNormalizer,
    /// Stage 1: token selection, parse, verify, expiry, revocation.
    pub capability_validator: CapabilityValidator,
    /// Stage 2: scope check, bundle freshness, Cedar policy eval.
    pub constraint_enforcer: ConstraintEnforcer,
    /// Credential injector called after Stage 2 ALLOW.
    pub credential_injector: Box<dyn CredentialInjector>,
    /// Per-session runtime state store — holds action count and risk score
    /// keyed by `SessionId`.
    pub session_state_store: Arc<dyn SessionStateStore>,
}

/// The enforcement pipeline. Orchestrates the full `enforce()` flow:
///
/// ```text
/// normalize → Stage 1 → Stage 2 → credential injection → assemble envelope
/// ```
///
/// Short-circuits on any DENY or PASSTHROUGH. Every code path returns
/// ALLOW, DENY, ABORT, or PASSTHROUGH.
/// The pipeline is stateless per-request — all shared state is accessed
/// via references injected at construction time.
///
/// Target: < 3ms p95 end-to-end overhead.
pub struct EnforcementPipeline {
    capability_validator: CapabilityValidator,
    constraint_enforcer: ConstraintEnforcer,
    credential_injector: Box<dyn CredentialInjector>,
    normalizer: IntentNormalizer,
    readiness: ReadinessView,
    stage2_timeout: Option<Duration>,
    session_state_store: Arc<dyn SessionStateStore>,
    /// When `Monitor`, DENY decisions are overridden to ALLOW (Passthrough)
    /// and the original deny reason is preserved in the audit record as
    /// `monitor_mode: <reason>`. The pipeline still classifies every call.
    mode: SidecarMode,
}

impl EnforcementPipeline {
    /// Construct the pipeline from [`PipelineArgs`]. Called once at
    /// startup.
    #[must_use]
    pub fn new(args: PipelineArgs) -> Self {
        Self {
            capability_validator: args.capability_validator,
            constraint_enforcer: args.constraint_enforcer,
            credential_injector: args.credential_injector,
            normalizer: args.normalizer,
            readiness: ReadinessView::all_ready(),
            stage2_timeout: None,
            session_state_store: args.session_state_store,
            mode: SidecarMode::Enforce,
        }
    }

    /// Set the enforcement mode. Use [`SidecarMode::Monitor`] for observe-only
    /// operation where DENY decisions are overridden to ALLOW.
    #[must_use]
    pub fn with_mode(mut self, mode: SidecarMode) -> Self {
        self.mode = mode;
        self
    }

    /// Install a readiness view for Authority-backed runtime state.
    #[must_use]
    pub fn with_readiness(mut self, readiness: ReadinessView) -> Self {
        self.readiness = readiness;
        self
    }

    /// Bound Stage 2 evaluation by a timeout.
    ///
    /// Any expiry DENYs with `EnforcementTimeout` to preserve fail-closed
    /// behavior under load.
    #[must_use]
    pub fn with_stage2_timeout(mut self, stage2_timeout: Duration) -> Self {
        self.stage2_timeout = Some(stage2_timeout);
        self
    }

    /// Run the full enforcement pipeline.
    ///
    /// This is the ONLY public entry point for enforcement.
    /// Token is selected internally from the `CapabilityMap` (ADR-002).
    ///
    /// Pipeline stages:
    /// 1. Normalize intent: raw request → `NormalizedEnvelope`
    /// 2. Capability validation: select token, validate → `ValidatedCapability`
    /// 3. Constraint enforcement: scope check + Cedar policy evaluation
    /// 4. Credential injection: fetch credentials for outbound target
    /// 5. On Allow: assemble a fully populated `ExecutionEnvelope` from
    ///    the normalized envelope + validated capability + session context.
    #[must_use]
    pub async fn enforce(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> (EnforcementDecision, AuditPayload) {
        let start = std::time::Instant::now();
        let bundle_version = self.constraint_enforcer.policy_version();

        let decision = self.enforce_inner(request, session_id).await;
        let mut payload = audit_payload_from_decision(
            &decision,
            request,
            session_id,
            start.elapsed(),
            bundle_version.as_deref(),
        );

        // Monitor mode: override DENY / MODIFY / STEP_UP / DEFER → ALLOW
        // (Passthrough) so the call goes through, but preserve the original
        // deny/reason in the audit record so operators can see what
        // enforcement would have blocked or remediated. The AARM R4
        // remediation outcomes are observability-only in monitor mode.
        if self.mode == SidecarMode::Monitor
            && matches!(
                &decision,
                EnforcementDecision::Deny { .. }
                    | EnforcementDecision::Modify { .. }
                    | EnforcementDecision::StepUp { .. }
                    | EnforcementDecision::Defer { .. }
            )
        {
            let original_reason = std::mem::take(&mut payload.deny_reason);
            payload.decision = Decision::Allow;
            payload.deny_reason = format!("monitor_mode: {original_reason}");
            return (
                EnforcementDecision::Passthrough {
                    detail: "monitor_mode".to_string(),
                },
                payload,
            );
        }

        (decision, payload)
    }

    /// Enforcement logic, separated so the outer [`enforce`](Self::enforce)
    /// can unconditionally audit the result.
    #[expect(
        clippy::too_many_lines,
        reason = "the verdict match lifts the AARM R4 five-decision set into EnforcementDecision"
    )]
    async fn enforce_inner(&self, request: &RawRequest, session_id: &str) -> EnforcementDecision {
        if let Err(deny) = self.check_readiness() {
            return deny;
        }

        // Normalize intent (may short-circuit with Deny or Passthrough)
        let normalized = match self.normalizer.normalize(request) {
            Ok(env) => env,
            Err(decision) => return decision,
        };

        // Capability validation: select token → validate
        let capability = match self.capability_validator.enforce(&normalized, session_id) {
            Ok(cap) => cap,
            Err(deny) => return deny,
        };

        // Capture the verified session id and the canonical action/resource
        // now, before `normalized`/`capability.claims` are moved into the
        // decision, so every Stage-2+ return path can record the outcome
        // into the session's prior-action history (AARM R2 G3).
        let verified_sid = capability.claims.session_id.clone();
        let action_class = normalized.intent.action_class.clone();
        let resource = normalized.intent.resource_display();

        // Constraint enforcement: scope check + Cedar policy evaluation.
        //
        // Record this admitted call. Session-scoped; first call is 1.
        // Gate is Stage 1 ALLOW — Stage 1 DENY short-circuits above and
        // must NOT bump the counter.
        let action_count = self
            .session_state_store
            .record_action(&capability.claims.session_id);
        let mut signals = self
            .session_state_store
            .signals(&capability.claims.session_id);
        // `record_action` already incremented the counter — ensure Cedar
        // sees the up-to-date value even if a concurrent writer raced
        // between `record_action` and `signals` (the LRU mutex is taken
        // twice; the second read could observe a later increment).
        signals.action_count = action_count;
        let stage2_result = match self.stage2_timeout {
            Some(timeout) => {
                self.constraint_enforcer
                    .evaluate_with_timeout(&normalized, &capability.claims, &signals, timeout)
                    .await
            }
            None => self
                .constraint_enforcer
                .evaluate(&normalized, &capability.claims, &signals),
        };
        let verdict = match stage2_result {
            Ok(verdict) => verdict,
            Err(deny) => {
                // Stage 2 runs after capability validation, so the verified
                // identity is known. Attach it so the audit record is
                // attributable and `firma monitor --agent <id>` keeps the
                // deny (FIR-208).
                self.session_state_store.record_outcome(
                    &verified_sid,
                    &action_class,
                    &resource,
                    Outcome::Deny,
                );
                return deny.with_identity(DenyIdentity::from_claims(&capability.claims));
            }
        };

        // Record the policy verdict's outcome into the session's prior-action
        // history (AARM R2 G3) in a single call, before dispatching the
        // verdict match. This records the *policy* outcome; a post-enforcement
        // failure (credential injection ABORT) does not override it — the
        // audit event captures ABORT separately, and the session history
        // reflects what the policy layer decided.
        let policy_outcome = match &verdict {
            PolicyVerdict::Allow => Outcome::Allow,
            PolicyVerdict::Modify { .. } => Outcome::Modify,
            PolicyVerdict::Deny => Outcome::Deny,
            PolicyVerdict::StepUp { .. } => Outcome::StepUp,
            PolicyVerdict::Defer { .. } => Outcome::Defer,
        };
        self.session_state_store.record_outcome(
            &verified_sid,
            &action_class,
            &resource,
            policy_outcome,
        );

        // AARM R4 remediation outcomes that do NOT dispatch return the
        // normalized envelope + verified claims for audit, with the
        // verified identity attached. `PolicyVerdict::Deny` is converted to
        // `Err` by the enforcer, so it only reaches this `Ok` path
        // defensively; fail closed if it ever does.
        let modifications = match verdict {
            PolicyVerdict::StepUp { challenge } => {
                let identity = DenyIdentity::from_claims(&capability.claims);
                return EnforcementDecision::StepUp {
                    claims: Some(capability.claims),
                    envelope: Some(normalized),
                    challenge: challenge.to_string(),
                    retry_after_ms: STEP_UP_RETRY_AFTER_MS,
                    identity: Some(identity),
                };
            }
            PolicyVerdict::Defer { backoff } => {
                let identity = DenyIdentity::from_claims(&capability.claims);
                let retry_after_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
                return EnforcementDecision::Defer {
                    claims: Some(capability.claims),
                    envelope: Some(normalized),
                    retry_after_ms,
                    identity: Some(identity),
                };
            }
            PolicyVerdict::Deny => {
                let identity = DenyIdentity::from_claims(&capability.claims);
                return EnforcementDecision::Deny {
                    reason: DenyReason::PolicyDenied,
                    stage: EnforcementStage::ConstraintEnforcement(
                        ConstraintEnforcementStage::PolicyEvaluation,
                    ),
                    detail: format!(
                        "policy denied action '{}' on resource '{}'",
                        normalized.intent.action_class,
                        normalized.intent.resource_display()
                    ),
                    envelope: Some(normalized),
                    identity: Some(identity),
                };
            }
            PolicyVerdict::Allow => None,
            PolicyVerdict::Modify { modifications } => Some(modifications),
        };

        // All stages passed (Allow or Modify) — assemble the fully populated
        // envelope. Use the session_id from the verified token claims, NOT
        // the caller-supplied header value. This prevents session spoofing
        // where an attacker sets a victim's session_id in the header to
        // manipulate audit logs and metadata.
        let session_id_typed = capability.claims.session_id.clone();
        // AARM R2 G2: capture the parent action id (the prior admitted
        // action's provenance anchor) BEFORE advancing the chain, so the
        // current envelope links to its predecessor.
        let parent_action_id = signals.last_provenance.clone();
        // AARM R2 G2: derive a stable thread id from the session id.
        // V1 maps one session → one thread; a future version may split
        // sessions into multiple threads based on intent metadata.
        let thread_id = derive_thread_id(&session_id_typed);
        // Advance the session's tamper-evident provenance chain and anchor
        // this admitted action to the session's prior calls. The chain links
        // only admitted (Allow/Modify) actions; denied/deferred actions are
        // recorded in the G3 prior-action history instead.
        let provenance = self.session_state_store.advance_provenance(
            &verified_sid,
            &capability.claims.context_hash,
            &action_class,
            &resource,
        );
        let provenance = if provenance.is_empty() {
            None
        } else {
            Some(provenance)
        };
        let envelope = ExecutionEnvelope::new(
            normalized.intent,
            capability.raw_token,
            ExecutionMetadata {
                session_id: session_id_typed,
                agent_id: capability.claims.agent_id,
                timestamp: normalized.timestamp,
                trace_id: None,
                risk_score: if signals.risk_score == 0.0 {
                    None
                } else {
                    Some(signals.risk_score)
                },
                thread_id: Some(thread_id),
                parent_action_id,
            },
            provenance,
        );

        // Credential injection: fetch credentials for the outbound
        // target. connector_id is the host portion of the resource.
        let resource_display = envelope.intent().resource_display();
        let connector_id = extract_host(&resource_display);
        let target = resource_display.as_str();
        let credentials = match self
            .credential_injector
            .inject(&envelope, connector_id, target)
            .await
        {
            Ok(creds) => creds,
            // No credentials configured for this connector — proceed
            // with empty headers (passthrough behavior).
            Err(CredentialInjectionError::UnknownConnector { .. }) => InjectedCredentials::empty(),
            // Credential fetch failed after enforcement allowed the call.
            Err(CredentialInjectionError::FetchFailed {
                connector_id,
                reason,
            }) => {
                // The policy outcome (Allow/Modify) was already recorded
                // above; the credential-injection ABORT is a post-
                // enforcement operational failure captured in the audit
                // event, not in the session prior-action history.
                return EnforcementDecision::Abort {
                    reason: AbortReason::CredentialInjectionFailed,
                    detail: format!("connector {connector_id}: {reason}"),
                    identity: Some(DenyIdentity::from_claims(&capability.claims)),
                };
            }
        };

        // The policy outcome (Allow/Modify) was already recorded into the
        // session prior-action history before the verdict match above.

        match modifications {
            Some(modifications) => EnforcementDecision::Modify {
                claims: capability.claims,
                envelope: Box::new(envelope),
                modifications,
                credentials,
            },
            None => EnforcementDecision::Allow {
                claims: capability.claims,
                envelope: Box::new(envelope),
                credentials,
            },
        }
    }

    /// Readiness gate. Denies every call until the Authority streams
    /// have hydrated both the policy bundle and the revocation cache,
    /// so in-flight traffic never bypasses state that the Authority
    /// has not yet shipped.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    fn check_readiness(&self) -> Result<(), EnforcementDecision> {
        let readiness = self.readiness.snapshot();
        if !readiness.policy_bundle_ready {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleNotReady,
                stage: EnforcementStage::ConstraintEnforcement(
                    crate::enforcement::decision::ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle has not been loaded".to_string(),
                envelope: None,
                identity: None,
            });
        }
        if !readiness.revocation_ready {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::RevocationCacheNotReady,
                stage: EnforcementStage::CapabilityValidation(
                    crate::enforcement::decision::CapabilityValidationStage::TokenValidation,
                ),
                detail: "revocation cache has not completed initial sync".to_string(),
                envelope: None,
                identity: None,
            });
        }
        Ok(())
    }
}

/// Extracts an [`AuditPayload`] from an [`EnforcementDecision`].
///
/// This is a pure data extraction — no cryptography, no I/O. Designed
/// to run on the enforcement hot path with < 1µs overhead.
///
/// `bundle_version` should be the version of the policy bundle that was
/// active when enforcement ran. Pass `None` when the bundle version is
/// unknown (e.g. in tests that do not wire a real `ConstraintEnforcer`).
#[must_use]
pub fn audit_payload_from_decision(
    decision: &EnforcementDecision,
    request: &RawRequest,
    session_id: &str,
    enforcement_latency: Duration,
    bundle_version: Option<&str>,
) -> AuditPayload {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "duration micros fits i64 for any realistic enforcement latency"
    )]
    let enforcement_latency_us = enforcement_latency.as_micros() as i64;
    let fields = audit_decision_fields(decision, request, bundle_version);

    let session_id_for_audit = match decision {
        EnforcementDecision::Allow { envelope, .. }
        | EnforcementDecision::Modify { envelope, .. } => {
            envelope.metadata().session_id.as_ref().to_string()
        }
        EnforcementDecision::Deny { .. }
        | EnforcementDecision::Abort { .. }
        | EnforcementDecision::Passthrough { .. }
        | EnforcementDecision::StepUp { .. }
        | EnforcementDecision::Defer { .. } => session_id.to_string(),
    };

    AuditPayload {
        session_id: session_id_for_audit,
        token_id: fields.token_id,
        agent_id: fields.agent_id,
        action: fields.action,
        resource: fields.resource,
        decision: fields.decision_code,
        deny_reason: fields.deny_reason,
        enforcement_latency_us,
        context_hash: fields.context_hash,
        bundle_version: fields.bundle_version,
        dispatch_status: 0,
        dispatch_latency_us: 0,
        response_size: 0,
        provenance: fields.provenance,
        thread_id: fields.thread_id,
        parent_action_id: fields.parent_action_id,
    }
}

struct AuditDecisionFields {
    token_id: String,
    agent_id: String,
    action: String,
    resource: String,
    decision_code: Decision,
    deny_reason: String,
    context_hash: String,
    bundle_version: String,
    provenance: String,
    thread_id: String,
    parent_action_id: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "exhaustive match over the AARM R4 five-decision EnforcementDecision"
)]
fn audit_decision_fields(
    decision: &EnforcementDecision,
    request: &RawRequest,
    bundle_version: Option<&str>,
) -> AuditDecisionFields {
    match decision {
        EnforcementDecision::Allow {
            claims, envelope, ..
        } => AuditDecisionFields {
            token_id: claims.token_id.to_string(),
            agent_id: claims.agent_id.to_string(),
            action: envelope.intent().action_class.clone(),
            resource: redact_sensitive_query_params(&envelope.intent().resource_display()),
            decision_code: Decision::Allow,
            deny_reason: String::new(),
            context_hash: claims.context_hash.clone(),
            bundle_version: bundle_version.unwrap_or("").to_string(),
            provenance: envelope.provenance().unwrap_or("").to_string(),
            thread_id: envelope
                .metadata()
                .thread_id
                .as_deref()
                .unwrap_or("")
                .to_string(),
            parent_action_id: envelope
                .metadata()
                .parent_action_id
                .as_deref()
                .unwrap_or("")
                .to_string(),
        },
        EnforcementDecision::Deny {
            reason,
            detail,
            envelope,
            identity,
            ..
        } => {
            let (action, resource) = envelope.as_ref().map_or_else(
                || {
                    (
                        raw_request_action_label(request),
                        redact_sensitive_query_params(&raw_request_resource_display(request)),
                    )
                },
                |e| {
                    (
                        e.intent.action_class.clone(),
                        redact_sensitive_query_params(&e.intent.resource_display()),
                    )
                },
            );

            // Carry the verified agent/token attribution when the denial
            // was raised after capability validation; pre-validation
            // denials have no known identity (FIR-208).
            let (token_id, agent_id, context_hash) = deny_identity_fields(identity.as_ref());

            AuditDecisionFields {
                token_id,
                agent_id,
                action,
                resource,
                decision_code: Decision::Deny,
                deny_reason: sanitize_audit_reason(&format!("{reason}: {detail}")),
                context_hash,
                bundle_version: String::new(),
                provenance: String::new(),
                thread_id: String::new(),
                parent_action_id: String::new(),
            }
        }
        EnforcementDecision::Abort {
            reason,
            detail,
            identity,
        } => {
            let (token_id, agent_id, context_hash) = deny_identity_fields(identity.as_ref());
            AuditDecisionFields {
                token_id,
                agent_id,
                action: raw_request_action_label(request),
                resource: redact_sensitive_query_params(&raw_request_resource_display(request)),
                decision_code: Decision::Abort,
                deny_reason: sanitize_audit_reason(&format!("{}: {detail}", reason.code())),
                context_hash,
                bundle_version: String::new(),
                provenance: String::new(),
                thread_id: String::new(),
                parent_action_id: String::new(),
            }
        }
        EnforcementDecision::Passthrough { .. } => AuditDecisionFields {
            token_id: String::new(),
            agent_id: String::new(),
            action: raw_request_action_label(request),
            resource: redact_sensitive_query_params(&raw_request_resource_display(request)),
            decision_code: Decision::Allow,
            deny_reason: String::new(),
            context_hash: String::new(),
            bundle_version: String::new(),
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        },
        EnforcementDecision::Modify {
            claims,
            envelope,
            modifications,
            ..
        } => AuditDecisionFields {
            token_id: claims.token_id.to_string(),
            agent_id: claims.agent_id.to_string(),
            action: envelope.intent().action_class.clone(),
            resource: redact_sensitive_query_params(&envelope.intent().resource_display()),
            decision_code: Decision::Modify,
            // Surface the applied transformation in the reason field so
            // operators can reconcile the transformed execution against policy
            // intent (no dedicated modification column exists yet).
            deny_reason: sanitize_audit_reason(&modifications.to_string()),
            context_hash: claims.context_hash.clone(),
            bundle_version: bundle_version.unwrap_or("").to_string(),
            provenance: envelope.provenance().unwrap_or("").to_string(),
            thread_id: envelope
                .metadata()
                .thread_id
                .as_deref()
                .unwrap_or("")
                .to_string(),
            parent_action_id: envelope
                .metadata()
                .parent_action_id
                .as_deref()
                .unwrap_or("")
                .to_string(),
        },
        EnforcementDecision::StepUp {
            claims,
            envelope,
            challenge,
            retry_after_ms,
            identity,
        } => {
            let (action, resource) = remediation_action_resource(envelope.as_ref(), request);
            let (token_id, agent_id, context_hash) =
                identity_or_claims_fields(identity.as_ref(), claims.as_ref());
            AuditDecisionFields {
                token_id,
                agent_id,
                action,
                resource,
                decision_code: Decision::StepUp,
                deny_reason: sanitize_audit_reason(&format!(
                    "{}: {challenge}; retry_after_ms: {retry_after_ms}",
                    DenyReason::StepUpRequired
                )),
                context_hash,
                bundle_version: String::new(),
                provenance: String::new(),
                thread_id: String::new(),
                parent_action_id: String::new(),
            }
        }
        EnforcementDecision::Defer {
            claims,
            envelope,
            retry_after_ms,
            identity,
        } => {
            let (action, resource) = remediation_action_resource(envelope.as_ref(), request);
            let (token_id, agent_id, context_hash) =
                identity_or_claims_fields(identity.as_ref(), claims.as_ref());
            AuditDecisionFields {
                token_id,
                agent_id,
                action,
                resource,
                decision_code: Decision::Defer,
                deny_reason: sanitize_audit_reason(&format!(
                    "{}: retry_after_ms: {retry_after_ms}",
                    DenyReason::Deferred
                )),
                context_hash,
                bundle_version: String::new(),
                provenance: String::new(),
                thread_id: String::new(),
                parent_action_id: String::new(),
            }
        }
    }
}

/// Resolve `(action, resource)` for a remediation decision (`StepUp`/`Defer`)
/// from the carried normalized envelope, falling back to the raw request
/// label/display when no envelope is attached (e.g. the local-exec HITL
/// bridge path carries `None`).
fn remediation_action_resource(
    envelope: Option<&NormalizedEnvelope>,
    request: &RawRequest,
) -> (String, String) {
    envelope.map_or_else(
        || {
            (
                raw_request_action_label(request),
                redact_sensitive_query_params(&raw_request_resource_display(request)),
            )
        },
        |e| {
            (
                e.intent.action_class.clone(),
                redact_sensitive_query_params(&e.intent.resource_display()),
            )
        },
    )
}

/// Resolve `(token_id, agent_id, context_hash)` for a remediation decision
/// (`StepUp`/`Defer`): prefer the verified [`DenyIdentity`], fall back to the
/// carried [`CapabilityClaims`], and default to empty strings when neither is
/// present (pre-validation / local-exec bridge origination).
fn identity_or_claims_fields(
    identity: Option<&DenyIdentity>,
    claims: Option<&CapabilityClaims>,
) -> (String, String, String) {
    if let Some(id) = identity {
        return (
            id.token_id.clone(),
            id.agent_id.clone(),
            id.context_hash.clone(),
        );
    }
    if let Some(claims) = claims {
        return (
            claims.token_id.to_string(),
            claims.agent_id.to_string(),
            claims.context_hash.clone(),
        );
    }
    (String::new(), String::new(), String::new())
}

/// Destructures the optional [`DenyIdentity`] into the
/// `(token_id, agent_id, context_hash)` audit fields, defaulting to
/// empty strings for pre-validation denials with no known identity.
fn deny_identity_fields(identity: Option<&DenyIdentity>) -> (String, String, String) {
    identity.map_or_else(
        || (String::new(), String::new(), String::new()),
        |id| {
            (
                id.token_id.clone(),
                id.agent_id.clone(),
                id.context_hash.clone(),
            )
        },
    )
}

fn raw_request_action_label(request: &RawRequest) -> String {
    if request.method == Method::CONNECT {
        "network.connect".to_string()
    } else {
        format!("raw.http.{}", request.method)
    }
}

/// Known sensitive query parameter names that must be redacted in audit output.
/// Covers common API key, secret, password, and token parameter names.
const SENSITIVE_QUERY_PARAMS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "auth",
    "bearer",
    "authorization",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "access_token",
    "access-token",
];

/// Redacts sensitive query parameter values from audit strings as a
/// defense-in-depth guardrail. Applied to `deny_reason` and audit
/// resource paths before emission to prevent credential leaks.
/// Preserves the query structure (param names visible) but replaces
/// any values for known sensitive parameters with `[REDACTED]`.
fn redact_sensitive_query_params(s: &str) -> String {
    let mut result = s.to_string();
    for param in SENSITIVE_QUERY_PARAMS {
        let pattern = format!("{param}=");
        let mut start = 0;
        while let Some(pos) = result[start..].find(&pattern) {
            let abs = start + pos;
            let val_start = abs + pattern.len();
            let val_end = result[val_start..]
                .find('&')
                .map_or(result.len(), |i| val_start + i);
            result.replace_range(val_start..val_end, "[REDACTED]");
            start = abs + 1;
        }
    }
    result
}

/// Redacts URL query string fragments from audit reason strings as a
/// defense-in-depth guardrail. Applied to `deny_reason` before audit
/// emission to catch any residual credential leaks from error messages
/// that may have escaped earlier sanitization.
fn sanitize_audit_reason(reason: &str) -> String {
    redact_sensitive_query_params(reason)
}

fn raw_request_resource_display(request: &RawRequest) -> String {
    format!("{}{}", request.host, request.path)
}

/// Extracts the host portion from a resource string.
///
/// Resource format is `host/path` (no scheme). Returns the host part
/// before the first `/`, or the entire string if no `/` is present.
fn extract_host(resource: &str) -> &str {
    resource.split('/').next().unwrap_or(resource)
}

/// Derive a stable thread id from the session id (AARM R2 G2).
///
/// V1 maps one session to one thread; the thread id is a deterministic
/// hex hash of the session id so it is stable across restarts and
/// independent of the session-state backend. A future version may split
/// sessions into multiple threads based on intent metadata.
#[must_use]
fn derive_thread_id(session_id: &firma_core::SessionId) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"firma:thread:");
    hasher.update(session_id.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Decision;
    use crate::config::{MappingRuleConfig, MappingRulesFile, TenancyMode};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::enforcement::registry::ActionClassRegistry;
    use crate::normalizer::MappingTable;
    use chrono::Utc;
    use firma_core::*;
    use firma_http::HeaderName;
    use std::collections::HashMap;
    use std::time::Duration;

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    struct MockVerifier {
        claims: CapabilityClaims,
    }
    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Ok(self.claims.clone())
        }
    }

    struct NoRevocations;
    impl RevocationStore for NoRevocations {
        fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &TokenId) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001"
                .parse()
                .expect("literal token id"),
            agent_id: "agt_01j0000000e008000000000001"
                .parse()
                .expect("literal agent id"),
            session_id: "sess_001".parse().expect("literal session id"),
            action_set: vec![
                "communication.external.send".to_string(),
                "filesystem.read".to_string(),
            ],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_mapping_table(rules: &[MappingRuleConfig]) -> MappingTable {
        test_mapping_table_with_protection(rules, true)
    }

    fn test_mapping_table_with_protection(
        rules: &[MappingRuleConfig],
        default_protected: bool,
    ) -> MappingTable {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: rules.to_vec(),
        };
        MappingTable::from_config(&file, &registry, default_protected)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn default_rules() -> Vec<MappingRuleConfig> {
        vec![
            MappingRuleConfig {
                method: Some(Method::POST),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            },
            MappingRuleConfig {
                method: Some(Method::GET),
                host: "*".to_string(),
                path: None,
                action_class: "filesystem.read".to_string(),
            },
        ]
    }

    fn test_pipeline() -> EnforcementPipeline {
        test_pipeline_with_session_store(std::sync::Arc::new(
            crate::enforcement::LruSessionStateStore::new(16),
        ))
    }

    fn test_pipeline_with_session_store(
        store: std::sync::Arc<dyn crate::enforcement::SessionStateStore>,
    ) -> EnforcementPipeline {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: store,
        })
    }

    /// Build a pipeline where Stage 1 denies every request: the
    /// `CapabilityMap` is empty, so token selection fails before any
    /// runtime-state bookkeeping.
    fn test_pipeline_stage1_denies_with_session_store(
        store: std::sync::Arc<dyn crate::enforcement::SessionStateStore>,
    ) -> EnforcementPipeline {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]), // empty — Stage 1 DENY
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: store,
        })
    }

    fn test_request(method: Method, host_and_path: &str) -> RawRequest {
        let (host, path) = host_and_path.split_once('/').map_or_else(
            || (host_and_path.to_string(), "/".to_string()),
            |(h, p)| (h.to_string(), format!("/{p}")),
        );
        RawRequest {
            method,
            host,
            path,
            headers: HashMap::new(),
            body: None,
            is_https: true,
        }
    }

    #[tokio::test]
    async fn test_enforce_happy_path() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow {
            claims, envelope, ..
        } = decision
        {
            assert_eq!(
                claims.agent_id.to_string(),
                "agt_01j0000000e008000000000001"
            );
            assert_eq!(
                envelope.metadata().agent_id.to_string(),
                "agt_01j0000000e008000000000001"
            );
            assert_eq!(envelope.metadata().session_id.as_ref(), "sess_001");
            assert!(
                !envelope.capability().is_empty(),
                "capability must be populated on Allow"
            );
            assert_eq!(
                envelope.intent().action_class,
                "communication.external.send"
            );
        }
    }

    #[tokio::test]
    async fn test_enforce_denies_before_authority_readiness() {
        let (flag, readiness) = crate::authority_client::readiness::ReadinessFlag::new(
            crate::authority_client::readiness::ReadinessState::default(),
        );
        let pipeline = test_pipeline().with_readiness(readiness);
        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::PolicyBundleNotReady)
        );

        flag.set_policy_bundle_ready(true);
        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::RevocationCacheNotReady)
        );
    }

    #[tokio::test]
    async fn test_enforce_unclassified_intent() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: Method::DELETE,
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
    }

    #[tokio::test]
    async fn test_enforce_not_protected_returns_passthrough() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table_with_protection(&rules, false));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::GET,
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(
            decision.is_passthrough(),
            "non-protected traffic should passthrough, not deny"
        );
        assert!(!decision.is_deny());
        assert!(!decision.is_allow());
    }

    #[tokio::test]
    async fn test_enforce_scope_violation() {
        struct DenyDeletePolicy;
        impl PolicyEvaluation for DenyDeletePolicy {
            fn evaluate(
                &self,
                _: &AgentId,
                action: &str,
                _: &str,
                _: serde_json::Value,
            ) -> Result<bool, String> {
                Ok(action != "filesystem.delete")
            }
            fn is_fresh(&self) -> bool {
                true
            }
            fn version(&self) -> Option<String> {
                Some("test".to_string())
            }
        }

        let rules = vec![MappingRuleConfig {
            method: Some(Method::DELETE),
            host: "api.example.com".to_string(),
            path: Some("/data".to_string()),
            action_class: "filesystem.delete".to_string(),
        }];

        let mut wide_claims = test_claims();
        wide_claims.action_set = vec!["*".to_string()];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.narrow".to_string(),
                claims: wide_claims.clone(),
            }]),
            Arc::new(MockVerifier {
                claims: wide_claims,
            }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(DenyDeletePolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::DELETE,
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[tokio::test]
    async fn test_stage2_policy_deny_audit_carries_validated_identity() {
        // Regression (FIR-208): a Stage-2 Cedar policy DENY happens AFTER
        // capability validation, so the agent/token identity is known.
        // The audit payload MUST carry it — otherwise `firma monitor
        // --agent <id>` filters every deny out and the operator sees only
        // allows, exactly the gap reported during 0.1.0 pre-release.
        struct DenyAllPolicy;
        impl PolicyEvaluation for DenyAllPolicy {
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
                Some("test".to_string())
            }
        }

        let claims = test_claims();
        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier {
                claims: claims.clone(),
            }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(DenyAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(
            payload.agent_id,
            claims.agent_id.to_string(),
            "deny audit must carry the validated agent_id"
        );
        assert_eq!(
            payload.token_id,
            claims.token_id.to_string(),
            "deny audit must carry the validated token_id"
        );
        assert_eq!(
            payload.context_hash, claims.context_hash,
            "deny audit must carry the validated context_hash"
        );
    }

    // ===== Fail-closed discipline tests =====

    #[tokio::test]
    async fn test_enforce_validation_failure_short_circuits_enforcement() {
        struct RejectingVerifier;
        impl TokenVerifier for RejectingVerifier {
            fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
                Err(TokenError::SignatureInvalid {
                    reason: "forged".to_string(),
                })
            }
        }

        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.bad".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(RejectingVerifier),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
        assert_eq!(
            decision.stage(),
            Some(
                crate::enforcement::decision::EnforcementStage::CapabilityValidation(
                    crate::enforcement::decision::CapabilityValidationStage::TokenValidation,
                )
            )
        );
    }

    #[tokio::test]
    async fn test_enforce_no_capability_token_denies() {
        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]), // empty!
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    // ===== Determinism test =====

    #[tokio::test]
    async fn test_enforce_deterministic_same_input_same_output() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        for _ in 0..100 {
            let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
            assert!(
                decision.is_allow(),
                "non-deterministic: got DENY on repeated call"
            );
        }
    }

    #[tokio::test]
    async fn test_enforce_deterministic_deny_same_input() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: Method::DELETE,
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        for _ in 0..100 {
            let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
            assert!(decision.is_deny());
            assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
        }
    }

    // ===== Policy bundle staleness =====

    #[tokio::test]
    async fn test_enforce_allow_envelope_fields_complete() {
        let pipeline = test_pipeline();
        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{\"model\":\"gpt-4\"}".to_vec()),
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow {
            claims, envelope, ..
        } = decision
        {
            // Verify intent fields
            assert_eq!(
                envelope.intent().action_class,
                "communication.external.send"
            );
            assert_eq!(
                envelope.intent().resource_display(),
                "api.openai.com/v1/chat/completions"
            );
            assert_eq!(envelope.intent().raw_transport, "https");
            assert_eq!(
                envelope.intent().raw_action_ref,
                "POST /v1/chat/completions"
            );

            // Verify metadata fields
            assert_eq!(envelope.metadata().session_id.as_ref(), "sess_001");
            assert_eq!(
                envelope.metadata().agent_id.to_string(),
                "agt_01j0000000e008000000000001"
            );
            assert!(envelope.metadata().trace_id.is_none());
            assert!(envelope.metadata().risk_score.is_none());

            // AARM R2 G2: provenance is populated for admitted (Allow) calls as a
            // tamper-evident chain anchor (hex SHA256 of prev || context_hash ||
            // action || resource). First call in the session chains from empty.
            let provenance = envelope
                .provenance()
                .expect("admitted call must carry a provenance chain anchor");
            assert!(
                !provenance.is_empty(),
                "provenance must be a non-empty hex hash"
            );

            // Verify capability token is populated
            assert!(!envelope.capability().is_empty());

            // Verify claims match
            assert_eq!(
                claims.token_id.to_string(),
                "ctok_01j0000000e008000000000001"
            );
            assert_eq!(
                claims.agent_id.to_string(),
                "agt_01j0000000e008000000000001"
            );
        }
    }

    #[tokio::test]
    async fn test_enforce_revoked_token_denied_through_pipeline() {
        struct RevokedStore;
        impl firma_core::RevocationStore for RevokedStore {
            fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, firma_core::TokenError> {
                Ok(true)
            }
            fn add_revocation(&self, _token_id: &TokenId) -> Result<(), firma_core::TokenError> {
                Ok(())
            }
        }

        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(RevokedStore),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenRevoked));
    }

    #[tokio::test]
    async fn test_enforce_expired_token_denied_through_pipeline() {
        let mut claims = test_claims();
        claims.expiry = Utc::now() - chrono::Duration::hours(1);

        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenExpired));
    }

    #[tokio::test]
    async fn test_enforce_scope_violation_through_pipeline() {
        // Token only allows communication.external.send, but request maps to filesystem.read
        let mut claims = test_claims();
        claims.action_set = vec!["communication.external.send".to_string()]; // no filesystem.read

        let rules = vec![MappingRuleConfig {
            method: Some(Method::GET),
            host: "api.example.com".to_string(),
            path: None,
            action_class: "filesystem.read".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::GET,
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        // Token selection fails because no token covers filesystem.read
        assert!(decision.is_deny());
    }

    #[tokio::test]
    async fn test_enforce_sensitive_headers_stripped_in_allow() {
        let pipeline = test_pipeline();
        let mut headers = HashMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            "Bearer secret".to_string(),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            "application/json".to_string(),
        );

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_allow());

        if let EnforcementDecision::Allow { envelope, .. } = decision
            && let firma_core::ActionParams::Http(ref params) = envelope.intent().params
        {
            assert!(
                !params
                    .headers
                    .contains_key(&HeaderName::from_static("authorization")),
                "authorization header must not leak into envelope"
            );
            assert!(
                params
                    .headers
                    .contains_key(&HeaderName::from_static("content-type"))
            );
        }
    }

    #[tokio::test]
    async fn test_enforce_stale_bundle_denies() {
        struct StalePolicy;
        impl PolicyEvaluation for StalePolicy {
            fn evaluate(
                &self,
                _: &AgentId,
                _: &str,
                _: &str,
                _: serde_json::Value,
            ) -> Result<bool, String> {
                Ok(true)
            }
            fn is_fresh(&self) -> bool {
                false
            }
            fn version(&self) -> Option<String> {
                None
            }
        }

        let claims = test_claims();
        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];

        let normalizer = IntentNormalizer::new(test_mapping_table(&rules));

        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );

        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(StalePolicy));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_001").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    // ===== Audit event emission tests =====

    #[tokio::test]
    async fn test_enforce_allow_emits_audit_event() {
        let mut claims = test_claims();
        claims.session_id = "sess_audit".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_audit").await;
        assert!(decision.is_allow());

        assert_eq!(payload.session_id, "sess_audit");
        assert_eq!(payload.decision, Decision::Allow);
        assert_eq!(payload.token_id, "ctok_01j0000000e008000000000001");
        assert_eq!(payload.agent_id, "agt_01j0000000e008000000000001");
        assert_eq!(payload.action, "communication.external.send");
        assert!(payload.enforcement_latency_us >= 0);
        assert_eq!(
            payload.bundle_version, "test-v1",
            "bundle_version must be populated from ConstraintEnforcer in Allow audit events"
        );
    }

    #[tokio::test]
    async fn test_enforce_deny_emits_audit_event() {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_deny").await;
        assert!(decision.is_deny());

        assert_eq!(payload.session_id, "sess_deny");
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(payload.action, "raw.http.POST");
        assert_eq!(payload.resource, "api.openai.com/v1/chat/completions");
    }

    #[tokio::test]
    async fn test_enforce_passthrough_emits_audit_event() {
        let claims = test_claims();

        let rules = vec![MappingRuleConfig {
            method: Some(Method::POST),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }];
        let normalizer = IntentNormalizer::new(test_mapping_table_with_protection(&rules, false));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::GET,
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_pt").await;
        assert!(decision.is_passthrough());

        assert_eq!(payload.session_id, "sess_pt");
        assert_eq!(payload.decision, Decision::Allow); // Passthrough maps to ALLOW
        assert_eq!(payload.action, "raw.http.GET");
        assert_eq!(payload.resource, "not-protected.example.com/any");
    }

    #[tokio::test]
    async fn test_enforce_normalization_deny_emits_audit_event() {
        let claims = test_claims();

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));
        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        // Unclassified intent — denied at normalization stage
        let request = RawRequest {
            method: Method::DELETE,
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_norm").await;
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));

        assert_eq!(payload.session_id, "sess_norm");
        assert_eq!(payload.decision, Decision::Deny);
    }

    // ===== Credential injection tests =====

    #[tokio::test]
    async fn test_enforce_credential_injection_success() {
        let mut claims = test_claims();
        claims.session_id = "sess_cred".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        // BasicCredentialInjector with credentials for api.openai.com
        let injector =
            crate::credential::provider::BasicCredentialInjector::new(HashMap::from([(
                "api.openai.com".to_string(),
                HashMap::from([(
                    HeaderName::from_static("authorization"),
                    "Bearer sk_test".to_string(),
                )]),
            )]));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, _payload) = pipeline.enforce(&request, "sess_cred").await;
        assert!(
            decision.is_allow(),
            "credential injection should not block Allow"
        );
    }

    #[tokio::test]
    async fn test_enforce_credential_injection_unknown_connector_allows() {
        let mut claims = test_claims();
        claims.session_id = "sess_cred".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        // Empty injector — no connectors configured
        let injector = crate::credential::provider::BasicCredentialInjector::empty();

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        // UnknownConnector should be treated as passthrough (empty creds)
        let (decision, _payload) = pipeline.enforce(&request, "sess_cred").await;
        assert!(
            decision.is_allow(),
            "unknown connector should still Allow with empty credentials"
        );
    }

    #[tokio::test]
    async fn test_enforce_credential_injection_fetch_failed_aborts() {
        let mut claims = test_claims();
        claims.session_id = "sess_fail".parse().expect("literal sid");

        let normalizer = IntentNormalizer::new(test_mapping_table(&default_rules()));
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        // Vault injector with nonexistent secret file — triggers FetchFailed
        let injector =
            crate::credential::provider::VaultCredentialInjector::new(HashMap::from([(
                "api.openai.com".to_string(),
                vec![crate::credential::provider::VaultSecretEntry {
                    header_name: HeaderName::from_static("authorization"),
                    value_prefix: Some("Bearer ".to_string()),
                    value_transform: None,
                    secret_path: std::path::PathBuf::from("/nonexistent/secret"),
                }],
            )]));

        let pipeline = EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(injector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        });

        let request = RawRequest {
            method: Method::POST,
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let (decision, payload) = pipeline.enforce(&request, "sess_fail").await;
        assert!(decision.is_abort(), "FetchFailed should produce ABORT");
        match decision {
            EnforcementDecision::Abort {
                reason,
                detail,
                identity,
            } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(detail.contains("connector api.openai.com"));
                let identity = identity.expect("post-validation abort should carry identity");
                assert_eq!(identity.agent_id, "agt_01j0000000e008000000000001");
            }
            other => panic!("expected abort decision, got {other:?}"),
        }

        assert_eq!(payload.session_id, "sess_fail");
        assert_eq!(payload.decision, Decision::Abort);
        assert_eq!(payload.agent_id, "agt_01j0000000e008000000000001");
        assert!(
            payload
                .deny_reason
                .starts_with("CREDENTIAL_INJECTION_FAILED"),
            "deny_reason should carry credential abort code, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    // ===== SessionStateStore wiring (Task 5) =====

    #[tokio::test]
    async fn pipeline_builds_runtime_signals_and_populates_metadata() {
        use crate::enforcement::session::{LruSessionStateStore, SessionStateStore};
        use std::sync::Arc;

        let store: Arc<dyn SessionStateStore> = Arc::new(LruSessionStateStore::new(16));

        let pipeline = test_pipeline_with_session_store(Arc::clone(&store));
        let request = test_request(Method::POST, "api.openai.com/v1/chat/completions");

        // First call: action_count should be 1.
        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(matches!(decision, EnforcementDecision::Allow { .. }));
        assert_eq!(
            store
                .signals(&"sess_001".parse().expect("sid"))
                .action_count,
            1
        );

        // Second call: action_count should be 2.
        let (decision, _) = pipeline.enforce(&request, "sess_001").await;
        assert!(matches!(decision, EnforcementDecision::Allow { .. }));
        assert_eq!(
            store
                .signals(&"sess_001".parse().expect("sid"))
                .action_count,
            2
        );
    }

    #[tokio::test]
    async fn pipeline_stage1_deny_does_not_increment_action_count() {
        use crate::enforcement::session::{LruSessionStateStore, SessionStateStore};
        use std::sync::Arc;

        let store: Arc<dyn SessionStateStore> = Arc::new(LruSessionStateStore::new(16));

        // Pipeline configured so Stage 1 denies (no valid capability for
        // this session).
        let pipeline = test_pipeline_stage1_denies_with_session_store(Arc::clone(&store));
        let request = test_request(Method::POST, "api.openai.com/v1/chat/completions");

        let (decision, _) = pipeline.enforce(&request, "sess_denied").await;
        assert!(matches!(decision, EnforcementDecision::Deny { .. }));
        assert_eq!(
            store
                .signals(&"sess_denied".parse().expect("sid"))
                .action_count,
            0
        );
    }

    // ===== Monitor mode tests =====

    #[tokio::test]
    async fn monitor_mode_converts_deny_to_passthrough() {
        // Unclassified intent would DENY in enforce mode.
        let pipeline = test_pipeline().with_mode(SidecarMode::Monitor);
        let request = test_request(Method::DELETE, "api.openai.com/v1/files/abc");

        let (decision, payload) = pipeline.enforce(&request, "sess_monitor").await;

        assert!(
            decision.is_passthrough(),
            "monitor mode must convert DENY to Passthrough"
        );
        assert_eq!(payload.decision, Decision::Allow, "audit must record ALLOW");
        assert!(
            payload.deny_reason.starts_with("monitor_mode:"),
            "audit reason must carry monitor_mode prefix, got: {}",
            payload.deny_reason
        );
    }

    #[tokio::test]
    async fn monitor_mode_audit_reason_contains_original_deny_reason() {
        let pipeline = test_pipeline().with_mode(SidecarMode::Monitor);
        // Unclassified intent → DenyReason::UnclassifiedIntent in enforce mode.
        let request = test_request(Method::DELETE, "api.openai.com/v1/files/abc");

        let (_, payload) = pipeline.enforce(&request, "sess_monitor").await;

        assert!(
            payload.deny_reason.contains("unclassified intent"),
            "original deny reason must be embedded, got: {}",
            payload.deny_reason
        );
    }

    #[tokio::test]
    async fn monitor_mode_allows_normal_allows_unchanged() {
        // Requests that would ALLOW in enforce mode stay ALLOW in monitor mode.
        let pipeline = test_pipeline().with_mode(SidecarMode::Monitor);
        let request = test_request(Method::POST, "api.openai.com/v1/chat/completions");

        let (decision, payload) = pipeline.enforce(&request, "sess_001").await;

        assert!(decision.is_allow(), "normal ALLOWs must remain Allow");
        assert_eq!(payload.decision, Decision::Allow);
        assert!(
            payload.deny_reason.is_empty(),
            "deny_reason must be empty for genuine ALLOWs"
        );
    }

    #[tokio::test]
    async fn enforce_mode_still_denies() {
        // Sanity: enforce mode (default) must still produce DENY.
        let pipeline = test_pipeline();
        let request = test_request(Method::DELETE, "api.openai.com/v1/files/abc");

        let (decision, payload) = pipeline.enforce(&request, "sess_001").await;

        assert!(
            decision.is_deny(),
            "enforce mode must deny unclassified intent"
        );
        assert_eq!(payload.decision, Decision::Deny);
        assert!(!payload.deny_reason.is_empty(), "deny_reason must be set");
    }

    // ---- AARM R4 remediation audit extraction ----
    //
    // These exercise `audit_payload_from_decision` directly so the audit
    // shape of each remediation decision is pinned without coupling to a
    // Cedar annotation fixture.

    fn test_execution_envelope(claims: &CapabilityClaims) -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            firma_core::ExecutionIntent {
                action_class: "communication.external.send".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("api.openai.com"),
                params: firma_core::ActionParams::Http(firma_core::HttpParams {
                    method: firma_core::HttpMethod::POST,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat/completions".to_string(),
            },
            "token".to_string(),
            firma_core::ExecutionMetadata {
                session_id: claims.session_id.clone(),
                agent_id: claims.agent_id,
                timestamp: chrono::Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        )
    }

    #[test]
    fn audit_modify_carries_modify_decision_and_description() {
        let request = test_request(Method::POST, "api.openai.com/v1/chat/completions");
        let claims = test_claims();
        let modify = EnforcementDecision::Modify {
            claims: claims.clone(),
            envelope: Box::new(test_execution_envelope(&claims)),
            modifications: firma_core::ModificationSpec::RedactHeader(
                http::HeaderName::from_static("authorization"),
            ),
            credentials: InjectedCredentials::empty(),
        };
        let payload =
            audit_payload_from_decision(&modify, &request, "sess_001", Duration::ZERO, None);
        assert_eq!(payload.decision, Decision::Modify);
        assert_eq!(payload.deny_reason, "redacted_header:authorization");
        assert_eq!(payload.token_id, "ctok_01j0000000e008000000000001");
        assert_eq!(payload.action, "communication.external.send");
    }

    #[test]
    fn audit_step_up_carries_step_up_decision_and_challenge_reason() {
        let request = test_request(Method::POST, "api.openai.com/v1/chat/completions");
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
            identity: Some(identity),
        };
        let payload =
            audit_payload_from_decision(&step_up, &request, "sess_001", Duration::ZERO, None);
        assert_eq!(payload.decision, Decision::StepUp);
        assert!(
            payload.deny_reason.contains("step up required"),
            "reason must carry typed StepUpRequired, got: {}",
            payload.deny_reason
        );
        assert!(
            payload.deny_reason.contains("require admin approval"),
            "reason must carry the challenge, got: {}",
            payload.deny_reason
        );
        assert!(payload.deny_reason.contains("retry_after_ms: 500"));
        assert_eq!(payload.agent_id, "agent");
        assert_eq!(payload.token_id, "tok");
    }

    #[test]
    fn audit_defer_carries_defer_decision_and_retry_reason() {
        let request = test_request(Method::POST, "api.openai.com/v1/chat/completions");
        let defer = EnforcementDecision::Defer {
            claims: None,
            envelope: None,
            retry_after_ms: 1_000,
            identity: None,
        };
        let payload =
            audit_payload_from_decision(&defer, &request, "sess_001", Duration::ZERO, None);
        assert_eq!(payload.decision, Decision::Defer);
        assert!(
            payload.deny_reason.contains("deferred"),
            "reason must carry typed Deferred, got: {}",
            payload.deny_reason
        );
        assert!(payload.deny_reason.contains("retry_after_ms: 1000"));
        // No identity and no claims → empty attribution.
        assert!(payload.agent_id.is_empty());
        assert!(payload.token_id.is_empty());
    }
}
