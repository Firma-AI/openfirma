//! Stage 2 — Constraint Enforcement Engine (CEE).
//!
//! Second enforcement phase. The semantic layer where Cedar policies and
//! quantitative constraints are evaluated. Operates on a previously normalized
//! `ExecutionEnvelope` produced by Stage 1 — it must not infer the canonical
//! action class from raw transport-specific input.
//!
//! Steps:
//! 1. **Scope check** — verifies that the requested `action_class` is within
//!    the token's allowed `action_set`. Wildcard `"*"` permits all actions.
//! 2. **Policy bundle freshness** — if the bundle TTL has expired without a
//!    successful refresh, the Sidecar enters fail-closed mode and denies all
//!    new requests.
//! 3. **Context build** — assembles the Cedar request context from envelope
//!    fields, claims, and runtime signals such as risk score.
//! 4. **Cedar eval** — evaluates against the current policy bundle.
//!    Deterministic: same context + same bundle = same decision. Fully local,
//!    no external calls.
//!
//! Target latency: < 200 µs p95.
//!
//! # Security properties
//!
//! Stage 2 prevents valid capabilities from being misused for out-of-policy,
//! contextually disallowed actions:
//! - **Privilege escalation within token** — a valid token does not imply all
//!   calls are allowed; Cedar eval checks the specific call against policy.
//! - **Scope misuse at runtime** — a valid capability for action class X
//!   cannot be used for action class Y.
//! - **Non-deterministic authorization** — same context + same bundle always
//!   produces the same decision.

use std::sync::Arc;
use std::time::Duration;

use firma_core::token::matches_resource_scope;
use firma_core::{
    AgentId, CapabilityClaims, DenyReason, ModificationSpec, SecretDecision, StepUpSpec,
};

use super::decision::{ConstraintEnforcementStage, EnforcementDecision, EnforcementStage};
use crate::enforcement::session::RuntimeSignals;
use crate::normalizer::NormalizedEnvelope;

/// The verdict a policy engine returns for one evaluated action.
///
/// Cedar natively produces only `Allow`/`Deny`. The three remediation
/// variants (`Modify`, `StepUp`, `Defer`) are sourced from `@modify` /
/// `@step_up` / `@defer` annotations on `forbid` policies — see
/// [`CedarPolicyEvaluator`](super::cedar_evaluator::CedarPolicyEvaluator).
/// This is the AARM R4 five-decision set at the engine layer; the pipeline
/// lifts it into [`EnforcementDecision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Request authorized. Proceed to envelope assembly + dispatch.
    Allow,
    /// Request denied by policy. Mapped to a hard
    /// [`EnforcementDecision::Deny`] by the enforcer.
    Deny,
    /// AARM R4 `MODIFY`: execute a transformed version. `modifications`
    /// is sourced from the `@modify("…")` annotation.
    Modify {
        /// Description of the transformation to apply.
        modifications: ModificationSpec,
    },
    /// AARM R4 `STEP_UP`: require human approval / stronger authn before
    /// proceeding. `challenge` is sourced from the `@step_up("…")`
    /// annotation; `retry_after_ms` is supplied by the pipeline.
    StepUp {
        /// Human-readable challenge / approval description, validated
        /// non-empty at load time.
        challenge: StepUpSpec,
    },
    /// AARM R4 `DEFER`: delay execution pending additional context or
    /// rate-limit window. `backoff` is sourced from the `@defer("<ms>")` annotation.
    Defer {
        /// Backoff window before the agent should retry, validated > 0 at
        /// load time.
        backoff: Duration,
    },
}

/// Trait for policy evaluation — abstracts Cedar or any other policy engine.
///
/// The sidecar uses this trait rather than firma-core's `PolicyEvaluator`
/// because it needs a richer context (three-layer attributes). The concrete
/// Cedar implementation will be provided when unit 003 is built.
pub trait PolicyEvaluation: Send + Sync {
    /// Evaluate policy against the given context attributes.
    /// Returns true for ALLOW, false for DENY.
    ///
    /// Implementations that can express AARM R4 remediation outcomes
    /// (`MODIFY`, `STEP_UP`, `DEFER`) should override
    /// [`Self::evaluate_verdict`] instead; this bool view is retained for
    /// backward compatibility with deny-all / allow-all test stubs.
    ///
    /// # Errors
    ///
    /// Returns an error string if policy evaluation fails (e.g., malformed
    /// context or engine error).
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<bool, String>;

    /// Evaluate policy and return the full AARM R4 verdict, including
    /// remediation outcomes.
    ///
    /// The default delegates to [`Self::evaluate`] and collapses the bool to
    /// [`PolicyVerdict::Allow`] / [`PolicyVerdict::Deny`], so deny-all and
    /// allow-all test stubs keep working without modification. The concrete
    /// Cedar evaluator overrides this to surface `@modify` / `@step_up` /
    /// `@defer` annotations as remediation verdicts.
    ///
    /// # Errors
    ///
    /// Returns an error string if policy evaluation fails (e.g., malformed
    /// context or engine error).
    fn evaluate_verdict(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<PolicyVerdict, String> {
        if self.evaluate(principal, action, resource, context)? {
            Ok(PolicyVerdict::Allow)
        } else {
            Ok(PolicyVerdict::Deny)
        }
    }

    /// Check if the policy bundle is still fresh (TTL not expired).
    fn is_fresh(&self) -> bool;

    /// Check if a policy bundle is currently available.
    ///
    /// Default assumes availability, preserving backwards compatibility for
    /// evaluators that only model freshness.
    fn is_available(&self) -> bool {
        true
    }

    /// Get the current policy bundle version.
    fn version(&self) -> Option<String>;

    /// Decide secret mediation for a shimmed launch (`secret.mediate`).
    ///
    /// The default returns [`SecretDecision::Passthrough`] — no governing
    /// policy, so the tool runs untouched. The Cedar evaluator overrides this
    /// to evaluate `secret.mediate` and return a [`SecretDecision::Permit`]
    /// directive when a permit fires.
    ///
    /// # Errors
    ///
    /// Returns an error string if policy evaluation fails.
    fn evaluate_secret_mediation(
        &self,
        _principal: &AgentId,
        _argv: &str,
        _context: serde_json::Value,
    ) -> Result<SecretDecision, String> {
        Ok(SecretDecision::Passthrough)
    }

    /// Decide whether to apply secret rewriting for an outbound HTTP request
    /// (`secret.redact`).
    ///
    /// Returns `true` when a `permit` policy fires — placeholder rehydration
    /// and secret masking are active for this request. The default returns
    /// `false` (passthrough). The Cedar evaluator overrides this.
    ///
    /// # Errors
    ///
    /// Returns an error string if policy evaluation fails.
    fn evaluate_secret_redact(
        &self,
        _principal: &AgentId,
        _host: &str,
        _path: &str,
        _method: &str,
        _context: serde_json::Value,
    ) -> Result<bool, String> {
        Ok(false)
    }
}

/// Stage 2: Constraint Enforcement Engine (CEE).
///
/// Performs scope check (action within token's allowed set), builds the
/// Cedar evaluation context, and evaluates policies. Fully local.
///
/// Target: < 200us p95.
pub struct ConstraintEnforcer {
    policy: Arc<dyn PolicyEvaluation>,
}

impl ConstraintEnforcer {
    #[must_use]
    pub fn new(policy: Arc<dyn PolicyEvaluation>) -> Self {
        Self { policy }
    }

    /// Return the active policy bundle version, if one has been installed.
    #[must_use]
    pub fn policy_version(&self) -> Option<String> {
        self.policy.version()
    }

    /// Evaluate the request against Cedar policies.
    ///
    /// Returns `Ok(PolicyVerdict)` for a passing or remediation outcome
    /// (`Allow`, `Modify`, `StepUp`, `Defer`), or
    /// `Err(EnforcementDecision::Deny)` if any check fails (scope, freshness,
    /// or a hard policy deny). The pipeline is responsible for lifting the
    /// verdict into a fully populated [`EnforcementDecision`].
    ///
    /// Sequence:
    /// 1. Scope check -- is `action_class` in the token's `action_set`?
    /// 2. Check policy availability
    /// 3. Check policy bundle freshness
    /// 4. Build Cedar context
    /// 5. Evaluate Cedar policies (incl. AARM R4 remediation annotations)
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if scope check, bundle freshness,
    /// or Cedar policy evaluation fails, or if the policy denies the action.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    pub fn evaluate(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
        signals: &RuntimeSignals,
    ) -> Result<PolicyVerdict, EnforcementDecision> {
        // Step 1: Scope check (pre-Cedar gate)
        self.check_scope(envelope, claims)?;

        // Step 2: Check policy availability (fail-closed)
        if !self.policy.is_available() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable; failing closed".to_string(),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }

        // Step 3: Check policy bundle freshness
        if !self.policy.is_fresh() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleStale,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable or stale".to_string(),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }

        // Step 4: Build context
        let context = self.build_context(envelope, claims, signals)?;

        // Step 5: Evaluate policies (verdict carries AARM R4 remediation)
        let resource_display = envelope.intent.resource_display();
        let verdict = self
            .policy
            .evaluate_verdict(
                &claims.agent_id,
                &envelope.intent.action_class,
                &resource_display,
                context,
            )
            .map_err(|err| EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("policy evaluation failed; failing closed: {err}"),
                envelope: Some(envelope.clone()),
                identity: None,
            })?;

        if matches!(verdict, PolicyVerdict::Deny) {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "policy denied action '{}' on resource '{}'",
                    envelope.intent.action_class, resource_display
                ),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }
        Ok(verdict)
    }

    /// Timeout-aware Stage 2 evaluation.
    ///
    /// Policy evaluation is bounded and any timeout yields a fail-closed DENY
    /// with `EnforcementTimeout`. Otherwise mirrors [`Self::evaluate`],
    /// returning the AARM R4 [`PolicyVerdict`] on the `Ok` path.
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if scope validation fails, the
    /// policy bundle is unavailable (`FailClosed`) or stale
    /// (`PolicyBundleStale`), policy evaluation times out
    /// (`EnforcementTimeout`), or the policy evaluator returns an error
    /// (`FailClosed`), or the policy denies the action (`PolicyDenied`).
    pub async fn evaluate_with_timeout(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
        signals: &RuntimeSignals,
        timeout: Duration,
    ) -> Result<PolicyVerdict, EnforcementDecision> {
        // Step 1: Scope check (pre-Cedar gate)
        self.check_scope(envelope, claims)?;

        // Step 2: Check policy availability (fail-closed)
        if !self.policy.is_available() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable; failing closed".to_string(),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }

        // Step 3: Deny stale policy bundle
        if !self.policy.is_fresh() {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleStale,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::BundleFreshness,
                ),
                detail: "policy bundle unavailable or stale".to_string(),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }

        // Step 4: Build context from immutable request + validated claims.
        let context = self.build_context(envelope, claims, signals)?;
        let policy = Arc::clone(&self.policy);
        let principal = claims.agent_id;
        let action = envelope.intent.action_class.clone();
        let resource = envelope.intent.resource_display();
        let eval_task = tokio::task::spawn_blocking(move || {
            policy.evaluate_verdict(&principal, &action, &resource, context)
        });

        let verdict = tokio::time::timeout(timeout, eval_task)
            .await
            .map_err(|_| EnforcementDecision::Deny {
                reason: DenyReason::EnforcementTimeout,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "stage 2 policy evaluation timed out after {} ms",
                    timeout.as_millis()
                ),
                envelope: Some(envelope.clone()),
                identity: None,
            })?
            .map_err(|join_err| EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("policy evaluation task failed; failing closed: {join_err}"),
                envelope: Some(envelope.clone()),
                identity: None,
            })?
            .map_err(|err| EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("policy evaluation failed; failing closed: {err}"),
                envelope: Some(envelope.clone()),
                identity: None,
            })?;

        if matches!(verdict, PolicyVerdict::Deny) {
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!(
                    "policy denied action '{}' on resource '{}'",
                    envelope.intent.action_class,
                    envelope.intent.resource_display()
                ),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }
        Ok(verdict)
    }

    /// Scope check: verify `action_class` is in the token's allowed action set.
    /// Wildcard "*" in `action_set` means all actions are allowed.
    #[expect(clippy::unused_self, reason = "will use self when Cedar is integrated")]
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    fn check_scope(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
    ) -> Result<(), EnforcementDecision> {
        let action = &envelope.intent.action_class;
        let resource = envelope.intent.resource_display();

        if claims.action_set.iter().any(|a| a == "*") {
            if matches_resource_scope(&claims.resource_scope, &resource) {
                return Ok(());
            }
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::ScopeViolation,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::ScopeCheck,
                ),
                detail: format!(
                    "resource '{}' not in token's scope '{}'",
                    resource, claims.resource_scope
                ),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }

        if claims.action_set.iter().any(|a| a == action) {
            if matches_resource_scope(&claims.resource_scope, &resource) {
                return Ok(());
            }
            return Err(EnforcementDecision::Deny {
                reason: DenyReason::ScopeViolation,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::ScopeCheck,
                ),
                detail: format!(
                    "resource '{}' not in token's scope '{}'",
                    resource, claims.resource_scope
                ),
                envelope: Some(envelope.clone()),
                identity: None,
            });
        }

        Err(EnforcementDecision::Deny {
            reason: DenyReason::ScopeViolation,
            stage: EnforcementStage::ConstraintEnforcement(ConstraintEnforcementStage::ScopeCheck),
            detail: format!(
                "action '{}' not in token's allowed set: {:?}",
                action, claims.action_set
            ),
            envelope: Some(envelope.clone()),
            identity: None,
        })
    }

    /// Build the Cedar evaluation context from envelope + claims + runtime signals.
    ///
    /// Emits the shape declared by `EnforcementContext` in the canonical
    /// `schema.cedarschema`. `action_class`, `resource`, and `agent_id` are
    /// not in the context — they are passed to Cedar as principal/action/
    /// resource entity UIDs.
    #[expect(clippy::unused_self, reason = "reserved for future stateful hooks")]
    #[expect(
        clippy::result_large_err,
        reason = "the error variant is the fail-closed enforcement decision"
    )]
    fn build_context(
        &self,
        envelope: &NormalizedEnvelope,
        claims: &CapabilityClaims,
        signals: &RuntimeSignals,
    ) -> Result<serde_json::Value, EnforcementDecision> {
        let session_duration_s = (envelope.timestamp - claims.issued_at).num_seconds().max(0);
        let timestamp_ms = envelope.timestamp.timestamp_millis();
        // Fail closed: if the intent params cannot be serialized into the
        // Cedar context, do not silently substitute an empty `params`
        // object — a policy conditioned on `params` could then allow a
        // request it should have blocked. Surface the serialization failure
        // as a fail-closed DENY instead.
        let params = serde_json::to_string(&envelope.intent.params).map_err(|err| {
            EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: EnforcementStage::ConstraintEnforcement(
                    ConstraintEnforcementStage::PolicyEvaluation,
                ),
                detail: format!("failed to serialize intent params; failing closed: {err}"),
                envelope: Some(envelope.clone()),
                identity: None,
            }
        })?;
        // Payment-context fields are declared in the canonical schema but
        // sourced by future tasks. V1 supplies fixed placeholders so the
        // schema-strict `Context::from_json_value` accepts the record.
        //
        // Prior-action context (AARM R2 G3): surface the bounded session
        // history so policies can reason about what the agent has already
        // attempted. `prior_action_classes` preserves first-seen order and
        // deduplicates within the bounded window; `last_resource` is empty
        // when no prior action has been recorded.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let prior_action_classes: Vec<String> = signals
            .history
            .iter()
            .filter_map(|o| {
                if seen.insert(o.action_class.as_str()) {
                    Some(o.action_class.clone())
                } else {
                    None
                }
            })
            .collect();
        let last_resource = signals
            .history
            .last()
            .map_or_else(String::new, |o| o.resource.clone());
        let mut context = serde_json::Map::new();
        context.insert(
            "session_id".to_string(),
            serde_json::json!(claims.session_id),
        );
        context.insert("timestamp_ms".to_string(), serde_json::json!(timestamp_ms));
        context.insert("params".to_string(), serde_json::json!(params));
        context.insert(
            "risk_score".to_string(),
            serde_json::json!(signals.risk_score_long()),
        );
        context.insert(
            "session_duration_s".to_string(),
            serde_json::json!(session_duration_s),
        );
        context.insert(
            "action_count".to_string(),
            serde_json::json!(i64::try_from(signals.action_count).unwrap_or(i64::MAX)),
        );
        context.insert(
            "raw_transport".to_string(),
            serde_json::json!(envelope.intent.raw_transport),
        );
        context.insert("transfer_amount".to_string(), serde_json::json!(0i64));
        context.insert(
            "daily_cumulative_amount".to_string(),
            serde_json::json!(0i64),
        );
        context.insert("transfers_last_10m".to_string(), serde_json::json!(0i64));
        context.insert("same_payee_count_30m".to_string(), serde_json::json!(0i64));
        context.insert(
            "session_transfer_count".to_string(),
            serde_json::json!(0i64),
        );
        context.insert(
            "deny_count".to_string(),
            serde_json::json!(i64::try_from(signals.deny_count).unwrap_or(i64::MAX)),
        );
        context.insert(
            "prior_action_classes".to_string(),
            serde_json::json!(prior_action_classes),
        );
        context.insert(
            "last_resource".to_string(),
            serde_json::json!(last_resource),
        );
        for key in [
            "git_provider",
            "git_owner",
            "git_repo",
            "git_ref",
            "git_ref_type",
            "git_operation",
        ] {
            if let Some(value) = envelope.intent.resource.get(key) {
                context.insert(key.to_string(), serde_json::json!(value));
            }
        }

        Ok(serde_json::Value::Object(context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::session::{ActionOutcome, Outcome, RuntimeSignals};
    use chrono::Utc;
    use firma_core::*;
    use std::collections::HashMap;

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
            Some("test-v1".to_string())
        }
    }

    struct ErrorPolicy;
    impl PolicyEvaluation for ErrorPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<bool, String> {
            Err("evaluation backend error".to_string())
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

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

    struct UnavailablePolicy;
    impl PolicyEvaluation for UnavailablePolicy {
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
        fn is_available(&self) -> bool {
            false
        }
        fn version(&self) -> Option<String> {
            None
        }
    }

    struct SlowPolicy;
    impl PolicyEvaluation for SlowPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<bool, String> {
            std::thread::sleep(Duration::from_millis(200));
            Ok(true)
        }

        fn is_fresh(&self) -> bool {
            true
        }

        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    fn test_envelope(action_class: &str) -> NormalizedEnvelope {
        test_envelope_with_resource(action_class, "api.openai.com/v1/chat/completions")
    }

    fn test_envelope_with_resource(action_class: &str, resource: &str) -> NormalizedEnvelope {
        NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: action_class.to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from(resource),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::POST,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat/completions".to_string(),
            },
            timestamp: Utc::now(),
        }
    }

    fn test_claims(actions: Vec<&str>) -> CapabilityClaims {
        test_claims_with_scope(actions, "*")
    }

    fn test_claims_with_scope(actions: Vec<&str>, resource_scope: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001"
                .parse()
                .expect("literal token id"),
            agent_id: "agt_01j0000000e008000000000001"
                .parse()
                .expect("literal agent id"),
            session_id: "sess_001".parse().expect("literal session id"),
            action_set: actions.into_iter().map(String::from).collect(),
            resource_scope: resource_scope.to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_signals() -> RuntimeSignals {
        RuntimeSignals {
            action_count: 1,
            risk_score: 0.0,
            ..RuntimeSignals::default()
        }
    }

    #[test]
    fn test_allow_when_in_scope_and_policy_allows() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_scope_violation() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.delete");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_wildcard_scope_allows_all() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("system.execute");
        let claims = test_claims(vec!["*"]);

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_when_policy_denies() {
        let evaluator = ConstraintEnforcer::new(Arc::new(DenyAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[test]
    fn test_deny_when_bundle_stale() {
        let evaluator = ConstraintEnforcer::new(Arc::new(StalePolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    #[test]
    fn test_deny_when_bundle_unavailable_fail_closed() {
        let evaluator = ConstraintEnforcer::new(Arc::new(UnavailablePolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[test]
    fn test_scope_check_multiple_actions_in_set() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.read");
        let claims = test_claims(vec![
            "communication.external.send",
            "filesystem.read",
            "credential.read",
        ]);

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_scope_check_empty_action_set_denies() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec![]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_build_context_includes_required_fields() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let mut claims = test_claims(vec!["communication.external.send"]);
        claims.issued_at = envelope.timestamp - chrono::Duration::seconds(42);
        let signals = RuntimeSignals {
            action_count: 7,
            risk_score: 3.0,
            ..RuntimeSignals::default()
        };

        let context = evaluator
            .build_context(&envelope, &claims, &signals)
            .expect("build_context must succeed for valid envelopes");

        // The canonical schema declares the `EnforcementContext` fields;
        // the commonly-tuned and prior-action ones are asserted here:
        assert_eq!(context["session_id"], "sess_001");
        assert!(context["timestamp_ms"].is_i64());
        assert!(context["params"].is_string());
        assert_eq!(context["risk_score"], 3);
        assert_eq!(context["session_duration_s"], 42);
        assert_eq!(context["action_count"], 7);
        // Prior-action context (AARM R2 G3) — fresh session defaults.
        assert_eq!(context["deny_count"], 0);
        assert_eq!(context["prior_action_classes"], serde_json::json!([]));
        assert_eq!(context["last_resource"], "");

        // Schema does not declare action_class / resource / agent_id /
        // timestamp — they are passed as Cedar principal/action/resource
        // entity UIDs, not context attributes.
        assert!(context.get("action_class").is_none());
        assert!(context.get("resource").is_none());
        assert!(context.get("agent_id").is_none());
        assert!(context.get("timestamp").is_none());
    }

    #[test]
    fn test_build_context_includes_git_metadata_when_present() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let mut envelope =
            test_envelope_with_resource("code.write", "github.com/owner/repo.git/git-receive-pack");
        envelope
            .intent
            .resource
            .insert("git_provider".to_string(), "github".to_string());
        envelope
            .intent
            .resource
            .insert("git_owner".to_string(), "firma-ai".to_string());
        envelope
            .intent
            .resource
            .insert("git_repo".to_string(), "openfirma".to_string());
        envelope
            .intent
            .resource
            .insert("git_ref".to_string(), "refs/heads/fir-413".to_string());
        envelope
            .intent
            .resource
            .insert("git_ref_type".to_string(), "branch".to_string());
        envelope
            .intent
            .resource
            .insert("git_operation".to_string(), "write".to_string());
        let claims = test_claims(vec!["code.write"]);

        let context = evaluator
            .build_context(&envelope, &claims, &test_signals())
            .expect("build_context must succeed for valid envelopes");

        assert_eq!(context["git_provider"], "github");
        assert_eq!(context["git_owner"], "firma-ai");
        assert_eq!(context["git_repo"], "openfirma");
        assert_eq!(context["git_ref"], "refs/heads/fir-413");
        assert_eq!(context["git_ref_type"], "branch");
        assert_eq!(context["git_operation"], "write");
    }

    #[test]
    fn test_build_context_surfaces_prior_action_history() {
        // AARM R2 G3: the Cedar context must surface prior action classes,
        // deny count, and the most recent resource so policies can reason
        // about what the session has already attempted.
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.delete");
        let claims = test_claims(vec!["filesystem.delete"]);
        let signals = RuntimeSignals {
            action_count: 4,
            risk_score: 0.0,
            deny_count: 2,
            history: vec![
                ActionOutcome {
                    action_class: "communication.external.send".to_string(),
                    resource: "api.example.com/v1".to_string(),
                    outcome: Outcome::Allow,
                },
                ActionOutcome {
                    action_class: "payment.transfer".to_string(),
                    resource: "api.pay.com/x".to_string(),
                    outcome: Outcome::Deny,
                },
            ],
            ..RuntimeSignals::default()
        };
        let context = evaluator
            .build_context(&envelope, &claims, &signals)
            .expect("build_context must succeed for valid envelopes");
        assert_eq!(context["deny_count"], serde_json::json!(2));
        // Deduped, first-seen order:
        assert_eq!(
            context["prior_action_classes"],
            serde_json::json!(["communication.external.send", "payment.transfer"])
        );
        // Most recent prior action's resource:
        assert_eq!(context["last_resource"], serde_json::json!("api.pay.com/x"));
    }

    #[test]
    fn test_build_context_negative_session_duration_clamped_to_zero() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let mut claims = test_claims(vec!["communication.external.send"]);
        // Token issued AFTER request timestamp (clock skew edge case).
        claims.issued_at = envelope.timestamp + chrono::Duration::seconds(10);
        let signals = RuntimeSignals {
            action_count: 1,
            risk_score: 0.0,
            ..RuntimeSignals::default()
        };
        let context = evaluator
            .build_context(&envelope, &claims, &signals)
            .expect("build_context must succeed for valid envelopes");
        assert_eq!(context["session_duration_s"], serde_json::json!(0));
    }

    #[test]
    fn test_stale_bundle_short_circuits_before_policy_eval() {
        // Even if policy would allow, staleness must deny first
        struct StaleButAllowPolicy;
        impl PolicyEvaluation for StaleButAllowPolicy {
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

        let evaluator = ConstraintEnforcer::new(Arc::new(StaleButAllowPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::BundleFreshness
            ))
        );
    }

    #[test]
    fn test_scope_violation_reports_correct_stage() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope("filesystem.delete");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::ScopeCheck
            ))
        );
    }

    #[test]
    fn test_policy_deny_reports_correct_stage() {
        let evaluator = ConstraintEnforcer::new(Arc::new(DenyAllPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert_eq!(
            decision.stage(),
            Some(EnforcementStage::ConstraintEnforcement(
                ConstraintEnforcementStage::PolicyEvaluation
            ))
        );
    }

    #[test]
    fn test_policy_evaluator_error_fails_closed() {
        let evaluator = ConstraintEnforcer::new(Arc::new(ErrorPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_stage2_timeout_fails_closed() {
        use std::time::Duration;
        let evaluator = ConstraintEnforcer::new(Arc::new(SlowPolicy));
        let envelope = test_envelope("communication.external.send");
        let claims = test_claims(vec!["communication.external.send"]);

        let decision = evaluator
            .evaluate_with_timeout(
                &envelope,
                &claims,
                &test_signals(),
                Duration::from_millis(20),
            )
            .await
            .unwrap_err();

        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::EnforcementTimeout));
    }

    #[test]
    fn test_resource_scope_prefix_allows_matching_resource() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims =
            test_claims_with_scope(vec!["communication.external.send"], "api.openai.com/*");

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_scope_exact_match_allows() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims = test_claims_with_scope(
            vec!["communication.external.send"],
            "api.openai.com/v1/chat/completions",
        );

        let result = evaluator.evaluate(&envelope, &claims, &test_signals());
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_scope_denies_different_host() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope =
            test_envelope_with_resource("communication.external.send", "other.example.com/v1/data");
        let claims =
            test_claims_with_scope(vec!["communication.external.send"], "api.openai.com/*");

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_resource_scope_denies_subpath_mismatch() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource(
            "communication.external.send",
            "api.openai.com/v1/chat/completions",
        );
        let claims = test_claims_with_scope(
            vec!["communication.external.send"],
            "api.openai.com/v1/files",
        );

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_resource_scope_wildcard_action_denied_by_resource_scope() {
        let evaluator = ConstraintEnforcer::new(Arc::new(AllowAllPolicy));
        let envelope = test_envelope_with_resource("system.execute", "other.example.com/anything");
        let claims = test_claims_with_scope(vec!["*"], "api.openai.com/*");

        let decision = evaluator
            .evaluate(&envelope, &claims, &test_signals())
            .unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }
}
