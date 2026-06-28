use serde::{Deserialize, Serialize};

/// Typed reason code explaining why an already-authorized request was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum AbortReason {
    /// Outbound connector exceeded its configured timeout.
    #[error("connector timeout")]
    ConnectorTimeout,
    /// Outbound connector failed before producing a target response.
    #[error("connector failure")]
    ConnectorFailure,
    /// Outbound connector rejected the authorized envelope shape.
    #[error("connector invalid request")]
    ConnectorInvalidRequest,
    /// Sidecar failed to inject credentials after enforcement allowed the call.
    #[error("credential injection failed")]
    CredentialInjectionFailed,
}

impl AbortReason {
    /// Canonical reason code string used in audit events and agent responses.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConnectorTimeout => "CONNECTOR_TIMEOUT",
            Self::ConnectorFailure => "CONNECTOR_FAILURE",
            Self::ConnectorInvalidRequest => "CONNECTOR_INVALID_REQUEST",
            Self::CredentialInjectionFailed => "CREDENTIAL_INJECTION_FAILED",
        }
    }
}

/// Outcome of policy evaluation.
///
/// Every enforcement decision in Firma maps to one of these three variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Request passes all checks. Proceed with execution.
    Allow,
    /// Request denied. Return error to agent with reason code.
    Deny { reason: DenyReason },
    /// Critical failure. Kill the session/execution immediately.
    Abort { reason: String },
}

/// Typed reason code explaining why a request was denied.
///
/// Backlog variants (add back when corresponding mechanisms exist):
/// - `BudgetExceeded` — when budget tracking mechanism is designed
/// - `RiskThreshold` — when anomaly detection is designed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum DenyReason {
    /// Signature check failed or unrecognized token format.
    #[error("token invalid")]
    TokenInvalid,
    /// Token TTL has elapsed.
    #[error("token expired")]
    TokenExpired,
    /// Token has been explicitly revoked.
    #[error("token revoked")]
    TokenRevoked,
    /// Cedar policy evaluation returned deny.
    #[error("policy denied")]
    PolicyDenied,
    /// Action or resource outside the token's granted scope.
    #[error("scope violation")]
    ScopeViolation,
    /// Specific tool not in the token's allowed set.
    #[error("tool not in scope")]
    ToolNotInScope,
    /// Execution envelope failed validation.
    #[error("malformed request")]
    MalformedRequest,
    /// Cannot reach Authority for token validation.
    #[error("authority unavailable")]
    AuthorityUnavailable,
    /// Policy bundle TTL exceeded, no fresh bundle available.
    #[error("policy bundle stale")]
    PolicyBundleStale,
    /// Initial policy bundle has not been applied yet.
    #[error("policy bundle not ready")]
    PolicyBundleNotReady,
    /// Initial revocation state has not been applied yet.
    #[error("revocation cache not ready")]
    RevocationCacheNotReady,
    /// Fail-closed safety boundary triggered due to missing/invalid enforcement prerequisites.
    #[error("fail closed")]
    FailClosed,
    /// Enforcement evaluation exceeded configured timeout budget.
    #[error("enforcement timeout")]
    EnforcementTimeout,
    /// Sidecar failed to inject credentials for Stage 3.
    ///
    /// No current producer: credential-injection failure after ALLOW is
    /// raised as [`AbortReason::CredentialInjectionFailed`] (FIR-46), not a
    /// DENY. Retained for serialized backward compatibility of this enum.
    #[error("credential injection failed")]
    CredentialInjectionFailed,
    /// Outbound connector timed out.
    #[error("connector timeout")]
    ConnectorTimeout,
    /// Outbound connector failed at the transport layer (DNS, TCP,
    /// TLS, connection reset).
    #[error("connector network error")]
    ConnectorNetworkError,
    /// Outbound connector could not translate the envelope into a
    /// well-formed target request.
    ///
    /// No current producer: a connector that fails to build a request after
    /// ALLOW is raised as [`AbortReason::ConnectorInvalidRequest`] (FIR-46),
    /// not a DENY. Retained for serialized backward compatibility of this enum.
    #[error("connector invalid request")]
    ConnectorInvalidRequest,
    /// Protected action could not be mapped to any canonical action class.
    #[error("unclassified intent")]
    UnclassifiedIntent,
    /// Token's `agent_id` differs from the first `agent_id` observed by this
    /// Sidecar process. Enforces single-agent tenancy (V1 ADR §2).
    #[error("tenant mismatch")]
    TenantMismatch,
    /// AARM R4 `STEP_UP`: the call is blocked pending human approval or
    /// stronger authentication before it may proceed. The agent should
    /// request approval and retry with the resulting approval credential.
    #[error("step up required")]
    StepUpRequired,
    /// AARM R4 `DEFER`: the call is blocked and should be retried after the
    /// supplied backoff window, pending additional context or rate budget.
    #[error("deferred")]
    Deferred,
}

/// Structured transformation applied to a request under the AARM R4 `MODIFY`
/// decision.
///
/// Sourced from a `@modify("…")` Cedar policy annotation. The annotation
/// value is a small DSL: `<kind>:<value>`. V1 supports a single kind:
///
/// - `redact_header:<name>` — strip the named HTTP header (case-insensitive)
///   from the outbound request before dispatch. The audit record carries
///   `redacted_header:<name>` so an operator can reconcile the transformed
///   execution against policy intent.
///
/// Unknown kinds, empty header names, or a missing `:` reject the bundle at
/// load time (`MalformedAnnotation`) — the author must fix the policy. New
/// kinds (e.g. `strip_query_param`) can be added later as enum variants
/// without a wire break.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModificationSpec {
    /// Strip the named HTTP header from the outbound request before dispatch.
    /// Header-name matching is case-insensitive (HTTP semantics).
    RedactHeader(String),
}

/// DSL prefix for the header-redaction transformation.
const MODIFICATION_REDACT_HEADER: &str = "redact_header:";

impl ModificationSpec {
    /// Parse a `@modify("…")` annotation value into a [`ModificationSpec`].
    ///
    /// Returns `Err(reason)` if the value is not a recognised `<kind>:<value>`
    /// form or the payload is empty. The caller maps the reason into a
    /// `MalformedAnnotation` error at the sidecar layer.
    ///
    /// # Errors
    ///
    /// - `redact_header:<name>` with an empty `<name>` → `Err`.
    /// - Unknown kind (no recognised prefix) → `Err`.
    pub fn parse(annotation: &str) -> Result<Self, String> {
        let value = annotation.trim();
        if value.is_empty() {
            return Err("modify annotation value must not be empty".to_string());
        }
        if let Some(name) = value.strip_prefix(MODIFICATION_REDACT_HEADER) {
            let name = name.trim();
            if name.is_empty() {
                return Err("redact_header: header name must not be empty".to_string());
            }
            return Ok(Self::RedactHeader(name.to_string()));
        }
        Err(format!(
            "unknown @modify kind; expected `{MODIFICATION_REDACT_HEADER}<name>`, got: {value:?}"
        ))
    }

    /// Apply this transformation in place to a dispatch-bound envelope.
    ///
    /// Mutates only the HTTP headers map of the dispatch clone; the original
    /// envelope stored on the sidecar's `EnforcementDecision::Modify` is
    /// untouched, preserving the immutability invariant. No-op for non-HTTP
    /// action params so the same call site is safe for all envelope shapes.
    pub fn apply(&self, envelope: &mut crate::envelope::ExecutionEnvelope) {
        let crate::envelope::ActionParams::Http(http) = &mut envelope.intent.params else {
            return;
        };
        match self {
            Self::RedactHeader(name) => {
                http.headers.retain(|k, _| !k.eq_ignore_ascii_case(name));
            }
        }
    }
}

impl std::fmt::Display for ModificationSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedactHeader(name) => write!(f, "redacted_header:{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Display;

    #[test]
    fn test_decision_allow() {
        let d = Decision::Allow;
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn test_decision_deny() {
        let d = Decision::Deny {
            reason: DenyReason::PolicyDenied,
        };
        assert!(matches!(
            d,
            Decision::Deny {
                reason: DenyReason::PolicyDenied
            }
        ));
    }

    #[test]
    fn test_decision_abort() {
        let d = Decision::Abort {
            reason: "fatal error".to_string(),
        };
        assert!(matches!(d, Decision::Abort { .. }));
    }

    #[test]
    fn test_abort_reason_code_all_variants() {
        use strum::IntoEnumIterator;
        // Exhaustive match: a new `AbortReason` variant fails to compile
        // here until its canonical code is added, so the registry can
        // never silently drift.
        for reason in AbortReason::iter() {
            let expected = match reason {
                AbortReason::ConnectorTimeout => "CONNECTOR_TIMEOUT",
                AbortReason::ConnectorFailure => "CONNECTOR_FAILURE",
                AbortReason::ConnectorInvalidRequest => "CONNECTOR_INVALID_REQUEST",
                AbortReason::CredentialInjectionFailed => "CREDENTIAL_INJECTION_FAILED",
            };
            assert_eq!(reason.code(), expected);
        }
    }

    #[test]
    fn test_deny_reason_display_all_variants() {
        let cases = [
            (DenyReason::TokenInvalid, "token invalid"),
            (DenyReason::TokenExpired, "token expired"),
            (DenyReason::TokenRevoked, "token revoked"),
            (DenyReason::PolicyDenied, "policy denied"),
            (DenyReason::ScopeViolation, "scope violation"),
            (DenyReason::ToolNotInScope, "tool not in scope"),
            (DenyReason::MalformedRequest, "malformed request"),
            (DenyReason::AuthorityUnavailable, "authority unavailable"),
            (DenyReason::PolicyBundleStale, "policy bundle stale"),
            (DenyReason::PolicyBundleNotReady, "policy bundle not ready"),
            (
                DenyReason::RevocationCacheNotReady,
                "revocation cache not ready",
            ),
            (DenyReason::FailClosed, "fail closed"),
            (DenyReason::EnforcementTimeout, "enforcement timeout"),
            (
                DenyReason::CredentialInjectionFailed,
                "credential injection failed",
            ),
            (DenyReason::ConnectorTimeout, "connector timeout"),
            (DenyReason::ConnectorNetworkError, "connector network error"),
            (
                DenyReason::ConnectorInvalidRequest,
                "connector invalid request",
            ),
            (DenyReason::UnclassifiedIntent, "unclassified intent"),
            (DenyReason::TenantMismatch, "tenant mismatch"),
            (DenyReason::StepUpRequired, "step up required"),
            (DenyReason::Deferred, "deferred"),
        ];
        for (reason, expected) in cases {
            assert_eq!(reason.to_string(), expected);
        }
    }

    #[test]
    fn test_deny_reason_copy() {
        let reason = DenyReason::TokenExpired;
        let copied = reason;
        assert_eq!(reason, copied);
    }

    #[test]
    fn modification_spec_round_trip() {
        let spec = ModificationSpec::RedactHeader("authorization".to_string());
        let json = serde_json::to_string(&spec).unwrap_or_else(|e| panic!("{e}"));
        let parsed: ModificationSpec =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(spec, parsed);
    }

    #[test]
    fn modification_spec_parse_redact_header() {
        let spec = ModificationSpec::parse("redact_header:authorization")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            spec,
            ModificationSpec::RedactHeader("authorization".to_string())
        );
    }

    #[test]
    fn modification_spec_parse_trims_whitespace() {
        let spec = ModificationSpec::parse("  redact_header:  x-api-key  ")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            spec,
            ModificationSpec::RedactHeader("x-api-key".to_string())
        );
    }

    #[test]
    fn modification_spec_parse_rejects_empty_header_name() {
        let err = ModificationSpec::parse("redact_header:").unwrap_err();
        assert!(err.contains("header name must not be empty"), "got: {err}");
    }

    #[test]
    fn modification_spec_parse_rejects_unknown_kind() {
        let err = ModificationSpec::parse("rewrite_body:foo").unwrap_err();
        assert!(err.contains("unknown @modify kind"), "got: {err}");
    }

    #[test]
    fn modification_spec_parse_rejects_empty_value() {
        let err = ModificationSpec::parse("   ").unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn modification_spec_display_redacted_header() {
        let spec = ModificationSpec::RedactHeader("authorization".to_string());
        assert_eq!(spec.to_string(), "redacted_header:authorization");
    }

    #[test]
    fn modification_spec_apply_strips_header_case_insensitive() {
        use crate::envelope::{
            ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
            HttpParams,
        };

        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer secret".to_string());
        headers.insert("X-Trace-Id".to_string(), "abc".to_string());
        let envelope = ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "communication.external.send".to_string(),
                resource: std::collections::BTreeMap::new(),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::POST,
                    headers,
                    body: None,
                    query: std::collections::HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat".to_string(),
            },
            "raw-token".to_string(),
            ExecutionMetadata {
                session_id: "sess".parse().unwrap(),
                agent_id: "agent".parse().unwrap(),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        );

        // Redact the Authorization header (case-insensitive match against "Authorization").
        let mut envelope = envelope;
        ModificationSpec::RedactHeader("authorization".to_string()).apply(&mut envelope);

        let ActionParams::Http(http) = &envelope.intent.params else {
            panic!("expected Http params");
        };
        assert!(
            !http.headers.contains_key("Authorization"),
            "Authorization should be stripped"
        );
        assert!(
            http.headers.contains_key("X-Trace-Id"),
            "X-Trace-Id should survive the redaction"
        );
    }

    #[test]
    fn modification_spec_apply_noop_for_non_http() {
        use crate::envelope::{
            ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, ToolUseParams,
        };

        let envelope = ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "tool.use".to_string(),
                resource: std::collections::BTreeMap::new(),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "search".to_string(),
                    input: std::collections::HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "tool:search".to_string(),
            },
            "raw-token".to_string(),
            ExecutionMetadata {
                session_id: "sess".parse().unwrap(),
                agent_id: "agent".parse().unwrap(),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        );

        // Applying a RedactHeader to a non-HTTP envelope is a no-op.
        let mut envelope = envelope;
        ModificationSpec::RedactHeader("authorization".to_string()).apply(&mut envelope);

        let ActionParams::ToolUse(tool) = &envelope.intent.params else {
            panic!("expected ToolUse params");
        };
        assert_eq!(tool.tool_name, "search");
    }

    #[test]
    fn step_up_required_and_deferred_display_and_serde() {
        assert_eq!(DenyReason::StepUpRequired.to_string(), "step up required");
        assert_eq!(DenyReason::Deferred.to_string(), "deferred");
        for json in [r#""StepUpRequired""#, r#""Deferred""#] {
            let parsed: DenyReason = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(
                parsed,
                DenyReason::StepUpRequired | DenyReason::Deferred
            ));
        }
    }

    #[test]
    fn test_decision_serde_round_trip() {
        let decisions = [
            Decision::Allow,
            Decision::Deny {
                reason: DenyReason::ScopeViolation,
            },
            Decision::Abort {
                reason: "panic".to_string(),
            },
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).unwrap_or_else(|e| panic!("{e}"));
            let parsed: Decision = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(*d, parsed);
        }
    }

    #[test]
    fn test_decision_eq() {
        assert_eq!(Decision::Allow, Decision::Allow);
        assert_ne!(
            Decision::Allow,
            Decision::Deny {
                reason: DenyReason::PolicyDenied
            }
        );
    }

    #[test]
    fn test_deny_reason_is_display() {
        fn assert_display<T: Display>() {}
        assert_display::<DenyReason>();
    }

    #[test]
    fn test_abort_reason_is_display() {
        fn assert_display<T: Display>() {}
        assert_display::<AbortReason>();
    }

    #[test]
    fn decision_backward_compat_allow() {
        let json = r#""Allow""#;
        let parsed: Decision = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed, Decision::Allow);
    }

    #[test]
    fn decision_backward_compat_deny() {
        let json = r#"{"Deny":{"reason":"ScopeViolation"}}"#;
        let parsed: Decision = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed,
            Decision::Deny {
                reason: DenyReason::ScopeViolation,
            }
        );
    }

    #[test]
    fn decision_backward_compat_abort() {
        let json = r#"{"Abort":{"reason":"fatal"}}"#;
        let parsed: Decision = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed,
            Decision::Abort {
                reason: "fatal".to_string(),
            }
        );
    }

    #[test]
    fn deny_reason_backward_compat() {
        use strum::IntoEnumIterator;
        for reason in DenyReason::iter() {
            let json = match reason {
                DenyReason::TokenInvalid => r#""TokenInvalid""#,
                DenyReason::TokenExpired => r#""TokenExpired""#,
                DenyReason::TokenRevoked => r#""TokenRevoked""#,
                DenyReason::PolicyDenied => r#""PolicyDenied""#,
                DenyReason::ScopeViolation => r#""ScopeViolation""#,
                DenyReason::ToolNotInScope => r#""ToolNotInScope""#,
                DenyReason::MalformedRequest => r#""MalformedRequest""#,
                DenyReason::AuthorityUnavailable => r#""AuthorityUnavailable""#,
                DenyReason::PolicyBundleStale => r#""PolicyBundleStale""#,
                DenyReason::PolicyBundleNotReady => r#""PolicyBundleNotReady""#,
                DenyReason::RevocationCacheNotReady => r#""RevocationCacheNotReady""#,
                DenyReason::FailClosed => r#""FailClosed""#,
                DenyReason::EnforcementTimeout => r#""EnforcementTimeout""#,
                DenyReason::CredentialInjectionFailed => r#""CredentialInjectionFailed""#,
                DenyReason::ConnectorTimeout => r#""ConnectorTimeout""#,
                DenyReason::ConnectorNetworkError => r#""ConnectorNetworkError""#,
                DenyReason::ConnectorInvalidRequest => r#""ConnectorInvalidRequest""#,
                DenyReason::UnclassifiedIntent => r#""UnclassifiedIntent""#,
                DenyReason::TenantMismatch => r#""TenantMismatch""#,
                DenyReason::StepUpRequired => r#""StepUpRequired""#,
                DenyReason::Deferred => r#""Deferred""#,
            };
            let parsed: DenyReason = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(parsed, reason);
        }
    }
}
