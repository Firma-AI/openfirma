use serde::{Deserialize, Serialize};

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
/// Deferred variants (add back when corresponding mechanisms exist):
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
    /// well-formed target request. Should be unreachable
    /// post-enforcement; treated as fail-closed.
    #[error("connector invalid request")]
    ConnectorInvalidRequest,
    /// Protected action could not be mapped to any canonical action class.
    #[error("unclassified intent")]
    UnclassifiedIntent,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
            };
            let parsed: DenyReason = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(parsed, reason);
        }
    }
}
