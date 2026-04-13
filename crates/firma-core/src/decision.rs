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
    /// Sidecar failed to inject credentials for Stage 3.
    #[error("credential injection failed")]
    CredentialInjectionFailed,
    /// Outbound connector timed out.
    #[error("connector timeout")]
    ConnectorTimeout,
    /// Protected action could not be mapped to any canonical action class.
    #[error("unclassified intent")]
    UnclassifiedIntent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn decision_backward_compat_allow() {
        let json = r#""Allow""#;
        let parsed: Decision = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, Decision::Allow);
    }

    #[test]
    fn decision_backward_compat_deny() {
        let json = r#"{"Deny":{"reason":"ScopeViolation"}}"#;
        let parsed: Decision = serde_json::from_str(json).unwrap();
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
        let parsed: Decision = serde_json::from_str(json).unwrap();
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
            let parsed: DenyReason = serde_json::from_str(match reason {
                DenyReason::TokenInvalid => r#""TokenInvalid""#,
                DenyReason::TokenExpired => r#""TokenExpired""#,
                DenyReason::TokenRevoked => r#""TokenRevoked""#,
                DenyReason::PolicyDenied => r#""PolicyDenied""#,
                DenyReason::ScopeViolation => r#""ScopeViolation""#,
                DenyReason::ToolNotInScope => r#""ToolNotInScope""#,
                DenyReason::MalformedRequest => r#""MalformedRequest""#,
                DenyReason::AuthorityUnavailable => r#""AuthorityUnavailable""#,
                DenyReason::PolicyBundleStale => r#""PolicyBundleStale""#,
                DenyReason::CredentialInjectionFailed => r#""CredentialInjectionFailed""#,
                DenyReason::ConnectorTimeout => r#""ConnectorTimeout""#,
                DenyReason::UnclassifiedIntent => r#""UnclassifiedIntent""#,
            })
            .unwrap();
            assert_eq!(parsed, reason);
        }
    }
}
