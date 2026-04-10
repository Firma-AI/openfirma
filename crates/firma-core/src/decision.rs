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
    use rstest::rstest;

    #[rstest]
    #[case(r#""Allow""#, Decision::Allow)]
    #[case(r#"{"Deny":{"reason":"ScopeViolation"}}"#, Decision::Deny { reason: DenyReason::ScopeViolation })]
    #[case(r#"{"Abort":{"reason":"fatal"}}"#, Decision::Abort { reason: "fatal".to_string() })]
    fn decision_backward_compat(#[case] json: &str, #[case] expected: Decision) {
        let parsed: Decision =
            serde_json::from_str(json).expect("backward compat broken: Decision format changed");
        assert_eq!(parsed, expected);
    }

    #[rstest]
    #[case(r#""TokenInvalid""#, DenyReason::TokenInvalid)]
    #[case(r#""TokenExpired""#, DenyReason::TokenExpired)]
    #[case(r#""TokenRevoked""#, DenyReason::TokenRevoked)]
    #[case(r#""PolicyDenied""#, DenyReason::PolicyDenied)]
    #[case(r#""ScopeViolation""#, DenyReason::ScopeViolation)]
    #[case(r#""ToolNotInScope""#, DenyReason::ToolNotInScope)]
    #[case(r#""MalformedRequest""#, DenyReason::MalformedRequest)]
    #[case(r#""AuthorityUnavailable""#, DenyReason::AuthorityUnavailable)]
    #[case(r#""PolicyBundleStale""#, DenyReason::PolicyBundleStale)]
    #[case(
        r#""CredentialInjectionFailed""#,
        DenyReason::CredentialInjectionFailed
    )]
    #[case(r#""ConnectorTimeout""#, DenyReason::ConnectorTimeout)]
    #[case(r#""UnclassifiedIntent""#, DenyReason::UnclassifiedIntent)]
    #[allow(clippy::expect_used)]
    fn deny_reason_backward_compat(#[case] json: &str, #[case] expected: DenyReason) {
        let parsed: DenyReason = serde_json::from_str(json)
            .expect("backward compat broken: DenyReason variant name changed");
        assert_eq!(parsed, expected);
    }
}
