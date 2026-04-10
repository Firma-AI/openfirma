pub mod paseto;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Errors from token signing, verification, and revocation operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Token could not be parsed from the raw string.
    #[error("token parse failure: {reason}")]
    ParseFailure { reason: String },
    /// Token signature verification failed.
    #[error("token signature invalid: {reason}")]
    SignatureInvalid { reason: String },
    /// Token has expired.
    #[error("token expired: {token_id}")]
    Expired { token_id: String },
    /// Token has been revoked.
    #[error("token revoked: {token_id}")]
    Revoked { token_id: String },
    /// Token payload is malformed or missing required fields.
    #[error("token malformed: {reason}")]
    Malformed { reason: String },
}

/// Payload of a signed capability token.
///
/// Represents the authority's grant to an agent for a scoped set of actions
/// and resources within a session. Carried inside a PASETO v4 or JWT token.
///
/// Field names mirror the proto `CapabilityToken` message in `firma/v1/types.proto`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Globally unique identifier for this token. Used for revocation lookups.
    pub token_id: String,
    /// Identity of the agent this token was issued to.
    pub agent_id: String,
    /// Session within which this token is valid.
    pub session_id: String,
    /// Allowed action set (e.g., `["http:GET", "tool:execute"]`). May be empty.
    pub action_set: Vec<String>,
    /// Resource scope pattern this token covers (e.g., `"api.example.com/*"`).
    pub resource_scope: String,
    /// When the Authority issued this token.
    pub issued_at: DateTime<Utc>,
    /// When this token expires. Validation enforced by `TokenVerifier`, not at construction.
    pub expiry: DateTime<Utc>,
    /// Hex-encoded SHA-256 of the Cedar context snapshot at issuance time.
    pub context_hash: String,
}

/// Lifecycle state of a capability token.
///
/// Terminal states (`Expired`, `Revoked`, `Aborted`) cannot transition to any other state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenState {
    /// Token created by Authority, not yet delivered to agent.
    Issued,
    /// Token delivered to agent, available for use.
    Active,
    /// Token currently attached to an in-flight execution.
    InUse,
    /// Token TTL has elapsed. Terminal.
    Expired,
    /// Token explicitly revoked by Authority or policy. Terminal.
    Revoked,
    /// Token invalidated due to policy abort. Terminal.
    Aborted,
}

/// Serialize and cryptographically sign capability claims into a token string.
///
/// Format-agnostic — implementations choose the token format (PASETO v4, JWT, etc.).
/// All implementations must be object-safe for dynamic dispatch.
pub trait TokenSigner {
    /// Sign the given claims and return a serialized token string.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if signing fails (e.g., key unavailable, serialization error).
    fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError>;
}

/// Parse, verify signature, validate expiry, and return capability claims.
///
/// Format-agnostic — implementations choose the token format (PASETO v4, JWT, etc.).
/// All implementations must be object-safe for dynamic dispatch.
pub trait TokenVerifier {
    /// Verify a raw token string and return the validated claims.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the token is invalid, expired, revoked, or malformed.
    fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError>;
}

/// Check and record token revocations.
pub trait RevocationStore {
    /// Check if a token has been revoked by its ID.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the revocation store cannot be queried.
    fn is_revoked(&self, token_id: &str) -> Result<bool, TokenError>;
    /// Record a token revocation.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the revocation cannot be recorded.
    fn add_revocation(&self, token_id: &str) -> Result<(), TokenError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[test]
    fn claims_payload_backward_compat() {
        let json = r#"{
            "token_id":      "golden-tok-001",
            "agent_id":      "golden-agent",
            "session_id":    "golden-sess",
            "action_set":    ["http:GET", "tool:execute"],
            "resource_scope":"https://api.example.com/*",
            "issued_at":     "2024-01-01T00:00:00Z",
            "expiry":        "2099-01-01T00:00:00Z",
            "context_hash":  "deadbeef1234567890abcdef"
        }"#;

        let claims: CapabilityClaims = serde_json::from_str(json)
            .expect("backward compat broken: claims payload format changed");

        let expected = CapabilityClaims {
            token_id: "golden-tok-001".to_string(),
            agent_id: "golden-agent".to_string(),
            session_id: "golden-sess".to_string(),
            action_set: vec!["http:GET".to_string(), "tool:execute".to_string()],
            resource_scope: "https://api.example.com/*".to_string(),
            issued_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .expect("fixed date")
                .with_timezone(&Utc),
            expiry: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                .expect("fixed date")
                .with_timezone(&Utc),
            context_hash: "deadbeef1234567890abcdef".to_string(),
        };

        assert_eq!(claims, expected);
    }

    #[rstest]
    #[case(TokenState::Issued, r#""Issued""#)]
    #[case(TokenState::Active, r#""Active""#)]
    #[case(TokenState::InUse, r#""InUse""#)]
    #[case(TokenState::Expired, r#""Expired""#)]
    #[case(TokenState::Revoked, r#""Revoked""#)]
    #[case(TokenState::Aborted, r#""Aborted""#)]
    #[allow(clippy::expect_used)]
    fn token_state_backward_compat(#[case] state: TokenState, #[case] expected_json: &str) {
        let json = serde_json::to_string(&state).expect("serialization failed");
        assert_eq!(json, expected_json);
        let parsed: TokenState = serde_json::from_str(expected_json)
            .expect("backward compat broken: TokenState variant name changed");
        assert_eq!(parsed, state);
    }
}
