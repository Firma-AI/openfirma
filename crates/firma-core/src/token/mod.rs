//! Capability token types and signing/verification traits.

pub mod paseto;

use chrono::{DateTime, Utc};
use firma_identifiers::{AgentId, SessionId, TokenId};
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
    Expired { token_id: TokenId },
    /// Token has been revoked.
    #[error("token revoked: {token_id}")]
    Revoked { token_id: TokenId },
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Globally unique identifier for this token. Used for revocation lookups.
    pub token_id: TokenId,
    /// Identity of the agent this token was issued to.
    pub agent_id: AgentId,
    /// Session within which this token is valid.
    pub session_id: SessionId,
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
#[cfg_attr(test, derive(strum::EnumIter))]
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
    fn is_revoked(&self, token_id: &TokenId) -> Result<bool, TokenError>;
    /// Record a token revocation.
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if the revocation cannot be recorded.
    fn add_revocation(&self, token_id: &TokenId) -> Result<(), TokenError>;
}

#[must_use]
pub fn matches_resource_scope(scope: &str, resource: &str) -> bool {
    if scope == "*" {
        return true;
    }
    if let Some(prefix) = scope.strip_suffix("/*") {
        return resource == prefix || starts_with_plus_slash(resource, prefix);
    }
    resource == scope || starts_with_plus_slash(resource, scope)
}

#[inline]
fn starts_with_plus_slash(resource: &str, scope: &str) -> bool {
    resource.len() > scope.len()
        && resource
            .chars()
            .zip(scope.chars().chain("/".chars()))
            .all(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pretty_assertions::assert_eq;

    #[test]
    fn claims_payload_without_budget_ceiling() {
        let json = r#"{
            "token_id":      "ctok_01j0000000e008000000000001",
            "agent_id":      "agt_01j0000000e008000000000001",
            "session_id":    "golden-sess",
            "action_set":    ["http:GET", "tool:execute"],
            "resource_scope":"https://api.example.com/*",
            "issued_at":     "2024-01-01T00:00:00Z",
            "expiry":        "2099-01-01T00:00:00Z",
            "context_hash":  "deadbeef1234567890abcdef"
        }"#;

        let claims: CapabilityClaims = serde_json::from_str(json).unwrap();

        let expected = CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001".parse().unwrap(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            session_id: "golden-sess".parse().unwrap(),
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

    #[test]
    fn resource_scope_prefix_rejects_different_host() {
        assert!(!matches_resource_scope(
            "api.example.com/*",
            "other.example.com/v1/data"
        ));
    }

    #[test]
    fn resource_scope_bare_host_matches_subpaths() {
        assert!(matches_resource_scope(
            "api.openai.com",
            "api.openai.com/v1/chat/completions"
        ));
        assert!(matches_resource_scope("api.openai.com", "api.openai.com"));
    }

    #[test]
    fn resource_scope_bare_host_rejects_different_host() {
        assert!(!matches_resource_scope(
            "api.openai.com",
            "other.example.com/v1/data"
        ));
    }

    #[test]
    fn resource_scope_exact_match() {
        assert!(matches_resource_scope(
            "api.example.com/v1/chat",
            "api.example.com/v1/chat"
        ));
        assert!(matches_resource_scope(
            "api.example.com/v1/chat",
            "api.example.com/v1/chat/completions"
        ));
    }

    #[test]
    fn resource_scope_different_path_denied() {
        assert!(!matches_resource_scope(
            "api.example.com/v1/chat",
            "api.example.com/v2/data"
        ));
    }

    #[test]
    fn resource_scope_prefix_does_not_match_similar_host() {
        assert!(!matches_resource_scope(
            "api.example.com/*",
            "api.example.community/v1/data"
        ));
        assert!(!matches_resource_scope(
            "api.example.com",
            "api.example.community/v1/data"
        ));
        assert!(!matches_resource_scope(
            "api.example.com/v1/chat",
            "api.example.community/v1/chat"
        ));
    }

    #[test]
    fn token_state_backward_compat() {
        use strum::IntoEnumIterator;
        for reason in TokenState::iter() {
            let parsed: TokenState = serde_json::from_str(match reason {
                TokenState::Issued => r#""Issued""#,
                TokenState::Active => r#""Active""#,
                TokenState::InUse => r#""InUse""#,
                TokenState::Expired => r#""Expired""#,
                TokenState::Revoked => r#""Revoked""#,
                TokenState::Aborted => r#""Aborted""#,
            })
            .unwrap();
            assert_eq!(parsed, reason);
        }
    }
}
