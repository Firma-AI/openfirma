use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Payload of a signed capability token.
///
/// Represents the authority's grant to an agent for a scoped set of actions
/// and resources within a session. Carried inside a PASETO v4 or JWT token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Globally unique identifier for this token. Used for revocation lookups.
    pub token_id: String,
    /// Identity of the agent this token was issued to.
    pub agent_id: String,
    /// Session within which this token is valid.
    pub session_id: String,
    /// Allowed action set (e.g., `["http:GET", "tool:execute"]`). May be empty.
    pub actions: Vec<String>,
    /// Resource scope (e.g., `["https://api.example.com/*"]`). May be empty.
    pub resources: Vec<String>,
    /// When the Authority issued this token.
    pub issued_at: DateTime<Utc>,
    /// When this token expires. Validation enforced by `TokenVerifier`, not at construction.
    pub expires_at: DateTime<Utc>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_abc".to_string(),
            session_id: "sess_xyz".to_string(),
            actions: vec!["http:GET".to_string()],
            resources: vec!["https://api.example.com/*".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now(),
            context_hash: "abcdef1234567890".to_string(),
        }
    }

    #[test]
    fn test_capability_claims_construction() {
        let claims = sample_claims();
        assert_eq!(claims.token_id, "tok_001");
        assert_eq!(claims.agent_id, "agent_abc");
        assert_eq!(claims.session_id, "sess_xyz");
        assert_eq!(claims.actions.len(), 1);
        assert_eq!(claims.resources.len(), 1);
    }

    #[test]
    fn test_capability_claims_serde_round_trip() {
        let claims = sample_claims();
        let json = serde_json::to_string(&claims).unwrap_or_else(|e| panic!("{e}"));
        let parsed: CapabilityClaims =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(claims, parsed);
    }

    #[test]
    fn test_capability_claims_empty_actions_resources() {
        let claims = CapabilityClaims {
            actions: vec![],
            resources: vec![],
            ..sample_claims()
        };
        assert!(claims.actions.is_empty());
        assert!(claims.resources.is_empty());
    }

    #[test]
    fn test_capability_claims_debug_clone() {
        let claims = sample_claims();
        let cloned = claims.clone();
        assert_eq!(claims, cloned);
        let debug = format!("{claims:?}");
        assert!(debug.contains("tok_001"));
    }

    #[test]
    fn test_token_state_all_variants() {
        let states = [
            TokenState::Issued,
            TokenState::Active,
            TokenState::InUse,
            TokenState::Expired,
            TokenState::Revoked,
            TokenState::Aborted,
        ];
        assert_eq!(states.len(), 6);
    }

    #[test]
    fn test_token_state_copy_eq() {
        let state = TokenState::Active;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_token_state_serde_round_trip() {
        let state = TokenState::Revoked;
        let json = serde_json::to_string(&state).unwrap_or_else(|e| panic!("{e}"));
        let parsed: TokenState = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(state, parsed);
    }
}
