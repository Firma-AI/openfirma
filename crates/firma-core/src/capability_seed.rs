//! Canonical on-disk capability seed schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use firma_identifiers::TokenId;

use crate::CapabilityClaims;

/// On-disk shape of a capability seed file.
///
/// Written by `firma run` (and `firma authority issue`) and read by the
/// sidecar's `[sidecar.capability_seed]` loader. Plain-string mirror of the signed
/// [`CapabilityClaims`]; the `raw_token` is authoritative and re-verified at
/// load time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySeed {
    /// Raw PASETO v4.public token string.
    pub raw_token: String,
    /// Capability token ID as written by the Authority.
    pub token_id: TokenId,
    /// Agent identity bound into the token.
    pub agent_id: String,
    /// Session identity bound into the token.
    pub session_id: String,
    /// Action class set the token covers.
    pub action_set: Vec<String>,
    /// Resource scope pattern.
    pub resource_scope: String,
    /// Issuance timestamp (RFC3339).
    pub issued_at: DateTime<Utc>,
    /// Expiry timestamp (RFC3339).
    pub expiry: DateTime<Utc>,
    /// Hex-encoded context hash bound into the claims.
    pub context_hash: String,
}

impl CapabilitySeed {
    /// Build a seed from verified claims and the raw token that produced them.
    #[must_use]
    pub fn from_claims(claims: &CapabilityClaims, raw_token: String) -> Self {
        Self {
            raw_token,
            token_id: claims.token_id,
            agent_id: claims.agent_id.to_string(),
            session_id: claims.session_id.to_string(),
            action_set: claims.action_set.clone(),
            resource_scope: claims.resource_scope.clone(),
            issued_at: claims.issued_at,
            expiry: claims.expiry,
            context_hash: claims.context_hash.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample_claims() -> CapabilityClaims {
        let now = chrono::Utc::now();
        CapabilityClaims {
            token_id: TokenId::generate(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            session_id: "sess_xyz".parse().unwrap(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::minutes(15),
            context_hash: "deadbeef".to_string(),
        }
    }

    #[test]
    fn from_claims_preserves_token_id_then_toml_round_trip() {
        let claims = sample_claims();
        let seed = CapabilitySeed::from_claims(&claims, "v4.public.tok".to_string());
        assert_eq!(seed.token_id, claims.token_id);
        assert_eq!(seed.agent_id, claims.agent_id.to_string());
        assert_eq!(seed.session_id, claims.session_id.to_string());

        let text = toml::to_string(&seed).unwrap();
        let parsed: CapabilitySeed = toml::from_str(&text).unwrap();
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parses_offset_and_z_timestamps() {
        let body = r#"
raw_token = "v4.public.test"
token_id = "ctok_01j0000000e008000000000001"
agent_id = "agt_01j0000000e008000000000001"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "*"
issued_at = "2026-04-29T15:00:00+00:00"
expiry = "2026-04-29T16:00:00Z"
context_hash = "cafebabe"
"#;
        let parsed: CapabilitySeed = toml::from_str(body).unwrap();
        // Both `+00:00` and `Z` offsets must parse to the same instant.
        assert_eq!(
            parsed.issued_at,
            "2026-04-29T15:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            parsed.expiry,
            "2026-04-29T16:00:00+00:00"
                .parse::<DateTime<Utc>>()
                .unwrap()
        );
    }
}
