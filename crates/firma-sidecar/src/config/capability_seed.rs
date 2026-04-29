//! `[capability_seed]` configuration section.
//!
//! Static capability provisioning for the demo path. Until the
//! sidecar wires the gRPC `IssueCapability` client, operators can
//! pre-issue tokens via `firma-authority issue` and list the
//! resulting TOML files here. Each seed contributes one
//! `CapabilityEntry` to the runtime `CapabilityMap`.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// `[capability_seed]` TOML section.
///
/// Lists pre-issued capability seed files that the sidecar loads at
/// startup to pre-populate its `CapabilityMap`. Empty by default.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CapabilitySeedConfig {
    /// Paths to seed TOML files produced by `firma-authority issue`.
    /// Empty list means no static seeding (Stage 1 will deny every
    /// protected request).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

impl CapabilitySeedConfig {
    /// Validate the section.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the first invalid
    /// path entry.
    pub fn validate(&self) -> Result<(), String> {
        for (i, p) in self.paths.iter().enumerate() {
            if p.as_os_str().is_empty() {
                return Err(format!("paths[{i}] must not be empty"));
            }
        }
        Ok(())
    }
}

/// On-disk shape of a seed file. Mirrors the writer in
/// `crates/firma-authority/src/cli.rs` (`SeedFile`).
#[derive(Debug, Clone, Deserialize)]
pub struct SeedFile {
    /// Raw PASETO v4.public token string.
    pub raw_token: String,
    /// Token id (ULID/UUID) as written by the authority.
    pub token_id: String,
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
    /// Optional budget ceiling.
    #[serde(default)]
    pub budget_ceiling: Option<f64>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_seed_file() {
        let body = r#"
raw_token = "v4.public.eyJhbGciOiJFZERTQSJ9.test-payload.test-sig"
token_id = "01J0000000000000000000000Z"
agent_id = "demo-agent"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "wttr.in*"
issued_at = "2026-04-29T15:00:00Z"
expiry = "2026-04-29T16:00:00Z"
context_hash = "deadbeef"
"#;
        let parsed: SeedFile = toml::from_str(body).unwrap();
        assert_eq!(parsed.agent_id, "demo-agent");
        assert_eq!(parsed.action_set, vec!["communication.external.send"]);
        assert!(parsed.budget_ceiling.is_none());
        assert_eq!(parsed.issued_at.to_rfc3339(), "2026-04-29T15:00:00+00:00");
    }

    #[test]
    fn parses_seed_with_offset_timestamps() {
        // Authority's CLI writes `issued_at`/`expiry` via
        // `DateTime<Utc>::to_rfc3339()`, which renders the offset as
        // `+00:00` rather than `Z`. Make sure both spellings parse.
        let body = r#"
raw_token = "v4.public.test"
token_id = "01J0000000000000000000000Z"
agent_id = "demo-agent"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "*"
issued_at = "2026-04-29T15:00:00+00:00"
expiry = "2026-04-29T16:00:00+00:00"
context_hash = "cafebabe"
budget_ceiling = 1.5
"#;
        let parsed: SeedFile = toml::from_str(body).unwrap();
        assert_eq!(parsed.budget_ceiling, Some(1.5));
        assert_eq!(parsed.expiry.to_rfc3339(), "2026-04-29T16:00:00+00:00");
    }

    #[test]
    fn rejects_empty_path() {
        let cfg = CapabilitySeedConfig {
            paths: vec![PathBuf::new()],
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("paths[0]"));
    }

    #[test]
    fn default_is_empty_and_valid() {
        let cfg = CapabilitySeedConfig::default();
        assert!(cfg.paths.is_empty());
        assert!(cfg.validate().is_ok());
    }
}
