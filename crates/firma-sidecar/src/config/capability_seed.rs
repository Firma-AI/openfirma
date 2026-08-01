//! `[capability_seed]` configuration section.
//!
//! Deprecated operator-seed input. Per-session capabilities are now minted
//! live by `firma run` (via `IssueCapability`) and written under the runtime
//! capabilities directory, which the sidecar loads through this same path.
//! Operator-configured seeds — tokens pre-issued via `firma-authority issue`
//! and listed here — still load but emit a deprecation warning at startup.
//! Each seed contributes one `CapabilityEntry` to the runtime `CapabilityMap`.

use std::path::PathBuf;

pub use firma_core::CapabilitySeed as SeedFile;

/// `[capability_seed]` TOML section.
///
/// Lists pre-issued capability seed files that the sidecar loads at
/// startup to pre-populate its `CapabilityMap`. Empty by default.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CapabilitySeedConfig {
    /// Paths to seed TOML files produced by `firma-authority issue`.
    /// Empty list means no static seeding (Stage 1 will deny every
    /// protected request).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// When `true` (default), the sidecar watches the seed file(s) and hot-swaps
    /// its `CapabilityMap` when they change, so a token re-minted by `firma run`
    /// is picked up without a restart. Set `false` to pin the map loaded at
    /// startup.
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
}

/// Default for [`CapabilitySeedConfig::hot_reload`].
const fn default_hot_reload() -> bool {
    true
}

impl Default for CapabilitySeedConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            hot_reload: default_hot_reload(),
        }
    }
}

impl CapabilitySeedConfig {
    /// Validate the section.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the first invalid
    /// path entry.
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (i, p) in self.paths.iter().enumerate() {
            if p.as_os_str().is_empty() {
                return Err(format!("paths[{i}] must not be empty"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_seed_file() {
        let body = r#"
raw_token = "v4.public.eyJhbGciOiJFZERTQSJ9.test-payload.test-sig"
token_id = "ctok_01j0000000e008000000000001"
agent_id = "agt_01j0000000e008000000000001"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "wttr.in*"
issued_at = "2026-04-29T15:00:00Z"
expiry = "2026-04-29T16:00:00Z"
context_hash = "deadbeef"
"#;
        let parsed: SeedFile = toml::from_str(body).unwrap();
        assert_eq!(parsed.agent_id, "agt_01j0000000e008000000000001");
        assert_eq!(parsed.action_set, vec!["communication.external.send"]);
        assert_eq!(parsed.issued_at.to_rfc3339(), "2026-04-29T15:00:00+00:00");
    }

    #[test]
    fn parses_seed_with_offset_timestamps() {
        // Authority's CLI writes `issued_at`/`expiry` via
        // `DateTime<Utc>::to_rfc3339()`, which renders the offset as
        // `+00:00` rather than `Z`. Make sure both spellings parse.
        let body = r#"
raw_token = "v4.public.test"
token_id = "ctok_01j0000000e008000000000001"
agent_id = "agt_01j0000000e008000000000001"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "*"
issued_at = "2026-04-29T15:00:00+00:00"
expiry = "2026-04-29T16:00:00+00:00"
context_hash = "cafebabe"
"#;
        let parsed: SeedFile = toml::from_str(body).unwrap();
        assert_eq!(parsed.expiry.to_rfc3339(), "2026-04-29T16:00:00+00:00");
    }

    #[test]
    fn rejects_empty_path() {
        let cfg = CapabilitySeedConfig {
            paths: vec![PathBuf::new()],
            hot_reload: true,
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
