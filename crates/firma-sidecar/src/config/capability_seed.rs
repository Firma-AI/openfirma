//! `[sidecar.capability_seed]` configuration section.
//!
//! Each path names canonical [`firma_core::CapabilitySeed`] TOML, either issued
//! explicitly with `firma authority issue` or staged for a session by
//! `firma run`. Every verified seed contributes one `CapabilityEntry` to the
//! runtime `CapabilityMap`.

use std::path::PathBuf;

use firma_config_schema::sidecar::capability_seed::CapabilitySeedConfig as SchemaCapabilitySeedConfig;

pub use firma_core::CapabilitySeed as SeedFile;

/// Validated `[sidecar.capability_seed]` section.
#[derive(Debug, Clone)]
pub struct CapabilitySeedConfig {
    /// Paths to seed TOML files produced by `firma authority issue`.
    pub paths: Vec<PathBuf>,
    /// When `true` (default), the sidecar watches the seed file(s) and
    /// hot-swaps its `CapabilityMap` when they change.
    pub hot_reload: bool,
}

/// Error validating a [`CapabilitySeedConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilitySeedConfigError {
    /// A seed path entry was empty.
    #[error("capability_seed.paths[{index}] must not be empty")]
    EmptyPath {
        /// Index of the offending entry.
        index: usize,
    },
}

impl Default for CapabilitySeedConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            hot_reload: true,
        }
    }
}

impl TryFrom<SchemaCapabilitySeedConfig> for CapabilitySeedConfig {
    type Error = CapabilitySeedConfigError;

    fn try_from(schema: SchemaCapabilitySeedConfig) -> Result<Self, Self::Error> {
        for (index, path) in schema.paths.iter().enumerate() {
            if path.as_os_str().is_empty() {
                return Err(CapabilitySeedConfigError::EmptyPath { index });
            }
        }
        Ok(Self {
            paths: schema.paths,
            hot_reload: schema.hot_reload,
        })
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
        let schema = SchemaCapabilitySeedConfig {
            paths: vec![PathBuf::new()],
            hot_reload: true,
        };
        assert!(matches!(
            CapabilitySeedConfig::try_from(schema),
            Err(CapabilitySeedConfigError::EmptyPath { index: 0 })
        ));
    }

    #[test]
    fn default_is_empty_and_valid() {
        let cfg = CapabilitySeedConfig::default();
        assert!(cfg.paths.is_empty());
        assert!(cfg.hot_reload);
    }
}
