//! On-disk seed format produced by `firma authority issue` and consumed
//! by the sidecar's `[capability_seed]` config block.
//!
//! Mirrored by the sidecar-side reader at
//! `crates/firma-sidecar/src/config/capability_seed.rs::SeedFile`. The two
//! structs intentionally duplicate the schema to avoid an authority →
//! sidecar (or vice versa) crate dependency cycle; keep them in lockstep
//! when adding fields.

use anyhow::{Context as _, Result};
use serde::Serialize;

use crate::IssuanceResult;

#[derive(Debug, Serialize)]
pub struct SeedFile {
    pub raw_token: String,
    pub token_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub action_set: Vec<String>,
    pub resource_scope: String,
    pub issued_at: String,
    pub expiry: String,
    pub context_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ceiling: Option<f64>,
}

impl SeedFile {
    #[must_use]
    pub fn from_issuance(out: &IssuanceResult) -> Self {
        Self {
            raw_token: out.raw_token.clone(),
            token_id: out.claims.token_id.to_string(),
            agent_id: out.claims.agent_id.to_string(),
            session_id: out.claims.session_id.to_string(),
            action_set: out.claims.action_set.clone(),
            resource_scope: out.claims.resource_scope.clone(),
            issued_at: out.claims.issued_at.to_rfc3339(),
            expiry: out.claims.expiry.to_rfc3339(),
            context_hash: out.claims.context_hash.clone(),
            budget_ceiling: out.claims.budget_ceiling,
        }
    }

    /// Serialize as pretty-printed TOML.
    ///
    /// # Errors
    ///
    /// Returns an error if `toml::to_string_pretty` fails (should not
    /// happen for the static schema).
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("seed serialization failed")
    }
}
