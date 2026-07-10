//! On-disk seed format produced by `firma authority issue` and consumed
//! by the sidecar's `[capability_seed]` config block.
//!
//! Mirrored by the sidecar-side reader at
//! `crates/firma-sidecar/src/config/capability_seed.rs::SeedFile`. The two
//! structs intentionally duplicate the schema to avoid an authority →
//! sidecar (or vice versa) crate dependency cycle; keep them in lockstep
//! when adding fields.

use anyhow::{Context as _, Result};
use firma_core::CapabilityClaims;
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
        // deconstruct so we can get an error if `CapabilityClaims` changes
        let IssuanceResult {
            raw_token,
            claims:
                CapabilityClaims {
                    token_id,
                    agent_id,
                    session_id,
                    action_set,
                    resource_scope,
                    issued_at,
                    expiry,
                    context_hash,
                    budget_ceiling,
                },
        } = out;

        Self {
            raw_token: raw_token.clone(),
            token_id: token_id.to_string(),
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            action_set: action_set.clone(),
            resource_scope: resource_scope.clone(),
            issued_at: issued_at.to_rfc3339(),
            expiry: expiry.to_rfc3339(),
            context_hash: context_hash.clone(),
            budget_ceiling: *budget_ceiling,
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
