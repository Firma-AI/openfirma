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
use firma_identifiers::TokenId;
use serde::Serialize;

use crate::IssuanceResult;

#[derive(Debug, Serialize)]
pub struct SeedFile {
    raw_token: String,
    token_id: TokenId,
    agent_id: String,
    session_id: String,
    action_set: Vec<String>,
    resource_scope: String,
    issued_at: String,
    expiry: String,
    context_hash: String,
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
                },
        } = out;

        Self {
            raw_token: raw_token.clone(),
            token_id: *token_id,
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            action_set: action_set.clone(),
            resource_scope: resource_scope.clone(),
            issued_at: issued_at.to_rfc3339(),
            expiry: expiry.to_rfc3339(),
            context_hash: context_hash.clone(),
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
