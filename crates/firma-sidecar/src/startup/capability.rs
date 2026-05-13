//! Build the runtime [`CapabilityMap`] and [`TokenVerifier`] from the
//! sidecar's `[capability_seed]` and `[authority] public_key_path` config.
//!
//! Replaces the empty-default + stub-verifier wiring that lived inline in
//! [`crate::startup::pipeline`] until the gRPC `IssueCapability` client lands.

use std::path::Path;

use firma_core::token::paseto::PasetoV4Verifier;
use firma_core::{AgentId, CapabilityClaims, SessionId, TokenError, TokenId, TokenVerifier};

use crate::config::{CapabilitySeedConfig, SeedFile};
use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};

/// Read every seed file referenced by `seed.paths` and assemble a
/// fully-indexed [`CapabilityMap`].
///
/// # Errors
///
/// Returns an error when a seed file cannot be read, parsed, or
/// converted into a [`CapabilityClaims`] value.
pub fn load_capability_map(seed: &CapabilitySeedConfig) -> anyhow::Result<CapabilityMap> {
    let mut entries: Vec<CapabilityEntry> = Vec::with_capacity(seed.paths.len());
    for path in &seed.paths {
        let body = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("failed to read capability seed '{}': {e}", path.display())
        })?;
        let file: SeedFile = toml::from_str(&body).map_err(|e| {
            anyhow::anyhow!("failed to parse capability seed '{}': {e}", path.display())
        })?;
        entries.push(
            seed_into_entry(&file).map_err(|e| {
                anyhow::anyhow!("invalid capability seed '{}': {e}", path.display())
            })?,
        );
    }
    Ok(CapabilityMap::new(entries))
}

pub fn seed_into_entry(file: &SeedFile) -> Result<CapabilityEntry, String> {
    let token_id: TokenId = file
        .token_id
        .parse()
        .map_err(|e| format!("invalid token_id: {e}"))?;
    let agent_id: AgentId = file
        .agent_id
        .parse()
        .map_err(|e| format!("invalid agent_id: {e}"))?;
    let session_id: SessionId = file
        .session_id
        .parse()
        .map_err(|e| format!("invalid session_id: {e}"))?;

    Ok(CapabilityEntry {
        raw_token: file.raw_token.clone(),
        claims: CapabilityClaims {
            token_id,
            agent_id,
            session_id,
            action_set: file.action_set.clone(),
            resource_scope: file.resource_scope.clone(),
            issued_at: file.issued_at,
            expiry: file.expiry,
            context_hash: file.context_hash.clone(),
            budget_ceiling: file.budget_ceiling,
        },
    })
}

/// Build the Stage 1 token verifier.
///
/// Returns a [`PasetoV4Verifier`] when `public_key_path` is set,
/// otherwise returns a [`RejectAllVerifier`] so unconfigured
/// deployments continue to deny every protected call.
///
/// # Errors
///
/// Returns an error when the public-key file cannot be read or its
/// contents do not match the Ed25519 32-byte format.
pub fn build_token_verifier(
    public_key_path: Option<&Path>,
) -> anyhow::Result<Box<dyn TokenVerifier + Send + Sync>> {
    if let Some(path) = public_key_path {
        let bytes = std::fs::read(path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read authority public key '{}': {e}",
                path.display()
            )
        })?;
        // PASETO's verifier has its own clock-skew leeway (10s by default).
        // Stage 1 already applies `clock_skew_tolerance_seconds` from config,
        // so we zero out the verifier's leeway to keep that knob authoritative
        // — otherwise the hard-coded 10s caps any operator setting above it.
        let verifier = PasetoV4Verifier::try_new(&bytes)
            .map(|v| v.with_leeway(chrono::Duration::zero()))
            .map_err(|e| {
                anyhow::anyhow!("invalid authority public key '{}': {e}", path.display())
            })?;
        Ok(Box::new(verifier))
    } else {
        Ok(Box::new(RejectAllVerifier))
    }
}

/// Default verifier used when no public key is configured. Always
/// returns [`TokenError::SignatureInvalid`] so Stage 1 stays
/// fail-closed.
struct RejectAllVerifier;

impl TokenVerifier for RejectAllVerifier {
    fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
        Err(TokenError::SignatureInvalid {
            reason: "no authority public key configured".to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn empty_seed_yields_empty_map() {
        let seed = CapabilitySeedConfig::default();
        let map = load_capability_map(&seed).unwrap();
        // `CapabilityMap::select` returns `Err(EnforcementDecision)`
        // when no entry matches; the empty map must always deny.
        let result = map.select("sess", "communication.external.send", "wttr.in");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unreadable_path() {
        let seed = CapabilitySeedConfig {
            paths: vec![PathBuf::from("/definitely/not/here.toml")],
        };
        let err = load_capability_map(&seed).unwrap_err().to_string();
        assert!(err.contains("/definitely/not/here.toml"));
    }

    #[test]
    fn unconfigured_verifier_denies_every_token() {
        let verifier = build_token_verifier(None).unwrap();
        let err = verifier
            .verify("v4.public.anything")
            .expect_err("RejectAllVerifier must always deny");
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }
}
