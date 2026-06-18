//! Build the runtime [`CapabilityMap`] and [`TokenVerifier`] from the
//! sidecar's `[capability_seed]` and `[authority] public_key_path` config.
//!
//! Seeds are minted per session by `firma run` (via `IssueCapability`) and
//! written under the runtime capabilities directory; operator-configured
//! `[capability_seed]` paths are deprecated and warn at load time.

use std::path::Path;

use anyhow::Context;
use firma_core::token::paseto::PasetoV4Verifier;
use firma_core::{AgentId, CapabilityClaims, SessionId, TokenError, TokenId, TokenVerifier};

use crate::config::{CapabilitySeedConfig, SeedFile};
use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};

/// True when `path` is an operator-configured seed (NOT under the runtime
/// capabilities dir written by `firma run`), and therefore should emit the
/// `[capability_seed]` deprecation warning.
fn is_operator_seed(path: &Path, capabilities_dir: &Path) -> bool {
    !path.starts_with(capabilities_dir)
}

/// Read every seed file referenced by `seed.paths` and assemble a
/// fully-indexed [`CapabilityMap`].
///
/// Emits a deprecation warning for each seed path that is not under the
/// runtime capabilities directory written by `firma run`.
///
/// # Errors
///
/// Returns an error when a seed file cannot be read, parsed, converted
/// into a [`CapabilityClaims`] value, or when its `raw_token` fails
/// PASETO verification.
pub fn load_capability_map(
    seed: &CapabilitySeedConfig,
    verifier: &dyn TokenVerifier,
    capabilities_dir: &Path,
) -> anyhow::Result<CapabilityMap> {
    let mut entries: Vec<CapabilityEntry> = Vec::with_capacity(seed.paths.len());
    for path in &seed.paths {
        if is_operator_seed(path, capabilities_dir) {
            tracing::warn!(
                path = %path.display(),
                "[capability_seed] is deprecated; prefer per-session capabilities \
                 minted by `firma run` under the runtime capabilities directory"
            );
        }
        let body = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("failed to read capability seed '{}': {e}", path.display())
        })?;
        let file: SeedFile = toml::from_str(&body).map_err(|e| {
            anyhow::anyhow!("failed to parse capability seed '{}': {e}", path.display())
        })?;
        entries.push(
            seed_into_entry(&file, verifier).map_err(|e| {
                anyhow::anyhow!("invalid capability seed '{}': {e}", path.display())
            })?,
        );
    }
    Ok(CapabilityMap::new(entries))
}

/// Convert a parsed capability seed file into a runtime entry.
///
/// # Errors
///
/// Returns a descriptive error string when any identifier (token, agent, or
/// session) fails to parse or when the token fails verification.
pub fn seed_into_entry(
    file: &SeedFile,
    verifier: &dyn TokenVerifier,
) -> anyhow::Result<CapabilityEntry> {
    let seed_claims = seed_claims(file).context("invalid seed file")?;
    let verified_claims = verifier
        .verify(&file.raw_token)
        .context("raw_token failed PASETO verification")?;

    if seed_claims != verified_claims {
        anyhow::bail!("raw_token claims do not match seed claims");
    }

    Ok(CapabilityEntry {
        raw_token: file.raw_token.clone(),
        claims: verified_claims,
    })
}

fn seed_claims(file: &SeedFile) -> anyhow::Result<CapabilityClaims> {
    let token_id: TokenId = file.token_id.parse().context("invalid token_id")?;
    let agent_id: AgentId = file.agent_id.parse().context("invalid agent_id")?;
    let session_id: SessionId = file.session_id.parse().context("invalid session_id")?;

    Ok(CapabilityClaims {
        token_id,
        agent_id,
        session_id,
        action_set: file.action_set.clone(),
        resource_scope: file.resource_scope.clone(),
        issued_at: file.issued_at,
        expiry: file.expiry,
        context_hash: file.context_hash.clone(),
        budget_ceiling: file.budget_ceiling,
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
    use firma_core::TokenSigner;
    use firma_core::token::paseto::PasetoV4Signer;
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;
    use std::path::PathBuf;

    #[test]
    fn empty_seed_yields_empty_map() {
        let seed = CapabilitySeedConfig::default();
        let verifier = build_token_verifier(None).unwrap();
        let map = load_capability_map(
            &seed,
            verifier.as_ref(),
            Path::new("/run/firma/capabilities"),
        )
        .unwrap();
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
        let verifier = build_token_verifier(None).unwrap();
        let err = load_capability_map(
            &seed,
            verifier.as_ref(),
            Path::new("/run/firma/capabilities"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("/definitely/not/here.toml"));
    }

    #[test]
    fn runtime_dir_seed_is_not_flagged_operator() {
        let cap_dir = Path::new("/run/firma/capabilities");
        assert!(!is_operator_seed(
            Path::new("/run/firma/capabilities/abc.toml"),
            cap_dir
        ));
        assert!(is_operator_seed(Path::new("/etc/firma/seed.toml"), cap_dir));
    }

    #[test]
    fn unconfigured_verifier_denies_every_token() {
        let verifier = build_token_verifier(None).unwrap();
        let err = verifier
            .verify("v4.public.anything")
            .expect_err("RejectAllVerifier must always deny");
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn seed_load_rejects_unverified_raw_token() {
        let (_sk, pk) = generate_keypair();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let claims = sample_claims();
        let mut file = seed_file_from_claims(&claims);
        file.raw_token = "v4.public.not-a-real-token".to_string();

        let err = seed_into_entry(&file, &verifier).unwrap_err();

        assert!(
            err.to_string()
                .contains("raw_token failed PASETO verification")
        );
    }

    #[test]
    fn seed_load_rejects_claims_that_do_not_match_raw_token() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let claims = sample_claims();
        let raw_token = signer.sign(&claims).unwrap();
        let mut file = seed_file_from_claims(&claims);
        file.raw_token = raw_token;
        file.action_set = vec!["github.repo.write".to_string()];

        let err = seed_into_entry(&file, &verifier).unwrap_err();
        let err = err.to_string();

        assert!(err.contains("raw_token claims do not match seed claims"));
    }

    #[test]
    fn seed_load_uses_verified_token_claims() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let claims = sample_claims();
        let raw_token = signer.sign(&claims).unwrap();
        let mut file = seed_file_from_claims(&claims);
        file.raw_token = raw_token.clone();

        let entry = seed_into_entry(&file, &verifier).unwrap();

        assert_eq!(entry.raw_token, raw_token);
        assert_eq!(entry.claims, claims);
    }

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
    }

    fn sample_claims() -> CapabilityClaims {
        let now = chrono::Utc::now();
        CapabilityClaims {
            token_id: TokenId::new(),
            agent_id: "agent_abc".parse().unwrap(),
            session_id: "sess_xyz".parse().unwrap(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "https://api.example.com/*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::minutes(10),
            context_hash: "abcdef1234567890".to_string(),
            budget_ceiling: Some(10.0),
        }
    }

    fn seed_file_from_claims(claims: &CapabilityClaims) -> SeedFile {
        SeedFile {
            raw_token: String::new(),
            token_id: claims.token_id.to_string(),
            agent_id: claims.agent_id.to_string(),
            session_id: claims.session_id.to_string(),
            action_set: claims.action_set.clone(),
            resource_scope: claims.resource_scope.clone(),
            issued_at: claims.issued_at,
            expiry: claims.expiry,
            context_hash: claims.context_hash.clone(),
            budget_ceiling: claims.budget_ceiling,
        }
    }
}
