use crate::error::TokenError;
use crate::token::CapabilityClaims;
use crate::traits::{TokenSigner, TokenVerifier};

use chrono::{DateTime, Utc};
use pasetors::claims::Claims;
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};

/// PASETO v4.public token signer using Ed25519.
///
/// Implements [`TokenSigner`] by serializing [`CapabilityClaims`] into
/// a PASETO v4.public token signed with an Ed25519 private key.
#[derive(Debug)]
pub struct PasetoV4Signer {
    secret_key: AsymmetricSecretKey<V4>,
}

impl PasetoV4Signer {
    /// Construct from raw Ed25519 secret key bytes (64 bytes: 32-byte seed + 32-byte public key).
    ///
    /// # Errors
    ///
    /// Returns `TokenError::Malformed` if the key bytes are invalid or wrong length.
    pub fn new(secret_key_bytes: &[u8]) -> Result<Self, TokenError> {
        let secret_key = AsymmetricSecretKey::<V4>::from(secret_key_bytes).map_err(|e| {
            TokenError::Malformed {
                reason: format!("invalid private key: {e:?}"),
            }
        })?;
        Ok(Self { secret_key })
    }
}

impl TokenSigner for PasetoV4Signer {
    fn sign(&self, claims: &CapabilityClaims) -> Result<String, TokenError> {
        let paseto_claims = build_paseto_claims(claims)?;
        let claims_json = paseto_claims
            .to_string()
            .map_err(|e| TokenError::Malformed {
                reason: format!("claims serialization failed: {e:?}"),
            })?;
        PublicToken::sign(&self.secret_key, claims_json.as_bytes(), None, None).map_err(|e| {
            TokenError::Malformed {
                reason: format!("signing failed: {e:?}"),
            }
        })
    }
}

/// PASETO v4.public token verifier using Ed25519.
///
/// Implements [`TokenVerifier`] by verifying the Ed25519 signature,
/// checking expiration, and deserializing claims from the token payload.
#[derive(Debug)]
pub struct PasetoV4Verifier {
    public_key: AsymmetricPublicKey<V4>,
}

impl PasetoV4Verifier {
    /// Construct from raw Ed25519 public key bytes (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns `TokenError::Malformed` if the key bytes are invalid or wrong length.
    pub fn new(public_key_bytes: &[u8]) -> Result<Self, TokenError> {
        let public_key = AsymmetricPublicKey::<V4>::from(public_key_bytes).map_err(|e| {
            TokenError::Malformed {
                reason: format!("invalid public key: {e:?}"),
            }
        })?;
        Ok(Self { public_key })
    }
}

impl TokenVerifier for PasetoV4Verifier {
    fn verify(&self, raw_token: &str) -> Result<CapabilityClaims, TokenError> {
        // 1. Parse as PASETO v4.public token
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(raw_token)
            .map_err(|e| TokenError::ParseFailure {
                reason: format!("not a valid PASETO v4 token: {e:?}"),
            })?;

        // 2. Verify Ed25519 signature (low-level — no claims validation)
        let trusted =
            PublicToken::verify(&self.public_key, &untrusted, None, None).map_err(|e| {
                TokenError::SignatureInvalid {
                    reason: format!("PASETO signature verification failed: {e:?}"),
                }
            })?;

        // 3. Parse payload into claims
        let claims = Claims::from_string(trusted.payload()).map_err(|e| TokenError::Malformed {
            reason: format!("invalid claims payload: {e:?}"),
        })?;

        // 4. Extract all claims
        let capability_claims = extract_capability_claims(&claims)?;

        // 5. Check expiration
        if capability_claims.expires_at <= Utc::now() {
            return Err(TokenError::Expired {
                token_id: capability_claims.token_id,
            });
        }

        Ok(capability_claims)
    }
}

/// Build `pasetors::claims::Claims` from `CapabilityClaims`.
fn build_paseto_claims(claims: &CapabilityClaims) -> Result<Claims, TokenError> {
    let mut pc = Claims::new().map_err(|e| TokenError::Malformed {
        reason: format!("claims creation failed: {e:?}"),
    })?;

    // Override registered claims with our values
    pc.expiration(&claims.expires_at.to_rfc3339())
        .map_err(|e| TokenError::Malformed {
            reason: format!("set exp: {e:?}"),
        })?;
    pc.issued_at(&claims.issued_at.to_rfc3339())
        .map_err(|e| TokenError::Malformed {
            reason: format!("set iat: {e:?}"),
        })?;

    // Custom string claims
    pc.add_additional("token_id", claims.token_id.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add token_id: {e:?}"),
        })?;
    pc.add_additional("agent_id", claims.agent_id.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add agent_id: {e:?}"),
        })?;
    pc.add_additional("session_id", claims.session_id.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add session_id: {e:?}"),
        })?;
    pc.add_additional("context_hash", claims.context_hash.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add context_hash: {e:?}"),
        })?;

    // Array claims (serialize via serde_json)
    let actions_val = serde_json::to_value(&claims.actions).map_err(|e| TokenError::Malformed {
        reason: format!("serialize actions: {e}"),
    })?;
    pc.add_additional("actions", actions_val)
        .map_err(|e| TokenError::Malformed {
            reason: format!("add actions: {e:?}"),
        })?;

    let resources_val =
        serde_json::to_value(&claims.resources).map_err(|e| TokenError::Malformed {
            reason: format!("serialize resources: {e}"),
        })?;
    pc.add_additional("resources", resources_val)
        .map_err(|e| TokenError::Malformed {
            reason: format!("add resources: {e:?}"),
        })?;

    Ok(pc)
}

/// Extract a string claim from PASETO claims.
fn extract_string_claim(claims: &Claims, name: &str) -> Result<String, TokenError> {
    claims
        .get_claim(name)
        .and_then(serde_json::Value::as_str)
        .map(String::from)
        .ok_or_else(|| TokenError::Malformed {
            reason: format!("missing or invalid claim: {name}"),
        })
}

/// Extract a `Vec<String>` claim from PASETO claims.
fn extract_vec_claim(claims: &Claims, name: &str) -> Result<Vec<String>, TokenError> {
    let arr = claims
        .get_claim(name)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TokenError::Malformed {
            reason: format!("missing or invalid array claim: {name}"),
        })?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or_else(|| TokenError::Malformed {
                    reason: format!("non-string element in claim: {name}"),
                })
        })
        .collect()
}

/// Parse an RFC 3339 datetime claim from PASETO claims.
fn extract_datetime_claim(claims: &Claims, name: &str) -> Result<DateTime<Utc>, TokenError> {
    let s = claims
        .get_claim(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TokenError::Malformed {
            reason: format!("missing or invalid claim: {name}"),
        })?;
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| TokenError::Malformed {
            reason: format!("invalid datetime format for {name}: {e}"),
        })
}

/// Extract all fields from PASETO claims into `CapabilityClaims`.
fn extract_capability_claims(claims: &Claims) -> Result<CapabilityClaims, TokenError> {
    Ok(CapabilityClaims {
        token_id: extract_string_claim(claims, "token_id")?,
        agent_id: extract_string_claim(claims, "agent_id")?,
        session_id: extract_string_claim(claims, "session_id")?,
        actions: extract_vec_claim(claims, "actions")?,
        resources: extract_vec_claim(claims, "resources")?,
        issued_at: extract_datetime_claim(claims, "iat")?,
        expires_at: extract_datetime_claim(claims, "exp")?,
        context_hash: extract_string_claim(claims, "context_hash")?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use pasetors::keys::{AsymmetricKeyPair, Generate};

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
    }

    fn sample_claims(expires_in_secs: i64) -> CapabilityClaims {
        let now = Utc::now();
        CapabilityClaims {
            token_id: "tok_test_001".to_string(),
            agent_id: "agent_abc".to_string(),
            session_id: "sess_xyz".to_string(),
            actions: vec!["http:GET".to_string(), "tool:execute".to_string()],
            resources: vec!["https://api.example.com/*".to_string()],
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(expires_in_secs),
            context_hash: "abcdef1234567890".to_string(),
        }
    }

    // -- Story 001: PasetoV4Signer --

    #[test]
    fn test_sign_produces_v4_public_token() {
        let (sk, _pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn test_signer_as_dyn_token_signer() {
        let (sk, _pk) = generate_keypair();
        let signer: Box<dyn TokenSigner> = Box::new(PasetoV4Signer::new(&sk).unwrap());
        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn test_invalid_secret_key_bytes() {
        let result = PasetoV4Signer::new(&[0u8; 32]); // wrong size
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TokenError::Malformed { .. }));
    }

    // -- Story 002: PasetoV4Verifier --

    #[test]
    fn test_verifier_as_dyn_token_verifier() {
        let (_sk, pk) = generate_keypair();
        let _verifier: Box<dyn TokenVerifier> = Box::new(PasetoV4Verifier::new(&pk).unwrap());
    }

    #[test]
    fn test_invalid_public_key_bytes() {
        let result = PasetoV4Verifier::new(&[0u8; 16]); // wrong size
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::Malformed { .. }));
    }

    #[test]
    fn test_verify_malformed_string() {
        let (_sk, pk) = generate_keypair();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();
        let result = verifier.verify("not-a-paseto-token");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenError::ParseFailure { .. }
        ));
    }

    #[test]
    fn test_verify_empty_string() {
        let (_sk, pk) = generate_keypair();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();
        let result = verifier.verify("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenError::ParseFailure { .. }
        ));
    }

    // -- Story 003: Round-trip and rejection tests --

    #[test]
    fn test_round_trip_claims_match() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let original = sample_claims(600);
        let token = signer.sign(&original).unwrap();
        let recovered = verifier.verify(&token).unwrap();

        assert_eq!(recovered.token_id, original.token_id);
        assert_eq!(recovered.agent_id, original.agent_id);
        assert_eq!(recovered.session_id, original.session_id);
        assert_eq!(recovered.actions, original.actions);
        assert_eq!(recovered.resources, original.resources);
        assert_eq!(recovered.context_hash, original.context_hash);
        // DateTime comparison: within 1 second tolerance (RFC 3339 round-trip may lose sub-second)
        assert!(
            (recovered.issued_at - original.issued_at)
                .num_seconds()
                .abs()
                <= 1
        );
        assert!(
            (recovered.expires_at - original.expires_at)
                .num_seconds()
                .abs()
                <= 1
        );
    }

    #[test]
    fn test_expired_token_rejected() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let claims = sample_claims(-1); // expired 1 second ago
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, TokenError::Expired { ref token_id } if token_id == "tok_test_001"),
            "expected Expired with token_id, got: {err:?}"
        );
    }

    #[test]
    fn test_tampered_token_rejected() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();

        // Tamper by replacing a character near the end of the token (signature area)
        let mut chars: Vec<char> = token.chars().collect();
        let idx = chars.len() - 5;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();

        let result = verifier.verify(&tampered);
        assert!(result.is_err());
        // Could be SignatureInvalid or ParseFailure depending on where the tamper lands
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                TokenError::SignatureInvalid { .. } | TokenError::ParseFailure { .. }
            ),
            "expected SignatureInvalid or ParseFailure, got: {err:?}"
        );
    }

    #[test]
    fn test_wrong_public_key_rejected() {
        let (sk, _pk) = generate_keypair();
        let (_sk2, pk2) = generate_keypair(); // different key pair

        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk2).unwrap();

        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenError::SignatureInvalid { .. }
        ));
    }

    #[test]
    fn test_future_token_accepted() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let claims = sample_claims(600); // 10 minutes in the future
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_round_trip_empty_actions_resources() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let mut claims = sample_claims(600);
        claims.actions = vec![];
        claims.resources = vec![];

        let token = signer.sign(&claims).unwrap();
        let recovered = verifier.verify(&token).unwrap();
        assert!(recovered.actions.is_empty());
        assert!(recovered.resources.is_empty());
    }

    #[test]
    fn test_round_trip_unicode_agent_id() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let mut claims = sample_claims(600);
        claims.agent_id = "agent-\u{1F916}-bot".to_string(); // robot emoji

        let token = signer.sign(&claims).unwrap();
        let recovered = verifier.verify(&token).unwrap();
        assert_eq!(recovered.agent_id, "agent-\u{1F916}-bot");
    }

    #[test]
    fn test_verify_performance() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let verifier = PasetoV4Verifier::new(&pk).unwrap();

        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();

        // Warm up
        let _ = verifier.verify(&token).unwrap();

        let start = std::time::Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = verifier.verify(&token).unwrap();
        }
        let elapsed = start.elapsed();
        let per_op = elapsed / iterations;

        assert!(
            per_op.as_micros() < 500,
            "verify took {per_op:?} per op, expected < 500\u{00B5}s"
        );
    }

    #[test]
    fn test_sign_performance() {
        let (sk, _pk) = generate_keypair();
        let signer = PasetoV4Signer::new(&sk).unwrap();
        let claims = sample_claims(600);

        // Warm up
        let _ = signer.sign(&claims).unwrap();

        let start = std::time::Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = signer.sign(&claims).unwrap();
        }
        let elapsed = start.elapsed();
        let per_op = elapsed / iterations;

        assert!(
            per_op.as_micros() < 1000,
            "sign took {per_op:?} per op, expected < 1ms"
        );
    }
}
