use super::{CapabilityClaims, TokenError, TokenSigner, TokenVerifier};

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
    pub fn try_new(secret_key_bytes: &[u8]) -> Result<Self, TokenError> {
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
/// checking expiration with a configurable clock skew leeway, and
/// deserializing claims from the token payload.
///
/// The leeway absorbs NTP drift and scheduling jitter between the
/// Authority (issuer) and the Sidecar (verifier).
#[derive(Debug)]
pub struct PasetoV4Verifier {
    public_key: AsymmetricPublicKey<V4>,
    /// Leeway added to the token expiry before comparing with the current
    /// time. A token is rejected only when `expiry + leeway <= now`.
    leeway: chrono::Duration,
}

impl PasetoV4Verifier {
    /// Construct from raw Ed25519 public key bytes (32 bytes).
    ///
    /// Uses a default clock skew leeway of 10 seconds.
    ///
    /// # Errors
    ///
    /// Returns `TokenError::Malformed` if the key bytes are invalid or wrong length.
    pub fn try_new(public_key_bytes: &[u8]) -> Result<Self, TokenError> {
        let public_key = AsymmetricPublicKey::<V4>::from(public_key_bytes).map_err(|e| {
            TokenError::Malformed {
                reason: format!("invalid public key: {e:?}"),
            }
        })?;
        Ok(Self {
            public_key,
            leeway: chrono::Duration::seconds(10),
        })
    }

    /// Override the leeway applied during expiry validation.
    ///
    /// By default the verifier allows 10 seconds of leeway. Use this method
    /// to tighten or loosen that window for specific deployment contexts.
    #[must_use]
    pub fn with_leeway(mut self, leeway: chrono::Duration) -> Self {
        self.leeway = leeway;
        self
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

        // 5. Check expiration with clock skew leeway.
        // A token is denied only when expiry + leeway <= now, so a token
        // that expired up to `clock_skew` ago is still accepted.
        if capability_claims.expiry + self.leeway <= Utc::now() {
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
    let agent_id = claims.agent_id.to_string();

    // Override registered claims with our values
    pc.expiration(&claims.expiry.to_rfc3339())
        .map_err(|e| TokenError::Malformed {
            reason: format!("set exp: {e:?}"),
        })?;
    pc.issued_at(&claims.issued_at.to_rfc3339())
        .map_err(|e| TokenError::Malformed {
            reason: format!("set iat: {e:?}"),
        })?;

    // Custom string claims
    pc.add_additional("token_id", claims.token_id.to_string().as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add token_id: {e:?}"),
        })?;
    pc.add_additional("agent_id", agent_id.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add agent_id: {e:?}"),
        })?;
    pc.add_additional("session_id", claims.session_id.as_ref())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add session_id: {e:?}"),
        })?;
    pc.add_additional("context_hash", claims.context_hash.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add context_hash: {e:?}"),
        })?;
    pc.add_additional("resource_scope", claims.resource_scope.as_str())
        .map_err(|e| TokenError::Malformed {
            reason: format!("add resource_scope: {e:?}"),
        })?;

    // Array claims (serialize via serde_json)
    let action_set_val =
        serde_json::to_value(&claims.action_set).map_err(|e| TokenError::Malformed {
            reason: format!("serialize action_set: {e}"),
        })?;
    pc.add_additional("action_set", action_set_val)
        .map_err(|e| TokenError::Malformed {
            reason: format!("add action_set: {e:?}"),
        })?;

    Ok(pc)
}

/// Extract and parse a claim from PASETO claims into any `FromStr` type.
fn extract_claim<T>(claims: &Claims, name: &str) -> Result<T, TokenError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let s = claims
        .get_claim(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TokenError::Malformed {
            reason: format!("missing or invalid claim: {name}"),
        })?;
    s.parse::<T>().map_err(|e| TokenError::Malformed {
        reason: format!("invalid {name}: {e}"),
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
        token_id: extract_claim(claims, "token_id")?,
        agent_id: extract_claim(claims, "agent_id")?,
        session_id: extract_claim(claims, "session_id")?,
        action_set: extract_vec_claim(claims, "action_set")?,
        resource_scope: extract_claim(claims, "resource_scope")?,
        issued_at: extract_datetime_claim(claims, "iat")?,
        expiry: extract_datetime_claim(claims, "exp")?,
        context_hash: extract_claim(claims, "context_hash")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::token::TokenId;
    use pasetors::keys::{AsymmetricKeyPair, Generate};

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
    }

    fn sample_claims(expires_in_secs: i64) -> CapabilityClaims {
        let now = Utc::now();
        CapabilityClaims {
            token_id: TokenId::generate(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            session_id: "sess_xyz".parse().unwrap(),
            action_set: vec!["http:GET".to_string(), "tool:execute".to_string()],
            resource_scope: "https://api.example.com/*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::seconds(expires_in_secs),
            context_hash: "abcdef1234567890".to_string(),
        }
    }

    // -- Story 001: PasetoV4Signer --

    #[test]
    fn sign_produces_v4_public_token() {
        let (sk, _pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn signer_as_dyn_token_signer() {
        let (sk, _pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let claims = sample_claims(600);
        let token = signer.sign(&claims).unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn invalid_secret_key_bytes() {
        let result = PasetoV4Signer::try_new(&[0u8; 32]); // wrong size
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TokenError::Malformed { .. }));
    }

    // -- Story 002: PasetoV4Verifier --

    #[test]
    fn verifier_as_dyn_token_verifier() {
        let (_sk, pk) = generate_keypair();
        let _verifier: Box<dyn TokenVerifier> = Box::new(PasetoV4Verifier::try_new(&pk).unwrap());
    }

    #[test]
    fn invalid_public_key_bytes() {
        let result = PasetoV4Verifier::try_new(&[0u8; 16]); // wrong size
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::Malformed { .. }));
    }

    #[test]
    fn verify_malformed_string() {
        let (_sk, pk) = generate_keypair();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let result = verifier.verify("not-a-paseto-token");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenError::ParseFailure { .. }
        ));
    }

    #[test]
    fn verify_empty_string() {
        let (_sk, pk) = generate_keypair();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let result = verifier.verify("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenError::ParseFailure { .. }
        ));
    }

    // -- Story 003: Round-trip and rejection tests --

    #[test]
    fn round_trip_claims_match() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();

        let original = sample_claims(600);
        let token = signer.sign(&original).unwrap();
        let recovered = verifier.verify(&token).unwrap();

        assert_eq!(recovered, original);
    }

    #[test]
    fn expired_token_rejected() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();

        // Expired 30s ago — well outside the 10s default leeway.
        let claims = sample_claims(-30);
        let expected_token_id = claims.token_id;
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, TokenError::Expired { ref token_id } if token_id == &expected_token_id),
            "expected Expired with token_id, got: {err:?}"
        );
    }

    #[test]
    fn token_within_leeway_accepted() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();

        // Expired 5s ago — within the 10s default leeway.
        let claims = sample_claims(-5);
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);

        assert!(result.is_ok(), "token within leeway must be accepted");
    }

    #[test]
    fn token_within_default_leeway_rejected_when_leeway_zeroed() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        // Override leeway to zero — strict expiry enforcement.
        let verifier = PasetoV4Verifier::try_new(&pk)
            .unwrap()
            .with_leeway(chrono::Duration::zero());

        // Expired 5s ago — accepted by the default verifier but rejected here.
        let claims = sample_claims(-5);
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);

        assert!(
            result.is_err(),
            "token expired 5s ago must be rejected with zero leeway"
        );
        assert!(
            matches!(result.unwrap_err(), TokenError::Expired { .. }),
            "error must be Expired"
        );
    }

    #[test]
    fn tampered_token_rejected() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();

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
    fn wrong_public_key_rejected() {
        let (sk, _pk) = generate_keypair();
        let (_sk2, pk2) = generate_keypair(); // different key pair

        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk2).unwrap();

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
    fn future_token_accepted() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();

        let claims = sample_claims(600); // 10 minutes in the future
        let token = signer.sign(&claims).unwrap();
        let result = verifier.verify(&token);
        assert!(result.is_ok());
    }

    #[test]
    fn round_trip_empty_action_set() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();

        let mut claims = sample_claims(600);
        claims.action_set = vec![];

        let token = signer.sign(&claims).unwrap();
        let recovered = verifier.verify(&token).unwrap();
        assert!(recovered.action_set.is_empty());
    }
}
