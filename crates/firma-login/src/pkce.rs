use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{
    EntropyError, LoopbackCallbackListenerError, PendingAuthorizationAttempt,
    redirect::LoopbackCallbackListener,
};

const RANDOM_VALUE_BYTES: usize = 32;

/// A single authorization attempt, including its state and PKCE verifier.
///
/// The secret values are opaque: callers can forward their domain types to
/// later login-flow steps but cannot accidentally format or clone them.
pub struct AuthorizationAttempt {
    state: AuthorizationState,
    verifier: PkceVerifier,
    challenge: PkceChallenge,
}

impl AuthorizationAttempt {
    /// Start a new authorization attempt using independent random state and
    /// PKCE verifier values.
    ///
    /// # Errors
    ///
    /// Returns an error if system entropy cannot provide either random value.
    pub fn start() -> Result<Self, EntropyError> {
        let state = AuthorizationState(random_secret()?);
        let verifier = PkceVerifier(random_secret()?);
        let challenge = PkceChallenge(
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.0.expose_secret().as_bytes())),
        );

        Ok(Self {
            state,
            verifier,
            challenge,
        })
    }

    /// Return the opaque authorization state for this attempt.
    #[must_use]
    pub fn state(&self) -> &AuthorizationState {
        &self.state
    }

    /// Return the opaque PKCE verifier for this attempt.
    #[must_use]
    pub fn verifier(&self) -> &PkceVerifier {
        &self.verifier
    }

    pub(crate) fn into_verifier(self) -> PkceVerifier {
        self.verifier
    }

    /// Return the public PKCE S256 challenge for this attempt.
    #[must_use]
    pub fn pkce_challenge(&self) -> &PkceChallenge {
        &self.challenge
    }

    /// Bind the loopback callback for this attempt.
    ///
    /// The returned pending attempt retains the state, verifier, challenge, and
    /// listener as one capability. Callers can compose an authorization URL from
    /// its public inputs but cannot pair a callback with another attempt's
    /// verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the required IPv4 loopback listener cannot be bound.
    pub fn bind_loopback(
        self,
    ) -> Result<PendingAuthorizationAttempt, LoopbackCallbackListenerError> {
        let listener = LoopbackCallbackListener::bind()?;

        Ok(PendingAuthorizationAttempt::new(
            self.state,
            self.verifier,
            self.challenge,
            listener,
        ))
    }
}

/// An opaque CSRF state value for a single authorization attempt.
pub struct AuthorizationState(SecretString);

impl AuthorizationState {
    /// Return the state value for the authorization request query.
    ///
    /// This is intentionally the only raw-state presentation surface. A pending
    /// attempt retains the same state and validates the callback before exposing
    /// an authorization code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    /// Return whether two opaque authorization states are equal.
    #[must_use]
    pub fn matches(&self, received: &Self) -> bool {
        self.matches_callback(received.0.expose_secret())
    }

    /// Return whether this state matches a state received for the same attempt.
    ///
    /// This comparison stays crate-private because callback parsing owns the
    /// raw inbound string; [`Self::as_str`] is the intentional outbound
    /// presentation surface.
    #[must_use]
    pub(crate) fn matches_callback(&self, received: &str) -> bool {
        // Any local process can drive the loopback listener and time the reply,
        // so a byte-by-byte compare would leak the state one prefix at a time.
        // The length is public — it is fixed for every generated state — and
        // `ct_eq` needs equal lengths, so it is the one part compared early.
        let expected = self.0.expose_secret();
        expected.len() == received.len()
            && bool::from(expected.as_bytes().ct_eq(received.as_bytes()))
    }
}

/// An opaque PKCE verifier for a single authorization attempt.
pub struct PkceVerifier(SecretString);

impl PkceVerifier {
    /// Return the secret verifier for the token-exchange boundary.
    #[must_use]
    pub fn as_secret(&self) -> &SecretString {
        &self.0
    }
}

/// A public PKCE S256 challenge derived from a [`PkceVerifier`].
#[derive(Debug, PartialEq, Eq)]
pub struct PkceChallenge(String);

impl PkceChallenge {
    /// Return the URL-safe base64 encoded PKCE S256 challenge.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn random_secret() -> Result<SecretString, EntropyError> {
    let mut bytes = Zeroizing::new([0_u8; RANDOM_VALUE_BYTES]);
    getrandom::fill(&mut *bytes).map_err(EntropyError::System)?;

    Ok(SecretString::from(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}
