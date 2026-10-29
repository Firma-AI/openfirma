//! Client side of the native `firma login` OAuth 2.0 exchange.
//!
//! The access token is opaque to this crate: it is kept as a secret and sent
//! back unchanged, never decoded.

use std::time::Duration;

use firma_identifiers::{MembershipId, WorkspaceId};
use reqwest::{Client, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AuthorizationAttempt, CallbackLanding, CallbackWaitTimeout, CompletedAuthorizationAttempt,
    ControlPlaneOrigin, LoginRefusal, LoopbackCallbackError, MAX_AUTHORIZATION_CODE_BYTES,
    PendingAuthorizationAttempt, PkceVerifier,
};

/// OAuth public-client identifier this CLI presents to the Authority.
const CLIENT_ID: &str = "firma-cli";
const AUTHORIZE_PATH: &str = "/agent-flow/authorizations/authorize";
const TOKEN_PATH: &str = "/api/agent-flow/v1/authorizations/token";
const REVOKE_PATH: &str = "/api/agent-flow/v1/authorizations/revoke";
const MAX_TOKEN_RESPONSE_BYTES: usize = 4 * 1024;
/// Carries one RFC 8941 String with the UUID of a request that may be
/// replayed.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
/// Terminal delivery has no listener: the Authority shows the code in the
/// page and never sends the browser here. Port 9 (discard) only keeps the URI
/// inert if it were ever followed.
const TERMINAL_REDIRECT: &str = "http://127.0.0.1:9/callback";
/// Bounds for one token or current-Workspace request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CURRENT_PATH: &str = "/api/agent-flow/v1/sessions/workspace/current";

/// Whether an authorization may issue a renewable credential.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthorizationScope {
    /// Request only the short-lived access credential.
    #[default]
    AccessOnly,
    /// Request an `offline_access` refresh credential.
    OfflineAccess,
}

/// One UUID v4 reused for all network attempts of one request the Control
/// Plane may replay: a refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdempotencyKey(Uuid);

impl IdempotencyKey {
    /// Creates a fresh key for one transition.
    ///
    /// # Errors
    /// Returns an entropy error if secure operating-system randomness is unavailable.
    pub fn generate() -> Result<Self, crate::EntropyError> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(crate::EntropyError::System)?;
        Ok(Self(uuid::Builder::from_random_bytes(bytes).into_uuid()))
    }

    /// The [`IDEMPOTENCY_KEY_HEADER`] value: an RFC 8941 String, the UUID
    /// between double quotes.
    fn header_value(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

/// Whether a keyed request may be sent again after this status: the Control
/// Plane was busy or failed, not refusing.
pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504)
}

/// An authorization URL coupled to the only listener that can complete it.
pub struct AuthorizationRequest {
    url: Url,
    pending: PendingAuthorizationAttempt,
    scope: AuthorizationScope,
    landing: CallbackLanding,
}

impl AuthorizationRequest {
    /// Compose an authorization request with the selected scope.
    #[must_use]
    pub fn with_scope(
        origin: &ControlPlaneOrigin,
        pending: PendingAuthorizationAttempt,
        scope: AuthorizationScope,
    ) -> Self {
        let mut url = endpoint(origin, AUTHORIZE_PATH);
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", CLIENT_ID)
            .append_pair("redirect_uri", pending.redirect_uri().as_url().as_str())
            .append_pair("state", pending.state_parameter())
            .append_pair("code_challenge", pending.pkce_challenge().as_str())
            .append_pair("code_challenge_method", "S256");
        if scope == AuthorizationScope::OfflineAccess {
            url.query_pairs_mut().append_pair("scope", "offline_access");
        }
        let landing = CallbackLanding::on(origin);
        Self {
            url,
            pending,
            scope,
            landing,
        }
    }

    /// URL to give to the browser. It contains state and must not enter logs.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// Receive the browser callback and keep its original redirect URI paired
    /// with the resulting code and verifier.
    ///
    /// # Errors
    /// Returns an error if the callback is rejected, fails, or exceeds its deadline.
    pub async fn receive(
        self,
        timeout: CallbackWaitTimeout,
    ) -> Result<AuthorizedTokenExchange, LoopbackCallbackError> {
        let redirect_uri = self.pending.redirect_uri().as_url().as_str().to_owned();
        let completed = self.pending.receive(timeout, self.landing).await?;
        Ok(AuthorizedTokenExchange {
            redirect_uri,
            proof: AuthorizationProof::Loopback(completed),
            scope: self.scope,
        })
    }

    /// Exact redirect URI retained for the token exchange.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        self.pending.redirect_uri().as_url()
    }
}

/// A callback result that cannot lose its original redirect URI.
pub struct AuthorizedTokenExchange {
    /// Exact `redirect_uri` text for the token form; the Authority compares it
    /// byte for byte, so it is never re-parsed on this side.
    redirect_uri: String,
    proof: AuthorizationProof,
    scope: AuthorizationScope,
}

enum AuthorizationProof {
    Loopback(CompletedAuthorizationAttempt),
    Terminal {
        code: SecretString,
        verifier: PkceVerifier,
    },
}

/// One terminal-code attempt using the original PKCE verifier without a listener.
pub struct TerminalAuthorizationRequest {
    url: Url,
    attempt: AuthorizationAttempt,
    scope: AuthorizationScope,
}

impl TerminalAuthorizationRequest {
    /// Compose the terminal request with the selected scope.
    #[must_use]
    pub fn with_scope(
        origin: &ControlPlaneOrigin,
        attempt: AuthorizationAttempt,
        scope: AuthorizationScope,
    ) -> Self {
        let mut url = endpoint(origin, AUTHORIZE_PATH);
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", CLIENT_ID)
            .append_pair("redirect_uri", TERMINAL_REDIRECT)
            .append_pair("state", attempt.state().as_str())
            .append_pair("code_challenge", attempt.pkce_challenge().as_str())
            .append_pair("code_challenge_method", "S256");
        if scope == AuthorizationScope::OfflineAccess {
            url.query_pairs_mut().append_pair("scope", "offline_access");
        }
        Self {
            url,
            attempt,
            scope,
        }
    }

    /// Browser URL containing the per-attempt state.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// Pair a canonical one-time code with this attempt's original verifier.
    ///
    /// The `state` sent in the authorize URL is not checked here. It protects a
    /// callback listener against a forged redirect, and terminal delivery has no
    /// listener: the person pastes the code themselves. The code is bound to
    /// this attempt by PKCE, which the Authority verifies at exchange. It is
    /// still sent because the authorize request has one shape for both modes.
    ///
    /// # Errors
    /// Rejects text that cannot be a pasted code at all.
    pub fn complete(self, code: &str) -> Result<AuthorizedTokenExchange, NativeTokenError> {
        // Copying from a browser often picks up surrounding whitespace.
        let code = code.trim();
        // The Authority owns the code format and rejects a wrong one itself.
        // Checking its exact shape here would make an older CLI refuse a valid
        // code locally, with a misleading error, as soon as that format changes.
        // Only refuse what no pasted code can be.
        if code.is_empty()
            || code.len() > MAX_AUTHORIZATION_CODE_BYTES
            || !code.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(NativeTokenError::InvalidCode);
        }
        let redirect_uri = TERMINAL_REDIRECT.to_owned();
        Ok(AuthorizedTokenExchange {
            redirect_uri,
            proof: AuthorizationProof::Terminal {
                code: SecretString::from(code.to_owned()),
                verifier: self.attempt.into_verifier(),
            },
            scope: self.scope,
        })
    }
}

/// The result of one token exchange. The access token is never formatted or
/// serialized.
pub struct NativeAccessGrant {
    /// Workspace the approval selected.
    pub workspace_id: WorkspaceId,
    /// Membership the approval selected.
    pub membership_id: MembershipId,
    expires_in: Duration,
    access_token: SecretString,
    refresh_token: Option<SecretString>,
}

impl NativeAccessGrant {
    pub(super) fn into_session_parts(
        self,
    ) -> Result<
        (
            SecretString,
            SecretString,
            Duration,
            WorkspaceId,
            MembershipId,
        ),
        NativeTokenError,
    > {
        let refresh_token = self
            .refresh_token
            .ok_or(NativeTokenError::InvalidResponse)?;
        Ok((
            self.access_token,
            refresh_token,
            self.expires_in,
            self.workspace_id,
            self.membership_id,
        ))
    }
}

/// Result of the first authenticated Workspace request.
pub struct AuthenticatedConnection {
    /// Workspace the access token is bound to.
    pub workspace_id: WorkspaceId,
    /// Membership the access token is bound to.
    pub membership_id: MembershipId,
    access_token: SecretString,
    refresh_token: Option<SecretString>,
}

impl AuthenticatedConnection {
    /// The access token, still wrapped so `Debug` stays redacted.
    ///
    /// Callers expose it with [`ExposeSecret::expose_secret`](secrecy::ExposeSecret::expose_secret)
    /// at the point they send it, and
    /// nowhere earlier.
    #[must_use]
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Moves the renewable credential out after identity proof succeeds.
    #[must_use]
    pub fn into_refresh_token(self) -> Option<SecretString> {
        self.refresh_token
    }
}

// Success responses are parsed leniently: the server may add fields over time
// (RFC 6749 section 5.1), and a client that rejects them would break on every
// additive change.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    workspace_id: WorkspaceId,
    membership_id: MembershipId,
    expires_in: i64,
}

#[derive(Deserialize)]
struct RefreshTokenResponse {
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct WorkspaceResponse {
    workspace_id: WorkspaceId,
    membership_id: MembershipId,
}

/// The HTTP client for requests to `origin`: no redirects, bounded
/// timeouts, and no environment proxy for a plain-HTTP loopback origin.
pub fn control_plane_http(origin: &ControlPlaneOrigin) -> Result<Client, reqwest::Error> {
    // An error here means another provider is already installed for this
    // process, which is the outcome this call wants. Nothing is lost, so
    // there is no error worth logging.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut http = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    // Plain HTTP is only allowed to a loopback Control Plane: never send
    // its code, verifier, or token in clear through an environment proxy.
    if origin.as_url().scheme() == "http" {
        http = http.no_proxy();
    }
    http.build()
}

/// A bounded, redirect rejecting token transport for one PKCE exchange.
pub struct NativeTokenClient {
    http: Client,
    endpoint: Url,
    current_endpoint: Url,
    revoke_endpoint: Url,
}

impl NativeTokenClient {
    /// Construct the transport from the validated Control Plane origin.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(origin: &ControlPlaneOrigin) -> Result<Self, NativeTokenError> {
        let http = control_plane_http(origin).map_err(NativeTokenError::Transport)?;
        let token_endpoint = endpoint(origin, TOKEN_PATH);
        let current_endpoint = endpoint(origin, CURRENT_PATH);
        let revoke_endpoint = endpoint(origin, REVOKE_PATH);
        Ok(Self {
            http,
            endpoint: token_endpoint,
            current_endpoint,
            revoke_endpoint,
        })
    }

    /// Exchange one completed callback, without retrying an uncertain request.
    ///
    /// # Errors
    /// Returns a redacted error for transport, provider, or response failures.
    pub async fn exchange(
        &self,
        exchange: AuthorizedTokenExchange,
    ) -> Result<NativeAccessGrant, NativeTokenError> {
        let (code, verifier) = match &exchange.proof {
            AuthorizationProof::Loopback(completed) => (
                completed.authorization_code().as_secret().expose_secret(),
                completed.pkce_verifier().as_secret().expose_secret(),
            ),
            AuthorizationProof::Terminal { code, verifier } => {
                (code.expose_secret(), verifier.as_secret().expose_secret())
            }
        };
        let form = [
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", &exchange.redirect_uri),
        ];
        let response = self
            .http
            .post(self.endpoint.clone())
            .form(&form)
            .send()
            .await
            .map_err(NativeTokenError::Transport)?;
        let body = bounded_json_body(response).await?;
        let refresh_token = serde_json::from_slice::<RefreshTokenResponse>(&body)
            .map_err(|_| NativeTokenError::InvalidResponse)?
            .refresh_token
            .map(Zeroizing::new);
        if exchange.scope == AuthorizationScope::AccessOnly
            && let Some(token) = refresh_token.as_ref().filter(|token| !token.is_empty())
        {
            return Err(self
                .failure_after_revocation(
                    NativeTokenError::InvalidResponse,
                    &SecretString::from(token.as_str()),
                )
                .await);
        }
        let response: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| NativeTokenError::InvalidResponse)?;
        // Zeroed on drop, including when the checks below reject it.
        let access_token = Zeroizing::new(response.access_token);
        // RFC 6749 section 7.1: a client must not use a token whose type it
        // does not understand. The type name is case-insensitive.
        if access_token.is_empty()
            || refresh_token.as_ref().is_some_and(|token| token.is_empty())
            || response.expires_in <= 0
            || !response.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(NativeTokenError::InvalidResponse);
        }
        let grant = NativeAccessGrant {
            workspace_id: response.workspace_id,
            membership_id: response.membership_id,
            expires_in: Duration::from_secs(
                u64::try_from(response.expires_in)
                    .map_err(|_| NativeTokenError::InvalidResponse)?,
            ),
            access_token: SecretString::from(access_token.as_str()),
            refresh_token: refresh_token.map(|token| SecretString::from(token.as_str())),
        };
        if exchange.scope == AuthorizationScope::OfflineAccess && grant.refresh_token.is_none() {
            return Err(NativeTokenError::InvalidResponse);
        }
        Ok(grant)
    }

    /// Rotates one renewable credential with one caller-owned retry key.
    ///
    /// # Errors
    /// Returns a redacted transport, refusal, or malformed-response error.
    pub(crate) async fn refresh(
        &self,
        token: &SecretString,
        key: IdempotencyKey,
    ) -> Result<NativeAccessGrant, NativeTokenError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", token.expose_secret()),
        ];
        let response = self
            .http
            .post(self.endpoint.clone())
            .header(IDEMPOTENCY_KEY_HEADER, key.header_value())
            .form(&form)
            .send()
            .await
            .map_err(NativeTokenError::Transport)?;
        let body = bounded_json_body(response).await?;
        let refresh_token = serde_json::from_slice::<RefreshTokenResponse>(&body)
            .map_err(|_| NativeTokenError::InvalidResponse)?
            .refresh_token
            .map(Zeroizing::new);
        let response: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| NativeTokenError::InvalidResponse)?;
        let access_token = Zeroizing::new(response.access_token);
        if access_token.is_empty()
            || refresh_token.as_ref().is_none_or(|token| token.is_empty())
            || response.expires_in <= 0
            || !response.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(NativeTokenError::InvalidResponse);
        }
        Ok(NativeAccessGrant {
            workspace_id: response.workspace_id,
            membership_id: response.membership_id,
            expires_in: Duration::from_secs(
                u64::try_from(response.expires_in)
                    .map_err(|_| NativeTokenError::InvalidResponse)?,
            ),
            access_token: SecretString::from(access_token.as_str()),
            refresh_token: refresh_token.map(|token| SecretString::from(token.as_str())),
        })
    }

    /// Revokes one renewable family. Unknown and already-revoked tokens are
    /// successful, as required by RFC 7009.
    ///
    /// # Errors
    /// Returns a redacted transport or protocol error when revocation cannot
    /// be confirmed.
    pub async fn revoke(&self, token: &SecretString) -> Result<(), NativeTokenError> {
        let form = [
            ("client_id", CLIENT_ID),
            ("token", token.expose_secret()),
            ("token_type_hint", "refresh_token"),
        ];
        let response = self
            .http
            .post(self.revoke_endpoint.clone())
            .form(&form)
            .send()
            .await
            .map_err(NativeTokenError::Transport)?;
        let status = response.status();
        if status == reqwest::StatusCode::OK {
            return Ok(());
        }
        if status.is_client_error() || status.is_server_error() {
            return Err(oauth_refusal(response).await.map_or(
                NativeTokenError::Rejected(status),
                NativeTokenError::Refused,
            ));
        }
        Err(NativeTokenError::Rejected(status))
    }

    /// Make the first protected Workspace request and check it reports the
    /// Workspace and Membership the exchange delivered.
    ///
    /// # Errors
    /// Returns a redacted error for transport, rejection, or a response that
    /// names another Workspace or Membership. Nothing is retried.
    pub async fn prove(
        &self,
        grant: NativeAccessGrant,
    ) -> Result<AuthenticatedConnection, NativeTokenError> {
        let current = self
            .http
            .get(self.current_endpoint.clone())
            .bearer_auth(grant.access_token.expose_secret())
            .send()
            .await;
        let proof = match current {
            Ok(response) => bounded_json::<WorkspaceResponse>(response)
                .await
                .and_then(|current| {
                    if current.workspace_id == grant.workspace_id
                        && current.membership_id == grant.membership_id
                    {
                        Ok(())
                    } else {
                        Err(NativeTokenError::InvalidResponse)
                    }
                }),
            Err(error) => Err(NativeTokenError::Transport(error)),
        };
        if let Err(error) = proof {
            return Err(match grant.refresh_token.as_ref() {
                Some(token) => self.failure_after_revocation(error, token).await,
                None => error,
            });
        }
        Ok(AuthenticatedConnection {
            workspace_id: grant.workspace_id,
            membership_id: grant.membership_id,
            access_token: grant.access_token,
            refresh_token: grant.refresh_token,
        })
    }

    async fn failure_after_revocation(
        &self,
        failure: NativeTokenError,
        token: &SecretString,
    ) -> NativeTokenError {
        match self.revoke(token).await {
            Ok(()) => failure,
            Err(revocation) => NativeTokenError::FailureAndRevocationUnconfirmed {
                failure: Box::new(failure),
                revocation: Box::new(revocation),
            },
        }
    }
}

async fn bounded_json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, NativeTokenError> {
    let body = bounded_json_body(response).await?;
    serde_json::from_slice(&body).map_err(|_| NativeTokenError::InvalidResponse)
}

pub async fn bounded_json_body(
    response: reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>, NativeTokenError> {
    let status = response.status();
    // The Authority puts an OAuth `error` code in a JSON body whatever the
    // status: RFC 6749 section 5.2 `invalid_grant` with 400, `server_error`
    // with 500, and the RFC 6750 `invalid_token` of its `WWW-Authenticate`
    // challenge with 401.
    if status.is_client_error() || status.is_server_error() {
        return Err(oauth_refusal(response).await.map_or(
            NativeTokenError::Rejected(status),
            NativeTokenError::Refused,
        ));
    }
    if status != reqwest::StatusCode::OK {
        return Err(NativeTokenError::Rejected(status));
    }
    json_body(response).await
}

/// Read the bounded JSON body of a response whose status the caller already
/// accepted.
///
/// # Errors
/// [`NativeTokenError::InvalidResponse`] when the body is not JSON or is
/// longer than [`MAX_TOKEN_RESPONSE_BYTES`]; transport failures propagate.
pub async fn json_body(
    response: reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>, NativeTokenError> {
    if !response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .is_some_and(|value| {
            value.to_str().is_ok_and(|text| {
                // RFC 7231: the media type is case-insensitive and may carry
                // parameters such as `charset`, which do not change it.
                text.split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
            })
        })
    {
        return Err(NativeTokenError::InvalidResponse);
    }
    let body = bounded_body(response)
        .await?
        .ok_or(NativeTokenError::InvalidResponse)?;
    Ok(body)
}

/// The RFC 6749 `error` code of an error response, if its bounded JSON body
/// has one.
async fn oauth_refusal(response: reqwest::Response) -> Option<LoginRefusal> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let Ok(Some(body)) = bounded_body(response).await else {
        return None;
    };
    let body: ErrorBody = serde_json::from_slice(&body).ok()?;
    Some(LoginRefusal::from_code(&body.error))
}

/// Read at most [`MAX_TOKEN_RESPONSE_BYTES`], or `None` if the body is longer.
///
/// The body may hold the access token, so it is zeroed on drop and allocated
/// once to leave no stale copy behind a reallocation. The chunks `reqwest`
/// buffers before handing them over, and the copies it makes to send the form
/// and the `Authorization` header, are outside this crate's reach.
pub async fn bounded_body(
    mut response: reqwest::Response,
) -> Result<Option<Zeroizing<Vec<u8>>>, NativeTokenError> {
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_RESPONSE_BYTES));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(NativeTokenError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// A native login failure that never includes code, verifier, state, or token.
#[derive(Debug, Error)]
pub enum NativeTokenError {
    /// The manually entered code is not canonical.
    #[error("invalid terminal authorization code")]
    InvalidCode,
    /// Secure operating-system randomness was unavailable.
    #[error(transparent)]
    Entropy(#[from] crate::EntropyError),
    /// An issued renewable credential could not be verified or accepted, and
    /// best-effort revocation could not be confirmed.
    #[error(
        "native login failed ({failure}); renewable credential revocation was not confirmed ({revocation})"
    )]
    FailureAndRevocationUnconfirmed {
        /// Original login failure.
        failure: Box<Self>,
        /// Revocation failure.
        revocation: Box<Self>,
    },
    /// The HTTP transport failed.
    #[error("native login transport failed")]
    Transport(#[source] reqwest::Error),
    /// The Control Plane refused the login with an RFC 6749 error code.
    #[error(transparent)]
    Refused(LoginRefusal),
    /// Authority rejected a native login request.
    #[error("native login request was rejected ({0})")]
    Rejected(reqwest::StatusCode),
    /// Authority returned an unexpected or oversized success document.
    #[error("native login response was invalid")]
    InvalidResponse,
}

/// Resolve one Authority endpoint from the validated Control Plane origin.
fn endpoint(origin: &ControlPlaneOrigin, path: &str) -> Url {
    let mut url = origin.as_url().clone();
    url.set_path(path);
    url
}
