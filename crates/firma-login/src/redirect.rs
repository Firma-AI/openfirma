use std::{
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_server::Handle;
use firma_config_utils::NonZeroDuration;
use hyper_util::rt::TokioTimer;
use secrecy::SecretString;
use thiserror::Error;

use crate::{ControlPlaneOrigin, LoginRefusal};
use tokio::{
    sync::{Mutex, oneshot},
    time::Instant,
};
use url::Url;

use crate::{AuthorizationState, PkceChallenge, PkceVerifier};

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADERS: usize = 64;
const MAX_BUFFER_SIZE: usize = 64 * 1024;
/// How long the answer to the callback may take to reach the browser.
const RESPONSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub struct LoopbackCallbackListener {
    listener: TcpListener,
    redirect_uri: LoopbackRedirectUri,
}

impl LoopbackCallbackListener {
    pub(crate) fn bind() -> Result<Self, LoopbackCallbackListenerError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(LoopbackCallbackListenerError::Bind)?;
        let port = listener
            .local_addr()
            .map_err(LoopbackCallbackListenerError::LocalAddress)?
            .port();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/callback"))
            .map_err(LoopbackCallbackListenerError::RedirectUri)?;

        Ok(Self {
            listener,
            redirect_uri: LoopbackRedirectUri { url, port },
        })
    }

    fn redirect_uri(&self) -> &LoopbackRedirectUri {
        &self.redirect_uri
    }
}

/// The exact loopback callback URI for a bound native-login listener.
#[derive(Debug, PartialEq, Eq)]
pub struct LoopbackRedirectUri {
    url: Url,
    port: u16,
}

impl LoopbackRedirectUri {
    /// Return the validated callback URI.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    fn host_header(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

/// A non-zero deadline for completing the loopback callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackWaitTimeout(NonZeroDuration);

impl TryFrom<Duration> for CallbackWaitTimeout {
    type Error = CallbackTimeoutError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        NonZeroDuration::try_from(value)
            .map(Self)
            .map_err(|_| CallbackTimeoutError::Zero)
    }
}

/// Failure to construct a callback timeout.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CallbackTimeoutError {
    /// Callback timeouts cannot be zero.
    #[error("callback timeout must be greater than zero")]
    Zero,
}

/// Path of the Control Plane page the browser lands on after the callback.
///
/// The Control Plane renders it, so its copy can change without a CLI release.
/// It must serve this path before a CLI that redirects there ships.
pub const LANDING_PATH: &str = "/agent-flow/authorizations/returned";

/// The Control Plane pages the browser lands on once the callback is
/// answered: one for a granted login, one for a refused one.
///
/// Both pages are on the validated Control Plane origin, so the listener can
/// never redirect the browser anywhere else. The pages are cosmetic: they are
/// reachable by anyone and prove nothing about the login.
#[derive(Debug, Clone)]
pub struct CallbackLanding {
    granted: Url,
    refused: Url,
}

impl CallbackLanding {
    /// The outcome pages under [`LANDING_PATH`] on `origin`.
    #[must_use]
    pub fn on(origin: &ControlPlaneOrigin) -> Self {
        let page = |outcome: &str| {
            let mut page = origin.as_url().clone();
            page.set_path(LANDING_PATH);
            page.query_pairs_mut().append_pair("outcome", outcome);
            page
        };
        Self {
            granted: page("approved"),
            refused: page("denied"),
        }
    }
}

/// An authorization attempt with its callback listener bound.
pub struct PendingAuthorizationAttempt {
    state: AuthorizationState,
    verifier: PkceVerifier,
    challenge: PkceChallenge,
    listener: LoopbackCallbackListener,
}

impl PendingAuthorizationAttempt {
    pub(crate) fn new(
        state: AuthorizationState,
        verifier: PkceVerifier,
        challenge: PkceChallenge,
        listener: LoopbackCallbackListener,
    ) -> Self {
        Self {
            state,
            verifier,
            challenge,
            listener,
        }
    }

    /// Return the callback URI to place in the authorization request.
    #[must_use]
    pub fn redirect_uri(&self) -> &LoopbackRedirectUri {
        self.listener.redirect_uri()
    }

    /// Return the state parameter to place in the authorization request.
    #[must_use]
    pub fn state_parameter(&self) -> &str {
        self.state.as_str()
    }

    /// Return the S256 challenge to place in the authorization request.
    #[must_use]
    pub fn pkce_challenge(&self) -> &PkceChallenge {
        &self.challenge
    }

    /// Receive the first valid callback before the overall deadline, then
    /// send the browser on to `landing`.
    ///
    /// Invalid requests leave the attempt pending. Once a valid callback or a
    /// matching OAuth error arrives, the listener stops accepting requests.
    /// Browser response delivery is best effort.
    ///
    /// # Errors
    ///
    /// Returns an error when the deadline expires, the callback server stops,
    /// or the authorization server reports a matching OAuth error.
    ///
    /// # Panics
    ///
    /// Panics without an entered Tokio runtime that enables both I/O and time.
    pub async fn receive(
        self,
        timeout: CallbackWaitTimeout,
        landing: CallbackLanding,
    ) -> Result<CompletedAuthorizationAttempt, LoopbackCallbackError> {
        let deadline = Instant::now()
            .checked_add(timeout.0.duration())
            .ok_or(CallbackFailure::DeadlineOutOfRange)?;
        let Self {
            state,
            verifier,
            challenge: _,
            listener,
        } = self;
        let LoopbackCallbackListener {
            listener,
            redirect_uri,
        } = listener;
        listener
            .set_nonblocking(true)
            .map_err(CallbackFailure::ConfigureNonblocking)?;
        let (terminal_sender, mut terminal_receiver) = oneshot::channel();
        let callback_state = Arc::new(CallbackServerState {
            expected_host: redirect_uri.host_header(),
            expected_state: state,
            landing,
            deadline,
            terminal_sender: Mutex::new(Some(terminal_sender)),
        });
        let router = Router::new()
            .route("/callback", get(receive_callback))
            .with_state(callback_state);

        let handle = Handle::new();
        let mut server = axum_server::from_tcp(listener)
            .map_err(CallbackFailure::ConfigureServer)?
            .handle(handle.clone())
            .http1_only();
        server
            .http_builder()
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(HEADER_READ_TIMEOUT))
            .max_headers(MAX_HEADERS)
            .max_buf_size(MAX_BUFFER_SIZE);
        let server = server.serve(router.into_make_service());
        tokio::pin!(server);

        let outcome = tokio::select! {
            biased;

            result = &mut terminal_receiver => {
                CallbackServerOutcome::Terminal(result)
            }
            result = &mut server => CallbackServerOutcome::Stopped(result),
            () = tokio::time::sleep_until(deadline) => {
                CallbackServerOutcome::DeadlineElapsed
            }
        };

        let terminal_result = match outcome {
            CallbackServerOutcome::Terminal(result) => {
                // Let the page that answers the callback reach the browser
                // before the listener closes.
                handle.graceful_shutdown(Some(RESPONSE_DRAIN_TIMEOUT));
                let _ = (&mut server).await;
                result.map_err(|_| CallbackFailure::ServerStopped)?
            }
            CallbackServerOutcome::Stopped(Ok(())) => {
                return Err(CallbackFailure::ServerStopped.into());
            }
            CallbackServerOutcome::Stopped(Err(error)) => {
                return Err(CallbackFailure::Server(error).into());
            }
            CallbackServerOutcome::DeadlineElapsed => {
                handle.shutdown();
                let _ = (&mut server).await;
                return Err(CallbackFailure::DeadlineElapsed.into());
            }
        };

        match terminal_result {
            ParsedCallback::Code(code) => Ok(CompletedAuthorizationAttempt {
                code: AuthorizationCode(SecretString::from(code)),
                verifier,
            }),
            ParsedCallback::AuthorizationRejected(refusal) => {
                Err(LoopbackCallbackError::AuthorizationRejected(refusal))
            }
        }
    }
}

/// The validated callback result coupled to its matching PKCE verifier.
pub struct CompletedAuthorizationAttempt {
    code: AuthorizationCode,
    verifier: PkceVerifier,
}

impl CompletedAuthorizationAttempt {
    /// Return the opaque authorization code.
    #[must_use]
    pub fn authorization_code(&self) -> &AuthorizationCode {
        &self.code
    }

    /// Return the PKCE verifier that generated the accepted challenge.
    #[must_use]
    pub fn pkce_verifier(&self) -> &PkceVerifier {
        &self.verifier
    }
}

/// An opaque authorization code accepted by the bound callback listener.
pub struct AuthorizationCode(SecretString);

impl AuthorizationCode {
    /// Return the authorization code for the token-exchange boundary.
    #[must_use]
    pub fn as_secret(&self) -> &SecretString {
        &self.0
    }
}

/// Failure while receiving a callback.
#[derive(Debug, Error)]
pub enum LoopbackCallbackError {
    /// The authorization server declined the authorization request.
    #[error(transparent)]
    AuthorizationRejected(LoginRefusal),

    /// The callback could not be accepted or validated.
    #[error(transparent)]
    CallbackFailed(#[from] anyhow::Error),
}

impl From<CallbackFailure> for LoopbackCallbackError {
    fn from(value: CallbackFailure) -> Self {
        Self::CallbackFailed(anyhow::Error::new(value))
    }
}

#[derive(Debug, Error)]
enum CallbackFailure {
    #[error("callback deadline is outside the supported monotonic range")]
    DeadlineOutOfRange,

    #[error("cannot configure the loopback callback listener")]
    ConfigureNonblocking(#[source] std::io::Error),

    #[error("cannot configure the loopback callback server")]
    ConfigureServer(#[source] std::io::Error),

    #[error("the loopback callback server stopped unexpectedly")]
    Server(#[source] std::io::Error),

    #[error("no valid loopback callback arrived before its deadline")]
    DeadlineElapsed,

    #[error("the loopback callback server stopped before a terminal callback")]
    ServerStopped,

    #[error("the loopback callback query is invalid")]
    InvalidQuery,
}

enum CallbackServerOutcome {
    Terminal(Result<ParsedCallback, oneshot::error::RecvError>),
    Stopped(std::io::Result<()>),
    DeadlineElapsed,
}

/// Failure to bind or represent a callback listener.
#[derive(Debug, Error)]
pub enum LoopbackCallbackListenerError {
    /// The operating system could not bind the required loopback listener.
    #[error("cannot bind the loopback callback listener")]
    Bind(#[source] std::io::Error),

    /// The bound listener's local address could not be read.
    #[error("cannot read the loopback callback listener address")]
    LocalAddress(#[source] std::io::Error),

    /// The fixed loopback callback URI is invalid for the URL library.
    #[error("cannot construct the loopback callback URI")]
    RedirectUri(#[source] url::ParseError),
}

struct CallbackServerState {
    expected_host: String,
    expected_state: AuthorizationState,
    /// Where to send the browser after a terminal callback.
    landing: CallbackLanding,
    deadline: Instant,
    terminal_sender: Mutex<Option<oneshot::Sender<ParsedCallback>>>,
}

enum ParsedCallback {
    Code(String),
    AuthorizationRejected(LoginRefusal),
}

async fn receive_callback(
    State(state): State<Arc<CallbackServerState>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if !has_expected_host(&headers, &state.expected_host) {
        return (StatusCode::BAD_REQUEST, "Invalid callback host").into_response();
    }

    let Some(query) = query else {
        return (StatusCode::BAD_REQUEST, "Invalid callback").into_response();
    };
    let Ok(callback) = parse_query(&query, &state.expected_state) else {
        return (StatusCode::BAD_REQUEST, "Invalid callback").into_response();
    };

    let sender = {
        let mut terminal_sender = state.terminal_sender.lock().await;
        if Instant::now() >= state.deadline {
            return (StatusCode::REQUEST_TIMEOUT, "Callback deadline elapsed").into_response();
        }
        terminal_sender.take()
    };
    let Some(sender) = sender else {
        return (StatusCode::CONFLICT, "Callback already handled").into_response();
    };

    let response = land(match &callback {
        ParsedCallback::Code(_) => &state.landing.granted,
        ParsedCallback::AuthorizationRejected(_) => &state.landing.refused,
    });
    if sender.send(callback).is_err() {
        return (StatusCode::GONE, "Callback no longer accepted").into_response();
    }

    response
}

/// Sends the browser on to a Control Plane page. The callback URL carries the
/// one-time code, so it must not follow as the referrer.
fn land(page: &Url) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, page.as_str()),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response()
}

fn has_expected_host(headers: &HeaderMap, expected_host: &str) -> bool {
    let mut hosts = headers.get_all(header::HOST).iter();
    let Some(host) = hosts.next() else {
        return false;
    };

    hosts.next().is_none() && host.as_bytes() == expected_host.as_bytes()
}

fn parse_query(
    query: &str,
    expected_state: &AuthorizationState,
) -> Result<ParsedCallback, CallbackFailure> {
    let mut parameters = CallbackParameters::default();

    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        parameters.insert(&name, value.into_owned())?;
    }

    parameters.finish(expected_state)
}

#[derive(Default)]
struct CallbackParameters {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

impl CallbackParameters {
    fn insert(&mut self, name: &str, value: String) -> Result<(), CallbackFailure> {
        let slot = match name {
            "code" => &mut self.code,
            "state" => &mut self.state,
            "error" => &mut self.error,
            _ => return Ok(()),
        };

        if value.is_empty() || slot.replace(value).is_some() {
            return Err(CallbackFailure::InvalidQuery);
        }

        Ok(())
    }

    fn finish(
        self,
        expected_state: &AuthorizationState,
    ) -> Result<ParsedCallback, CallbackFailure> {
        match (self.code, self.state, self.error) {
            (Some(code), Some(state), None)
                if expected_state.matches_callback(&state)
                    && code.len() <= crate::MAX_AUTHORIZATION_CODE_BYTES =>
            {
                Ok(ParsedCallback::Code(code))
            }
            (None, Some(state), Some(error)) if expected_state.matches_callback(&state) => Ok(
                ParsedCallback::AuthorizationRejected(LoginRefusal::from_code(&error)),
            ),
            _ => Err(CallbackFailure::InvalidQuery),
        }
    }
}
