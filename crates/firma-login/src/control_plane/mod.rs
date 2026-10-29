//! Authenticated requests to the Firma Team Control Plane on behalf of one
//! saved login.
//!
//! Every request carries a token from [`NativeSession`] and goes to the origin
//! that issued it.
//!
//! A start is never repeated: each one creates a new run and returns
//! its credential once, so a lost answer means running the command again. A
//! close may be repeated, since the first close wins.

use std::time::Duration;

use firma_config_loader::AgentProfile;
use firma_config_utils::http::host_is_this_machine;
use firma_connection_store::ConnectionStore;
use firma_identifiers::{AgentHandle, AgentId, RunId, SidecarId, WorkspaceId};
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::protocol::{bounded_body, control_plane_http, is_retryable_status, json_body};
use crate::{
    ControlPlaneOrigin, ControlPlaneOriginError, NativeSession, NativeTokenError,
    OriginValidationMode, SessionError,
};

/// The native Agent flow contract this client speaks.
const CONTRACT_VERSION: u32 = 1;
const CONTRACT_VERSION_HEADER: &str = "Firma-Agent-Flow-Version";
const API_PATH: [&str; 3] = ["api", "agent-flow", "v1"];
/// A problem code is a short machine name; anything else is not this
/// contract and never reaches the terminal.
const MAX_PROBLEM_CODE_LEN: usize = 64;
/// A repeatable request is sent again when the Control Plane could not
/// answer or the answer was lost; any other failure is final.
const REQUEST_ATTEMPTS: usize = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);

mod closure;
pub use closure::{CloseOutcome, RecordedOutcome};

/// An Agent as the Control Plane resolved it.
#[derive(Debug)]
pub struct ResolvedAgent {
    /// The Agent's identity.
    pub agent_id: AgentId,
    /// The handle it was resolved by.
    pub handle: AgentHandle,
    /// Display name chosen by a Member; any text, so escape it before
    /// printing it to a terminal.
    pub name: String,
    /// The canonical `OpenFirma` Agent profile the Control Plane names.
    pub profile_id: AgentProfile,
    /// The Policy Set the Agent runs under; unvalidated.
    pub policy_set_id: String,
    /// Opaque, unordered; changes whenever the configuration changes.
    pub generation: String,
    /// The Workspace the request was answered for.
    pub workspace_id: WorkspaceId,
    /// Where a Sidecar reaches the Authority's gRPC services: `https` to
    /// another host, verified against the platform's trusted roots, or `http`
    /// to a loopback host.
    pub authority_grpc_uri: Url,
    /// The Workspace's Ed25519 capability verifying key, raw.
    pub capability_public_key: [u8; 32],
}

/// A started run: its identity, its one Sidecar identity, and the
/// runtime credential that authenticates it.
#[derive(Debug)]
pub struct StartedRun {
    /// The run the Control Plane created.
    pub run_id: RunId,
    /// The Sidecar identity issued for this run alone.
    pub sidecar_id: SidecarId,
    /// The runtime bearer, shown by the Control Plane exactly once; `Debug`
    /// redacts it, never log or format it otherwise.
    pub credential: SecretString,
}

/// Why a Control Plane request did not produce its answer.
///
/// No variant carries a token or free server-supplied text: a problem code
/// is shown only once it parsed as a short machine name.
#[derive(Debug, Error)]
pub enum ControlPlaneError {
    /// The saved login could not provide access.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// The Control Plane refused the access token.
    #[error("the Control Plane refused the access token; run the command again")]
    Unauthorized,
    /// The Membership may not use Agents in this Workspace.
    #[error("your Membership cannot use Agents in this Workspace")]
    AccessDenied,
    /// A human login cannot close a machine-owned run.
    #[error("this run is owned by a machine and cannot be closed with your human login")]
    RunNotClosable,
    /// No active Agent has the handle in this Workspace.
    #[error("no Agent {0} in this Workspace")]
    AgentNotFound(AgentHandle),
    /// The Control Plane refused the request with a code this firma has no
    /// recovery for.
    #[error("the Control Plane refused the request ({code}){}", request_id_suffix(*request_id))]
    Refused {
        /// The status paired with the problem code.
        status: StatusCode,
        /// The problem code the Control Plane answered with.
        code: String,
        /// The diagnostic id the Control Plane logged the refusal under.
        request_id: Option<Uuid>,
    },
    /// The Control Plane speaks another contract version or sent an
    /// unexpected answer.
    #[error("the Control Plane answered in a form this firma does not understand; update firma")]
    IncompatibleServer,
    /// The Authority is reachable only over a transport this firma does not
    /// support for managed runs.
    #[error(
        "this firma reaches the Authority of a managed run only over https on another host, or plain http on a loopback host"
    )]
    AuthorityTransportUnsupported,
    /// The Control Plane could not answer now.
    #[error("the Control Plane is unavailable ({status}){}", request_id_suffix(*request_id))]
    Unavailable {
        /// The response status.
        status: StatusCode,
        /// The diagnostic id the Control Plane logged the failure under.
        request_id: Option<Uuid>,
    },
    /// The request could not be built or delivered.
    #[error("the Control Plane could not be reached")]
    Transport(#[source] reqwest::Error),
}

/// Authenticated Control Plane requests for one saved login.
pub struct ControlPlaneClient {
    session: NativeSession,
    /// HTTP client for the origin that issued the last token, built once and
    /// reused while that origin stays the same.
    http: Option<(ControlPlaneOrigin, reqwest::Client)>,
}

#[derive(Deserialize)]
struct ResolutionBody {
    contract_version: u32,
    agent: AgentBody,
    configuration: ConfigurationBody,
}

#[derive(Deserialize)]
struct AgentBody {
    id: AgentId,
    handle: AgentHandle,
    name: String,
    profile_id: String,
    policy_set_id: String,
}

#[derive(Deserialize)]
struct ConfigurationBody {
    generation: String,
    authority_grpc_uri: String,
    capability_public_key: String,
}

/// The Authority URI a managed run trusts: a plain origin that `firma
/// login` would accept in development, less `https` on a loopback host. A
/// managed run verifies an `https` Authority against the platform's trusted
/// roots; on this host the Sidecar would instead trust the state directory's
/// local CA, so the run's trust would come from a local file.
fn trusted_authority_grpc_uri(value: &str) -> Result<Url, ControlPlaneError> {
    let url = Url::parse(value).map_err(|_| ControlPlaneError::IncompatibleServer)?;
    let origin = ControlPlaneOrigin::new(url, OriginValidationMode::DevelopmentLoopback).map_err(
        |error| match error {
            ControlPlaneOriginError::DevelopmentHttpRequiresLoopback => {
                ControlPlaneError::AuthorityTransportUnsupported
            }
            // A validated origin on the server, so any other shape is not
            // the Control Plane this firma knows.
            _ => ControlPlaneError::IncompatibleServer,
        },
    )?;
    let url = origin.as_url();
    if url.scheme() == "https" && url.host_str().is_some_and(host_is_this_machine) {
        return Err(ControlPlaneError::AuthorityTransportUnsupported);
    }
    Ok(url.clone())
}

fn capability_public_key(value: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()?
        .try_into()
        .ok()
}

#[derive(Deserialize)]
struct ProblemBody {
    code: ProblemCode,
    #[serde(default, deserialize_with = "diagnostic_id")]
    request_id: Option<Uuid>,
}

fn diagnostic_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Uuid>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(value.as_str().and_then(|value| value.parse().ok()))
}

/// A problem code as the contract spells it: lowercase ASCII letters, digits
/// and underscores, never empty.
#[derive(Deserialize)]
#[serde(try_from = "String")]
struct ProblemCode(String);

impl TryFrom<String> for ProblemCode {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let well_formed = !value.is_empty()
            && value.len() <= MAX_PROBLEM_CODE_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        well_formed
            .then_some(Self(value))
            .ok_or("not a problem code")
    }
}

#[derive(Serialize)]
struct StartBody<'a> {
    agent_handle: &'a AgentHandle,
    resolved_configuration_generation: &'a str,
}

#[derive(Deserialize)]
struct StartedBody {
    contract_version: u32,
    run: StartedView,
    runtime_credential: RuntimeCredentialBody,
}

#[derive(Deserialize)]
struct StartedView {
    id: RunId,
    state: RunState,
    sidecar_id: Option<SidecarId>,
}

/// The states the contract names; any other value is an incompatible server.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RunState {
    Active,
    Terminal,
}

#[derive(Deserialize)]
struct RuntimeCredentialBody {
    token_type: String,
    access_token: SecretString,
}

impl ControlPlaneClient {
    /// Uses `store` as the single source of access.
    #[must_use]
    pub const fn new(store: ConnectionStore) -> Self {
        Self {
            session: NativeSession::new(store),
            http: None,
        }
    }

    /// Drops the HTTP connections and keeps the session with its access
    /// token. Call it before using the client from another tokio runtime: a
    /// pooled connection is driven by the runtime that opened it.
    pub fn drop_connections(&mut self) {
        self.http = None;
    }

    /// Renews the access token now when it is about to expire, so that a
    /// request raced against an interrupt seldom has to renew it.
    ///
    /// # Errors
    /// Returns [`ControlPlaneError::Session`] when the login cannot provide
    /// access.
    pub async fn renew_access(&mut self) -> Result<(), ControlPlaneError> {
        self.session.access_token().await?;
        Ok(())
    }

    /// Resolves the active Agent with `handle` in the login's Workspace.
    ///
    /// A refused token or Membership is reported, never retried; a refused
    /// token is dropped, so the next request renews it.
    ///
    /// # Errors
    /// Returns a [`ControlPlaneError`] naming what the user can do next.
    pub async fn resolve_agent(
        &mut self,
        handle: &AgentHandle,
    ) -> Result<ResolvedAgent, ControlPlaneError> {
        let (workspace_id, response) = self
            .send(Method::GET, &["agents", handle.as_str()], None)
            .await?;
        let response = match self.accepted(response, &[StatusCode::OK]).await {
            Err(ControlPlaneError::Refused {
                status: StatusCode::NOT_FOUND,
                code,
                ..
            }) if code == "agent_not_found" => {
                return Err(ControlPlaneError::AgentNotFound(handle.clone()));
            }
            outcome => outcome?,
        };
        let body = json_body(response).await.map_err(unexpected)?;
        let body: ResolutionBody =
            serde_json::from_slice(&body).map_err(|_| ControlPlaneError::IncompatibleServer)?;
        let generation = body.configuration.generation;
        // The resolution contract is a canonical positive u64 decimal, but
        // callers must retain its wire spelling and never order generations.
        if body.contract_version != CONTRACT_VERSION
            || body.agent.handle != *handle
            || !generation.starts_with(|c: char| matches!(c, '1'..='9'))
            || !generation.bytes().all(|byte| byte.is_ascii_digit())
            || generation.parse::<u64>().is_err()
        {
            return Err(ControlPlaneError::IncompatibleServer);
        }
        let profile_id = AgentProfile::from_canonical_name(&body.agent.profile_id)
            .ok_or(ControlPlaneError::IncompatibleServer)?;
        let authority_grpc_uri =
            trusted_authority_grpc_uri(&body.configuration.authority_grpc_uri)?;
        let capability_public_key =
            capability_public_key(&body.configuration.capability_public_key)
                .ok_or(ControlPlaneError::IncompatibleServer)?;
        Ok(ResolvedAgent {
            agent_id: body.agent.id,
            handle: body.agent.handle,
            name: body.agent.name,
            profile_id,
            policy_set_id: body.agent.policy_set_id,
            generation,
            workspace_id,
            authority_grpc_uri,
            capability_public_key,
        })
    }

    /// Starts a run of the Agent `handle` at the configuration
    /// `generation` the caller resolved: the Control Plane issues its Sidecar
    /// identity and runtime credential, once.
    ///
    /// Never retried, since each start creates a run: a lost answer
    /// leaves one nobody holds the credential of, which expires, and the
    /// caller starts again. The only replay follows renewing a refused token,
    /// which the Control Plane answers before any write.
    ///
    /// # Errors
    /// Returns a [`ControlPlaneError`] naming what the user can do next.
    pub async fn start_run(
        &mut self,
        handle: &AgentHandle,
        generation: &str,
    ) -> Result<StartedRun, ControlPlaneError> {
        let request = serde_json::to_vec(&StartBody {
            agent_handle: handle,
            resolved_configuration_generation: generation,
        })
        .map_err(|_| ControlPlaneError::IncompatibleServer)?;
        let body = match self
            .post_renewing(&["runs"], &request, &[StatusCode::CREATED])
            .await
        {
            Err(ControlPlaneError::Refused {
                status: StatusCode::NOT_FOUND,
                code,
                ..
            }) if code == "agent_not_found" => {
                return Err(ControlPlaneError::AgentNotFound(handle.clone()));
            }
            answer => answer?,
        };
        let body: StartedBody =
            serde_json::from_slice(&body).map_err(|_| ControlPlaneError::IncompatibleServer)?;
        let credential = body.runtime_credential;
        match body.run {
            StartedView {
                id,
                state: RunState::Active,
                sidecar_id: Some(sidecar_id),
            } if body.contract_version == CONTRACT_VERSION
                && credential.token_type.eq_ignore_ascii_case("bearer")
                && !credential.access_token.expose_secret().is_empty() =>
            {
                Ok(StartedRun {
                    run_id: id,
                    sidecar_id,
                    credential: credential.access_token,
                })
            }
            _ => Err(ControlPlaneError::IncompatibleServer),
        }
    }

    /// Posts `body` to the repeatable request at `segments` until one of the
    /// `expected` statuses answers. The Control Plane is asked again only
    /// when it could not answer, for up to three attempts, plus one
    /// immediate replay after renewing a refused token; its refusals are
    /// final.
    async fn post_with_retries(
        &mut self,
        segments: &[&str],
        body: &[u8],
        expected: &[StatusCode],
    ) -> Result<Zeroizing<Vec<u8>>, ControlPlaneError> {
        let mut attempt = 1;
        let mut refreshed = false;
        loop {
            match self.post_once(segments, body, expected).await {
                Ok(answer) => return Ok(answer),
                Err((ControlPlaneError::Unauthorized, _)) if !refreshed => {
                    refreshed = true;
                }
                Err((error, delay)) if attempt < REQUEST_ATTEMPTS && is_retryable(&error) => {
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                }
                Err((error, _)) => return Err(error),
            }
        }
    }

    /// Posts `body` to `segments` once, and once more after renewing a refused
    /// token, which the Control Plane refuses before any write. For a request
    /// that must not be repeated otherwise, such as a start.
    async fn post_renewing(
        &mut self,
        segments: &[&str],
        body: &[u8],
        expected: &[StatusCode],
    ) -> Result<Zeroizing<Vec<u8>>, ControlPlaneError> {
        match self.post_once(segments, body, expected).await {
            Err((ControlPlaneError::Unauthorized, _)) => {
                self.post_once(segments, body, expected).await
            }
            answer => answer,
        }
        .map_err(|(error, _)| error)
    }

    /// One attempt of a repeatable request: the request and its body, so that
    /// a connection lost while the answer was being read is retried like one
    /// lost before.
    async fn post_once(
        &mut self,
        segments: &[&str],
        body: &[u8],
        expected: &[StatusCode],
    ) -> Result<Zeroizing<Vec<u8>>, (ControlPlaneError, Duration)> {
        let (_, response) = self
            .send(Method::POST, segments, Some(body))
            .await
            .map_err(|error| (error, RETRY_DELAY))?;
        let delay = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(RETRY_DELAY, |value| {
                Duration::from_secs(value.parse::<u64>().unwrap_or(u64::MAX).min(15))
            });
        let response = self
            .accepted(response, expected)
            .await
            .map_err(|error| (error, delay))?;
        json_body(response)
            .await
            .map_err(|error| (unexpected(error), RETRY_DELAY))
    }

    /// Passes a response with one of the `expected` statuses through; a
    /// refused token is dropped so the next request renews it, another
    /// success or a redirect is a contract this firma does not speak, every
    /// other status becomes its error.
    async fn accepted(
        &mut self,
        response: reqwest::Response,
        expected: &[StatusCode],
    ) -> Result<reqwest::Response, ControlPlaneError> {
        match response.status() {
            status if expected.contains(&status) => Ok(response),
            status if status.is_success() || status.is_redirection() => {
                Err(ControlPlaneError::IncompatibleServer)
            }
            StatusCode::UNAUTHORIZED => {
                self.session.forget_access();
                Err(ControlPlaneError::Unauthorized)
            }
            _ => Err(refusal(response).await),
        }
    }

    /// Sends one request to the Agent-flow `segments` under the origin that
    /// issued the token, and returns the Workspace the token speaks for with
    /// the response. A JSON `body` is attached when given.
    async fn send(
        &mut self,
        method: Method,
        segments: &[&str],
        body: Option<&[u8]>,
    ) -> Result<(WorkspaceId, reqwest::Response), ControlPlaneError> {
        let access = self.session.access_token().await?;
        let mut url: Url = access.origin().as_url().clone();
        url.path_segments_mut()
            .map_err(|()| ControlPlaneError::IncompatibleServer)?
            .clear()
            .extend(API_PATH)
            .extend(segments);
        let http = match &self.http {
            Some((origin, http)) if origin == access.origin() => http,
            _ => {
                let http =
                    control_plane_http(access.origin()).map_err(ControlPlaneError::Transport)?;
                &self.http.insert((access.origin().clone(), http)).1
            }
        };
        let mut request = http
            .request(method, url)
            .bearer_auth(access.token().expose_secret())
            .header(CONTRACT_VERSION_HEADER, CONTRACT_VERSION.to_string());
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request.send().await.map_err(ControlPlaneError::Transport)?;
        Ok((access.workspace_id(), response))
    }
}

/// The diagnostic id, when the Control Plane gave one, for an error message.
fn request_id_suffix(request_id: Option<Uuid>) -> String {
    request_id.map_or_else(String::new, |id| format!("; request id {id}"))
}

/// Whether a repeatable request may be sent again: the Control Plane could
/// not be reached or could not answer, so no refusal stands. Token renewal
/// has its own one-replay budget.
fn is_retryable(error: &ControlPlaneError) -> bool {
    match error {
        ControlPlaneError::Transport(_) => true,
        ControlPlaneError::Unavailable { status, .. } => is_retryable_status(*status),
        _ => false,
    }
}

/// The error for any other status. A problem code is reported as a refusal
/// for the caller to recognise; a redirect, a 400, or a client error without
/// a code means the Control Plane does not speak this contract. Timeouts and
/// rate limits remain retryable availability failures.
async fn refusal(response: reqwest::Response) -> ControlPlaneError {
    let status = response.status();
    let problem = bounded_body(response)
        .await
        .ok()
        .flatten()
        .and_then(|body| serde_json::from_slice::<ProblemBody>(&body).ok());
    match (status, problem) {
        (StatusCode::FORBIDDEN, Some(problem)) if problem.code.0 == "run_not_closable" => {
            ControlPlaneError::RunNotClosable
        }
        (StatusCode::FORBIDDEN, _) => ControlPlaneError::AccessDenied,
        (status, _) if status.is_redirection() || status == StatusCode::BAD_REQUEST => {
            ControlPlaneError::IncompatibleServer
        }
        // A timeout or too many requests is "later", like a 503, not a refusal.
        (StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS, problem) => {
            ControlPlaneError::Unavailable {
                status,
                request_id: problem.and_then(|problem| problem.request_id),
            }
        }
        (status, Some(problem)) if status.is_client_error() => ControlPlaneError::Refused {
            status,
            code: problem.code.0,
            request_id: problem.request_id,
        },
        // A refusal without a problem code is not this contract.
        (status, None) if status.is_client_error() => ControlPlaneError::IncompatibleServer,
        (status, problem) => ControlPlaneError::Unavailable {
            status,
            request_id: problem.and_then(|problem| problem.request_id),
        },
    }
}

/// Maps a failure reading a success body.
fn unexpected(error: NativeTokenError) -> ControlPlaneError {
    match error {
        NativeTokenError::Transport(source) => ControlPlaneError::Transport(source),
        _ => ControlPlaneError::IncompatibleServer,
    }
}
