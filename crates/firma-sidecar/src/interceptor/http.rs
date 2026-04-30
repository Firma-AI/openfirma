//! HTTP proxy interceptor.
//!
//! Implements the [`Interceptor`](super::Interceptor) trait using a TCP
//! HTTP/1.1 proxy endpoint. The agent sets
//! `HTTP_PROXY=http://localhost:<port>` and all outbound HTTP traffic flows
//! through this interceptor before reaching external systems.
//!
//! The interceptor parses each inbound request into a
//! [`RawRequest`](crate::normalizer::RawRequest), passes it to the shared
//! [`RequestHandler`](crate::handler::RequestHandler), and writes the handled
//! response downstream.
//!
//! HTTPS `CONNECT` is supported in two modes:
//! - Transparent TCP tunneling (default, no MITM).
//! - Optional TLS MITM interception for configured hosts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use firma_core::DenyReason;
use http_body::Body as _;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use super::https_mitm::HttpsMitmRuntime;
use crate::config::{ConnectRelayConfig, HttpsMitmConfig};
use crate::handler::{ConnectDecision, DispatchedResponse, HandledResponse, RequestHandler};
use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::RawRequest;

const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// HTTP forward proxy interceptor.
///
/// Listens on a configurable TCP port (default 8080) and captures every
/// outbound HTTP request made by the agent. Each request is converted into a
/// [`RawRequest`](crate::normalizer::RawRequest) and handled through the
/// [`RequestHandler`](crate::handler::RequestHandler) provided in
/// [`Interceptor::run`](super::Interceptor::run).
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct HttpInterceptor {
    address: SocketAddr,
    handler: Option<Arc<RequestHandler>>,
    https_mitm_config: HttpsMitmConfig,
    ca_dir: PathBuf,
    max_request_body_bytes: usize,
    connect_relay: ConnectRelayConfig,
}

impl HttpInterceptor {
    /// Create a new [`HttpInterceptor`] that listens on the specified address.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        // Startup always injects explicit config via `with_https_mitm`; keep
        // the raw constructor conservative to avoid surprising side effects in
        // tests and local helper usage.
        let https_mitm_config = HttpsMitmConfig {
            enabled: false,
            ..HttpsMitmConfig::default()
        };
        Self {
            address,
            handler: None,
            https_mitm_config,
            ca_dir: PathBuf::from("./firma-ca/"),
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            connect_relay: ConnectRelayConfig::default(),
        }
    }

    /// Attach HTTPS MITM configuration to this interceptor.
    #[must_use]
    pub fn with_https_mitm(mut self, config: HttpsMitmConfig, ca_dir: PathBuf) -> Self {
        self.https_mitm_config = config;
        self.ca_dir = ca_dir;
        self
    }

    /// Set the maximum request body size accepted by the interceptor.
    #[must_use]
    pub fn with_max_request_body_bytes(mut self, max_request_body_bytes: usize) -> Self {
        self.max_request_body_bytes = max_request_body_bytes;
        self
    }

    /// Set CONNECT tunnel/MITM relay timeout controls.
    #[must_use]
    pub fn with_connect_relay(mut self, connect_relay: ConnectRelayConfig) -> Self {
        self.connect_relay = connect_relay;
        self
    }
}

impl From<SocketAddr> for HttpInterceptor {
    fn from(address: SocketAddr) -> Self {
        Self::new(address)
    }
}

impl Interceptor for HttpInterceptor {
    async fn run(
        mut self,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        let mitm_runtime = if self.https_mitm_config.enabled {
            let runtime = HttpsMitmRuntime::new(self.https_mitm_config.clone(), &self.ca_dir)
                .map_err(InterceptorError::ServerError)?;
            Some(Arc::new(runtime))
        } else {
            None
        };

        self.handler = Some(handler);
        let listener = TcpListener::bind(self.address)
            .await
            .map_err(|e| InterceptorError::BindFailed(e.to_string()))?;

        let handler =
            Arc::clone(self.handler.as_ref().ok_or_else(|| {
                InterceptorError::ServerError("request handler not set".to_string())
            })?);

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        let handler = Arc::clone(&handler);
                        let mitm_runtime = mitm_runtime.clone();
                        let max_request_body_bytes = self.max_request_body_bytes;
                        let connect_relay = self.connect_relay.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(
                                stream,
                                handler,
                                mitm_runtime,
                                max_request_body_bytes,
                                connect_relay,
                            ).await {
                                tracing::warn!("http proxy connection error: {e}");
                            }
                        });
                    }
                }
                () = cancel.cancelled() => break,
            }
        }

        Ok(())
    }
}

async fn serve_connection(
    socket: TcpStream,
    handler: Arc<RequestHandler>,
    mitm_runtime: Option<Arc<HttpsMitmRuntime>>,
    max_request_body_bytes: usize,
    connect_relay: ConnectRelayConfig,
) -> Result<(), InterceptorError> {
    let io = TokioIo::new(socket);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                let mitm_runtime = mitm_runtime.clone();
                let connect_relay = connect_relay.clone();
                async move {
                    handle_request(
                        req,
                        handler,
                        mitm_runtime,
                        max_request_body_bytes,
                        connect_relay,
                    )
                    .await
                }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| InterceptorError::ServerError(format!("HTTP connection error: {e}")))
}

async fn handle_request(
    mut req: Request<Incoming>,
    handler: Arc<RequestHandler>,
    mitm_runtime: Option<Arc<HttpsMitmRuntime>>,
    max_request_body_bytes: usize,
    connect_relay: ConnectRelayConfig,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        return handle_connect_request(
            &mut req,
            handler,
            mitm_runtime,
            max_request_body_bytes,
            connect_relay,
        )
        .await;
    }

    let raw = match build_raw_request(req, max_request_body_bytes).await {
        Ok(raw) => raw,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };
    let session_id = raw
        .headers
        .get("x-firma-session-id")
        .cloned()
        .unwrap_or_default();

    let response = match handler.handle(raw, &session_id).await {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            dispatched_response(response)
        }
        HandledResponse::Deny {
            reason,
            detail,
            context: _,
        } => deny_json_response(
            StatusCode::FORBIDDEN,
            crate::handler::deny_body_json(reason, &detail),
        ),
        HandledResponse::Aborted { reason, detail } => deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(reason, &detail),
        ),
    };

    Ok(response)
}

async fn handle_connect_request(
    req: &mut Request<Incoming>,
    handler: Arc<RequestHandler>,
    mitm_runtime: Option<Arc<HttpsMitmRuntime>>,
    max_request_body_bytes: usize,
    connect_relay: ConnectRelayConfig,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let raw = match build_raw_request_head(req, true) {
        Ok(raw) => raw,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };
    let session_id = raw
        .headers
        .get("x-firma-session-id")
        .cloned()
        .unwrap_or_default();
    let target_info = connect_target_info(&host_with_default_port(req, true));
    let mitm_candidate = mitm_runtime
        .as_ref()
        .filter(|runtime| runtime.should_intercept_host(&target_info.host))
        .cloned();
    let strict_mitm = mitm_candidate
        .as_ref()
        .is_some_and(|runtime| runtime.is_strict_host(&target_info.host));

    let mut prepared_acceptor: Option<TlsAcceptor> = None;
    if strict_mitm && let Some(runtime) = mitm_candidate.as_ref() {
        match runtime.tls_acceptor_for_host(&target_info.host).await {
            Ok(acceptor) => prepared_acceptor = Some(acceptor),
            Err(e) => {
                let detail = format!("HTTPS_MITM_SETUP_FAILED: {e}");
                tracing::error!(
                    host = %target_info.host,
                    "strict MITM preflight failed: {detail}"
                );
                return Ok(deny_json_response(
                    StatusCode::FORBIDDEN,
                    crate::handler::deny_body_json(DenyReason::FailClosed, &detail),
                ));
            }
        }
    }

    match handler.handle_connect(raw, &session_id).await {
        ConnectDecision::Deny { reason, detail } => Ok(deny_json_response(
            StatusCode::FORBIDDEN,
            crate::handler::deny_body_json(reason, &detail),
        )),
        ConnectDecision::Allow => {
            let limits = connect_relay_limits(&connect_relay);
            let target = connect_target(&target_info.authority);
            let on_upgrade = hyper::upgrade::on(req);
            if let Some(mitm_runtime) = mitm_candidate {
                let acceptor = if let Some(acceptor) = prepared_acceptor {
                    acceptor
                } else {
                    match mitm_runtime.tls_acceptor_for_host(&target_info.host).await {
                        Ok(acceptor) => acceptor,
                        Err(e) => {
                            let detail = format!("HTTPS_MITM_SETUP_FAILED: {e}");
                            tracing::warn!(
                                host = %target_info.host,
                                "MITM preflight failed, falling back to CONNECT tunnel: {detail}"
                            );
                            let limits = limits.clone();
                            tokio::spawn(async move {
                                if let Err(err) =
                                    relay_connect_tunnel(on_upgrade, &target, limits).await
                                {
                                    tracing::warn!(
                                        "CONNECT tunnel failed after MITM fallback: {err}"
                                    );
                                }
                            });
                            return Ok(connect_established_response());
                        }
                    }
                };

                let handler = Arc::clone(&handler);
                let connect_target = target_info;
                let connect_session_id = session_id;
                tokio::spawn(async move {
                    if let Err(e) = relay_connect_mitm(
                        on_upgrade,
                        connect_target,
                        handler,
                        connect_session_id,
                        acceptor,
                        max_request_body_bytes,
                        limits,
                    )
                    .await
                    {
                        tracing::warn!("MITM CONNECT flow failed: {e}");
                    }
                });
            } else {
                let limits = limits.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay_connect_tunnel(on_upgrade, &target, limits).await {
                        tracing::warn!("CONNECT tunnel failed: {e}");
                    }
                });
            }
            Ok(connect_established_response())
        }
    }
}

#[derive(Clone)]
struct ConnectTargetInfo {
    host: String,
    port: u16,
    authority: String,
}

fn connect_target_info(host: &str) -> ConnectTargetInfo {
    if let Ok(authority) = host.parse::<hyper::http::uri::Authority>() {
        let parsed_host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let port = authority.port_u16().unwrap_or(443);
        let authority = if parsed_host.contains(':') {
            format!("[{parsed_host}]:{port}")
        } else {
            format!("{parsed_host}:{port}")
        };
        ConnectTargetInfo {
            host: parsed_host,
            port,
            authority,
        }
    } else {
        ConnectTargetInfo {
            host: host.to_ascii_lowercase(),
            port: 443,
            authority: host.to_string(),
        }
    }
}

async fn relay_connect_tunnel(
    on_upgrade: hyper::upgrade::OnUpgrade,
    target: &str,
    limits: ConnectRelayLimits,
) -> Result<(), String> {
    let upgraded = tokio::time::timeout(limits.setup_timeout, on_upgrade)
        .await
        .map_err(|_| {
            format!(
                "upgrade timed out after {} seconds",
                limits.setup_timeout.as_secs()
            )
        })?
        .map_err(|e| format!("upgrade failed: {e}"))?;
    let mut downstream = TokioIo::new(upgraded);
    let mut upstream = tokio::time::timeout(limits.setup_timeout, TcpStream::connect(target))
        .await
        .map_err(|_| {
            format!(
                "upstream connect timed out after {} seconds for {target}",
                limits.setup_timeout.as_secs()
            )
        })?
        .map_err(|e| format!("upstream connect failed for {target}: {e}"))?;
    let _ = tokio::time::timeout(
        limits.session_max,
        copy_bidirectional(&mut downstream, &mut upstream),
    )
    .await
    .map_err(|_| {
        format!(
            "CONNECT tunnel exceeded {} seconds session cap",
            limits.session_max.as_secs()
        )
    })?
    .map_err(|e| format!("tunnel relay failed: {e}"))?;
    Ok(())
}

async fn relay_connect_mitm(
    on_upgrade: hyper::upgrade::OnUpgrade,
    target: ConnectTargetInfo,
    handler: Arc<RequestHandler>,
    connect_session_id: String,
    acceptor: TlsAcceptor,
    max_request_body_bytes: usize,
    limits: ConnectRelayLimits,
) -> Result<(), String> {
    let upgraded = tokio::time::timeout(limits.setup_timeout, on_upgrade)
        .await
        .map_err(|_| {
            format!(
                "upgrade timed out after {} seconds",
                limits.setup_timeout.as_secs()
            )
        })?
        .map_err(|e| format!("upgrade failed: {e}"))?;
    let downstream = TokioIo::new(upgraded);
    let tls_stream = tokio::time::timeout(limits.setup_timeout, acceptor.accept(downstream))
        .await
        .map_err(|_| {
            format!(
                "downstream TLS handshake timed out after {} seconds for {}",
                limits.setup_timeout.as_secs(),
                target.host
            )
        })?
        .map_err(|e| format!("downstream TLS handshake failed for {}: {e}", target.host))?;

    let target_host = target.host.clone();
    let io = TokioIo::new(tls_stream);
    let serve = http1::Builder::new().serve_connection(
        io,
        service_fn(move |req: Request<Incoming>| {
            let handler = Arc::clone(&handler);
            let target = target.clone();
            let connect_session_id = connect_session_id.clone();
            async move {
                handle_mitm_https_request(
                    req,
                    handler,
                    target,
                    &connect_session_id,
                    max_request_body_bytes,
                )
                .await
            }
        }),
    );
    tokio::time::timeout(limits.session_max, serve)
        .await
        .map_err(|_| {
            format!(
                "HTTPS MITM relay exceeded {} seconds session cap for {}",
                limits.session_max.as_secs(),
                target_host
            )
        })?
        .map_err(|e| format!("HTTPS MITM connection failed: {e}"))?;
    Ok(())
}

#[derive(Clone)]
struct ConnectRelayLimits {
    setup_timeout: Duration,
    session_max: Duration,
}

fn connect_relay_limits(config: &ConnectRelayConfig) -> ConnectRelayLimits {
    ConnectRelayLimits {
        setup_timeout: Duration::from_secs(config.setup_timeout_secs),
        session_max: Duration::from_secs(config.session_max_secs),
    }
}

fn connect_established_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

async fn handle_mitm_https_request(
    req: Request<Incoming>,
    handler: Arc<RequestHandler>,
    target: ConnectTargetInfo,
    connect_session_id: &str,
    max_request_body_bytes: usize,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        return Ok(deny_response(
            StatusCode::BAD_REQUEST,
            "MALFORMED_REQUEST: nested CONNECT is not supported",
        ));
    }

    let raw = match build_raw_https_request(req, &target, max_request_body_bytes).await {
        Ok(raw) => raw,
        Err(detail) => return Ok(deny_response(StatusCode::FORBIDDEN, &detail)),
    };

    let session_id = raw
        .headers
        .get("x-firma-session-id")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| connect_session_id.to_string());

    let response = match handler.handle(raw, &session_id).await {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            dispatched_response(response)
        }
        HandledResponse::Deny {
            reason,
            detail,
            context: _,
        } => deny_json_response(
            StatusCode::FORBIDDEN,
            crate::handler::deny_body_json(reason, &detail),
        ),
        HandledResponse::Aborted { reason, detail } => deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(reason, &detail),
        ),
    };
    Ok(response)
}

async fn build_raw_https_request(
    req: Request<Incoming>,
    target: &ConnectTargetInfo,
    max_request_body_bytes: usize,
) -> Result<RawRequest, String> {
    let mut raw = build_raw_https_request_head(&req, target)?;
    raw.body = read_body_with_limit(req.into_body(), max_request_body_bytes).await?;
    Ok(raw)
}

fn build_raw_https_request_head(
    req: &Request<Incoming>,
    target: &ConnectTargetInfo,
) -> Result<RawRequest, String> {
    let method = req.method().to_string();
    let host_value = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
        .or_else(|| req.uri().authority().map(ToString::to_string))
        .unwrap_or_else(|| target.authority.clone());
    let host_info = connect_target_info(&host_value);

    if !host_matches_connect_target(&host_info, target) {
        return Err("MALFORMED_REQUEST: tunneled host mismatch with CONNECT target".to_string());
    }

    let path = extract_path(req.uri().to_string().as_bytes());
    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
        .collect();

    Ok(RawRequest {
        method,
        host: host_info.authority,
        headers,
        path,
        body: None,
        is_https: true,
    })
}

fn host_matches_connect_target(requested: &ConnectTargetInfo, connect: &ConnectTargetInfo) -> bool {
    requested.host.eq_ignore_ascii_case(&connect.host) && requested.port == connect.port
}

async fn build_raw_request(
    req: Request<Incoming>,
    max_request_body_bytes: usize,
) -> Result<RawRequest, String> {
    let mut raw = build_raw_request_head(&req, false)?;
    raw.body = read_body_with_limit(req.into_body(), max_request_body_bytes).await?;
    Ok(raw)
}

async fn read_body_with_limit(
    mut body: Incoming,
    max_request_body_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(upper) = body.size_hint().upper()
        && upper > max_request_body_bytes as u64
    {
        return Err(format!(
            "MALFORMED_REQUEST: request body exceeds {max_request_body_bytes} bytes limit"
        ));
    }

    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| format!("MALFORMED_REQUEST: failed to read body: {e}"))?;
        if let Ok(data) = frame.into_data() {
            let new_len = out
                .len()
                .checked_add(data.len())
                .ok_or_else(|| "MALFORMED_REQUEST: request body size overflow".to_string())?;
            if new_len > max_request_body_bytes {
                return Err(format!(
                    "MALFORMED_REQUEST: request body exceeds {max_request_body_bytes} bytes limit"
                ));
            }
            out.extend_from_slice(data.as_ref());
        }
    }

    Ok(if out.is_empty() { None } else { Some(out) })
}

fn build_raw_request_head(req: &Request<Incoming>, is_connect: bool) -> Result<RawRequest, String> {
    let method = req.method().to_string();
    let host = host_with_default_port(req, is_connect);
    if host.is_empty() {
        return Err("MALFORMED_REQUEST: missing host".to_string());
    }
    let path = if is_connect {
        "/".to_string()
    } else {
        extract_path(req.uri().to_string().as_bytes())
    };
    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let is_https = is_connect
        || req
            .uri()
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"));

    Ok(RawRequest {
        method,
        host,
        headers,
        path,
        body: None,
        is_https,
    })
}

fn host_with_default_port(req: &Request<Incoming>, is_connect: bool) -> String {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
        .or_else(|| req.uri().authority().map(ToString::to_string))
        .or_else(|| {
            req.uri().host().map(|h| {
                let port = req
                    .uri()
                    .port_u16()
                    .unwrap_or(if is_connect { 443 } else { 80 });
                format!("{h}:{port}")
            })
        })
        .unwrap_or_default()
}

fn connect_target(host: &str) -> String {
    if let Ok(authority) = host.parse::<hyper::http::uri::Authority>() {
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = authority.port_u16().unwrap_or(443);
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        host.to_string()
    }
}

fn dispatched_response(response: DispatchedResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(response.body)))
        .unwrap_or_else(|_| {
            deny_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
        })
}

fn deny_response(status: StatusCode, detail: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(detail.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

fn deny_json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

/// Extracts the path component from a raw request-target.
///
/// For absolute-form proxy requests (`http://host/path`), strips the scheme
/// and authority to return just the path (e.g. `/path`). For origin-form
/// requests (`/path`), returns the value unchanged.
fn extract_path(raw_path: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw_path);
    if let Some(rest) = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
    {
        // Find the first '/' after the authority.
        rest.find('/')
            .map_or_else(|| "/".to_string(), |i| rest[i..].to_string())
    } else {
        s.into_owned()
    }
}

/// Resolves the upstream [`HttpPeer`] from a [`RawRequest`].
///
/// Parses `host` into address and port, defaulting to 443 for HTTPS
/// and 80 for HTTP.
// Note: CONNECT routing is handled explicitly in `handle_connect_request`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use rustls::ClientConfig;
    use rustls::RootCertStore;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, EnforcementPipeline,
        IntentNormalizer, MappingTable, PipelineArgs,
    };

    // ── helpers ────────────────────────────────────────────────────────

    /// Returns an available localhost address by binding to port 0.
    fn free_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|l| l.local_addr().ok());
        // SAFETY: this is test-only code; binding port 0 always succeeds
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        listener.unwrap()
    }

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    struct MockVerifier {
        claims: CapabilityClaims,
    }
    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Ok(self.claims.clone())
        }
    }

    struct NoRevocations;
    impl RevocationStore for NoRevocations {
        fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &TokenId) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "_test_".parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    /// Builds a pipeline that ALLOWs POST requests to `host` at `path`.
    ///
    /// Uses a wildcard host pattern (`*`) combined with the concrete path
    /// so the rule matches regardless of port number in the host header.
    fn test_pipeline_allow(path: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "*".to_string(),
                path: Some(path.to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_pipeline_allow_connect() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("CONNECT".to_string()),
                host: "*".to_string(),
                path: Some("/".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    /// Builds a pipeline that DENYs classified requests to `host` (empty
    /// capability map). Uses `default_protected: false` so unmapped hosts
    /// pass through.
    fn test_pipeline_deny_for_host(host: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: host.to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, false).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_pipeline_deny_connect_for_host(host: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("CONNECT".to_string()),
                host: host.to_string(),
                path: Some("/".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, false).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_handler(pipeline: Arc<EnforcementPipeline>) -> Arc<RequestHandler> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        Arc::new(RequestHandler::new(
            pipeline,
            crate::handler::tests::test_connector_registry(),
            tx,
        ))
    }

    /// Starts a minimal HTTP server that always returns `200 OK`.
    /// Returns the address it is listening on.
    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let listener = listener.unwrap();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            // Read the request (consume everything available).
                            let mut buf = vec![0u8; 4096];
                            let _ = stream.read(&mut buf).await;

                            // Respond with a minimal 200 OK.
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                    }
                    () = cancel_clone.cancelled() => break,
                }
            }
        });

        (addr, cancel)
    }

    /// Starts a raw TCP target for CONNECT tunnel testing.
    ///
    /// After receiving bytes through the tunnel it replies with `pong`.
    async fn mock_connect_target() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let listener = listener.unwrap();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            let mut buf = [0u8; 4];
                            if stream.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                                let _ = stream.write_all(b"pong").await;
                            }
                            let _ = stream.shutdown().await;
                        }
                    }
                    () = cancel_clone.cancelled() => break,
                }
            }
        });

        (addr, cancel)
    }

    /// Sends a raw HTTP/1.1 request through the proxy and returns the response
    /// status code.
    async fn proxy_request(proxy_addr: SocketAddr, request: &str) -> u16 {
        let response = proxy_response(proxy_addr, request).await;

        // Parse the status code from the first line: "HTTP/1.1 <code> ..."
        response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0)
    }

    async fn proxy_response(proxy_addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(proxy_addr).await.ok();
        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        let stream = stream.as_mut().unwrap();

        #[expect(clippy::unwrap_used, reason = "test code asserts setup succeeds")]
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        for _ in 0..16 {
            match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) | Err(_) => break,
            }
        }
        String::from_utf8_lossy(&out).to_string()
    }

    async fn read_connect_response(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    /// Starts the HTTP proxy interceptor and waits for it to be ready.
    /// Returns a handle to the server task.
    async fn start_proxy(
        addr: SocketAddr,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor = HttpInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        // Wait for the proxy to be ready by polling the port.
        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                return handle;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("proxy did not become ready within 2.5 seconds");
    }

    async fn start_proxy_with_body_limit(
        addr: SocketAddr,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        max_request_body_bytes: usize,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor =
            HttpInterceptor::new(addr).with_max_request_body_bytes(max_request_body_bytes);
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                return handle;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("proxy did not become ready within 2.5 seconds");
    }

    async fn start_proxy_with_mitm(
        addr: SocketAddr,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        mitm_config: HttpsMitmConfig,
        ca_dir: std::path::PathBuf,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor = HttpInterceptor::new(addr).with_https_mitm(mitm_config, ca_dir);
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                return handle;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("proxy did not become ready within 2.5 seconds");
    }

    async fn start_proxy_with_mitm_and_body_limit(
        addr: SocketAddr,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        mitm_config: HttpsMitmConfig,
        ca_dir: std::path::PathBuf,
        max_request_body_bytes: usize,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor = HttpInterceptor::new(addr)
            .with_https_mitm(mitm_config, ca_dir)
            .with_max_request_body_bytes(max_request_body_bytes);
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                return handle;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("proxy did not become ready within 2.5 seconds");
    }

    async fn connect_tls_with_ca(
        stream: TcpStream,
        ca_cert_path: &std::path::Path,
        server_name: &str,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let pem = std::fs::read(ca_cert_path)
            .unwrap_or_else(|e| panic!("failed to read CA cert {}: {e}", ca_cert_path.display()));
        let mut reader = std::io::BufReader::new(Cursor::new(pem));
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.unwrap_or_else(|e| panic!("failed to parse CA cert PEM: {e}"));
            roots
                .add(cert)
                .unwrap_or_else(|e| panic!("failed to add CA cert to root store: {e}"));
        }

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(server_name.to_string())
            .unwrap_or_else(|e| panic!("invalid server name {server_name}: {e}"));
        connector
            .connect(server_name, stream)
            .await
            .unwrap_or_else(|e| panic!("TLS connect failed: {e}"))
    }

    // ── extract_path unit tests ─────────────────────────────────────────

    #[test]
    fn test_extract_path_absolute_http() {
        let path = extract_path(b"http://api.openai.com/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_extract_path_absolute_https() {
        let path = extract_path(b"https://api.openai.com/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_extract_path_absolute_with_port() {
        let path = extract_path(b"http://127.0.0.1:9090/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_extract_path_absolute_host_only() {
        let path = extract_path(b"http://api.openai.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_extract_path_origin_form() {
        let path = extract_path(b"/v1/chat/completions");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_connect_target_info_parses_ipv4_authority() {
        let info = connect_target_info("api.openai.com:443");
        assert_eq!(info.host, "api.openai.com");
        assert_eq!(info.port, 443);
        assert_eq!(info.authority, "api.openai.com:443");
    }

    #[test]
    fn test_connect_target_info_parses_ipv6_authority() {
        let info = connect_target_info("[::1]:8443");
        assert_eq!(info.host, "::1");
        assert_eq!(info.port, 8443);
        assert_eq!(info.authority, "[::1]:8443");
    }

    #[test]
    fn test_host_matches_connect_target_requires_host_and_port_match() {
        let connect = connect_target_info("api.openai.com:443");
        assert!(host_matches_connect_target(
            &connect_target_info("api.openai.com:443"),
            &connect
        ));
        assert!(!host_matches_connect_target(
            &connect_target_info("api.openai.com:8443"),
            &connect
        ));
        assert!(!host_matches_connect_target(
            &connect_target_info("chat.openai.com:443"),
            &connect
        ));
    }

    // ── pipeline sanity checks ─────────────────────────────────────────

    #[tokio::test]
    async fn test_pipeline_allow_matches_with_port_in_host() {
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let raw = RawRequest {
            method: "POST".to_string(),
            host: "127.0.0.1:9999".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: false,
        };
        let (decision, _payload) = pipeline.enforce(&raw, "").await;
        assert!(decision.is_allow(), "expected allow, got: {decision:?}");
    }

    // ── integration tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_proxy_allows_valid_request_and_forwards_to_upstream() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {{}}"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 200, "expected 200 OK for allowed request");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_rejects_request_body_over_limit() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        let server_handle =
            start_proxy_with_body_limit(proxy_addr, handler, cancel.clone(), 4).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: 10\r\n\
             \r\n\
             0123456789"
        );

        let response = proxy_response(proxy_addr, &request).await;
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(status, 403, "expected 403 for oversized body");
        assert!(
            response.contains("request body exceeds 4 bytes limit"),
            "expected body-size limit message, got: {response}"
        );

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_denies_when_no_capability() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        // Wildcard host, empty cap map → DENY at token selection
        let handler = test_handler(test_pipeline_deny_for_host("*"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {{}}"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 403, "expected 403 for denied request");

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_passthrough_for_unmapped_host() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        // Pipeline maps only api.openai.com, default_protected=false →
        // unmapped hosts pass through.
        let handler = test_handler(test_pipeline_deny_for_host("api.openai.com"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "GET http://{host}/anything HTTP/1.1\r\n\
             Host: {host}\r\n\
             \r\n"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(
            status, 200,
            "expected 200 for passthrough (unmapped) request"
        );

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_allows_and_tunnels_bytes() {
        let (target_addr, target_cancel) = mock_connect_target().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", target_addr.port());
        let handler = test_handler(test_pipeline_allow_connect());
        let cancel = CancellationToken::new();
        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to proxy: {e}"));
        let connect_req = format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\
             x-firma-session-id: _test_\r\n\
             \r\n"
        );
        stream
            .write_all(connect_req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write CONNECT request: {e}"));

        let response = read_connect_response(&mut stream).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200, got: {response:?}"
        );

        stream
            .write_all(b"ping")
            .await
            .unwrap_or_else(|e| panic!("failed to write tunnel payload: {e}"));
        let mut reply = [0u8; 4];
        stream
            .read_exact(&mut reply)
            .await
            .unwrap_or_else(|e| panic!("failed to read tunnel reply: {e}"));
        assert_eq!(&reply, b"pong");

        cancel.cancel();
        target_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_denies_without_capability() {
        let (target_addr, target_cancel) = mock_connect_target().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", target_addr.port());
        let handler = test_handler(test_pipeline_deny_connect_for_host("*"));
        let cancel = CancellationToken::new();
        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\
             \r\n"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 403, "expected 403 for denied CONNECT");

        cancel.cancel();
        target_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_mitm_intercepts_and_applies_l7_deny() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let proxy_addr = free_addr();
        let handler = test_handler(test_pipeline_deny_for_host("*"));
        let cancel = CancellationToken::new();

        let mitm_config = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec!["localhost".to_string()],
            strict_hosts: vec!["localhost".to_string()],
            cert_ttl_secs: 300,
            cert_cache_capacity: 16,
            ..HttpsMitmConfig::default()
        };

        let server_handle = start_proxy_with_mitm(
            proxy_addr,
            handler,
            cancel.clone(),
            mitm_config,
            ca_tempdir.path().to_path_buf(),
        )
        .await;

        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to proxy: {e}"));
        let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nx-firma-session-id: _test_\r\n\r\n";
        stream
            .write_all(connect_req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write CONNECT request: {e}"));
        let connect_response = read_connect_response(&mut stream).await;
        assert!(
            connect_response.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200, got: {connect_response:?}"
        );

        let ca_cert_path = ca_tempdir.path().join("firma-ca.crt");
        for _ in 0..20 {
            if ca_cert_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(ca_cert_path.exists(), "expected CA cert to be generated");

        let mut tls_stream = connect_tls_with_ca(stream, &ca_cert_path, "localhost").await;
        let tunneled_request = "POST /v1/chat/completions HTTP/1.1\r\n\
Host: localhost:443\r\n\
Content-Length: 2\r\n\
\r\n\
{}";
        tls_stream
            .write_all(tunneled_request.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write tunneled HTTPS request: {e}"));

        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(3), tls_stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timed out reading tunneled HTTPS response"))
            .unwrap_or_else(|e| panic!("failed reading tunneled HTTPS response: {e}"));
        let response = String::from_utf8_lossy(&buf[..n]).to_string();
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(
            status, 403,
            "expected L7 deny over MITM path, got: {response}"
        );

        cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_mitm_rejects_oversized_tunneled_body() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let proxy_addr = free_addr();
        let handler = test_handler(test_pipeline_allow_connect());
        let cancel = CancellationToken::new();

        let mitm_config = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec!["localhost".to_string()],
            strict_hosts: vec!["localhost".to_string()],
            cert_ttl_secs: 300,
            cert_cache_capacity: 16,
            ..HttpsMitmConfig::default()
        };

        let server_handle = start_proxy_with_mitm_and_body_limit(
            proxy_addr,
            handler,
            cancel.clone(),
            mitm_config,
            ca_tempdir.path().to_path_buf(),
            4,
        )
        .await;

        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to proxy: {e}"));
        let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nx-firma-session-id: _test_\r\n\r\n";
        stream
            .write_all(connect_req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write CONNECT request: {e}"));
        let connect_response = read_connect_response(&mut stream).await;
        assert!(
            connect_response.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200, got: {connect_response:?}"
        );

        let ca_cert_path = ca_tempdir.path().join("firma-ca.crt");
        for _ in 0..20 {
            if ca_cert_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(ca_cert_path.exists(), "expected CA cert to be generated");

        let mut tls_stream = connect_tls_with_ca(stream, &ca_cert_path, "localhost").await;
        let tunneled_request = "POST /v1/chat/completions HTTP/1.1\r\n\
Host: localhost:443\r\n\
Content-Length: 10\r\n\
\r\n\
0123456789";
        tls_stream
            .write_all(tunneled_request.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write tunneled HTTPS request: {e}"));

        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(3), tls_stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timed out reading tunneled HTTPS response"))
            .unwrap_or_else(|e| panic!("failed reading tunneled HTTPS response: {e}"));
        let response = String::from_utf8_lossy(&buf[..n]).to_string();
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(status, 403, "expected 403 for oversized tunneled body");
        assert!(
            response.contains("request body exceeds 4 bytes limit"),
            "expected body-size limit message, got: {response}"
        );

        cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_strict_mitm_preflight_failure_denies_fail_closed() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let proxy_addr = free_addr();
        let handler = test_handler(test_pipeline_allow_connect());
        let cancel = CancellationToken::new();
        let invalid_dns_host = "exa_mple.com".to_string();
        let connect_authority = format!("{invalid_dns_host}:443");

        let mitm_config = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec![invalid_dns_host.clone()],
            strict_hosts: vec![invalid_dns_host.clone()],
            cert_ttl_secs: 300,
            cert_cache_capacity: 16,
            ..HttpsMitmConfig::default()
        };

        let server_handle = start_proxy_with_mitm(
            proxy_addr,
            handler,
            cancel.clone(),
            mitm_config,
            ca_tempdir.path().to_path_buf(),
        )
        .await;

        let request =
            format!("CONNECT {connect_authority} HTTP/1.1\r\nHost: {connect_authority}\r\n\r\n");
        let response = proxy_response(proxy_addr, &request).await;
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(
            status, 403,
            "expected 403 for strict MITM preflight failure"
        );
        assert!(
            response.contains(r#""reason":"FailClosed""#),
            "expected fail-closed reason body, got: {response}"
        );
        assert!(
            response.contains("HTTPS_MITM_SETUP_FAILED"),
            "expected MITM setup failure detail, got: {response}"
        );

        cancel.cancel();
        let _ = server_handle.await;
    }
}
