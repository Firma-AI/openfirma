//! HTTP proxy interceptor.
//!
//! Implements the [`Interceptor`] trait using a TCP
//! HTTP/1.1 proxy endpoint. The agent sets
//! `HTTP_PROXY=http://localhost:<port>` and all outbound HTTP traffic flows
//! through this interceptor before reaching external systems.
//!
//! The interceptor parses each inbound request into a
//! [`RawRequest`], passes it to the shared
//! [`RequestHandler`], and writes the handled
//! response downstream.
//!
//! HTTPS `CONNECT` is supported in two modes:
//! - Transparent TCP tunneling (default, no MITM).
//! - Optional TLS MITM interception for configured hosts.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use firma_core::{AbortReason, DenyReason};
use firma_http::{Authority, HeaderMap, Method};
use http_body::Body as _;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::RootCertStore;
#[cfg(test)]
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use super::https_mitm::HttpsMitmRuntime;
use crate::config::{ConnectRelayConfig, HttpsMitmConfig};
use crate::handler::{
    ConnectDecision, DispatchedResponse, HandledResponse, RequestHandler, UpgradeAuthorization,
};
use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::RawRequest;

const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_TOTAL_BODY_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const CONNECT_PREFACE_MAX_BYTES: usize = 32;

struct BodyBudget {
    used: AtomicUsize,
    ceiling: usize,
}

impl BodyBudget {
    fn new(ceiling: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            ceiling,
        }
    }

    fn try_acquire(&self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                cur.checked_add(n).filter(|&next| next <= self.ceiling)
            })
            .is_ok()
    }

    fn try_release(&self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                cur.checked_sub(n)
            })
            .is_ok()
    }
}

struct BudgetGuard {
    budget: Arc<BodyBudget>,
    reserved: usize,
}

impl BudgetGuard {
    fn new(budget: Arc<BodyBudget>) -> Self {
        Self {
            budget,
            reserved: 0,
        }
    }

    fn release(&mut self, n: usize) {
        self.reserved = n;
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        if self.reserved > 0 {
            let _ = self.budget.try_release(self.reserved);
        }
    }
}

/// HTTP forward proxy interceptor.
///
/// Listens on a configurable TCP port (default 8080) and captures every
/// outbound HTTP request made by the agent. Each request is converted into a
/// [`RawRequest`] and handled through the
/// [`RequestHandler`] provided in
/// [`Interceptor::run`].
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
    total_body_budget_bytes: usize,
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
            total_body_budget_bytes: DEFAULT_TOTAL_BODY_BUDGET_BYTES,
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
    pub(crate) fn with_max_request_body_bytes(mut self, max_request_body_bytes: usize) -> Self {
        self.max_request_body_bytes = max_request_body_bytes;
        self
    }

    /// Set the global ceiling for concurrent request body buffering.
    #[must_use]
    pub(crate) fn with_total_body_budget_bytes(mut self, total_body_budget_bytes: usize) -> Self {
        self.total_body_budget_bytes = total_body_budget_bytes;
        self
    }

    /// Set CONNECT tunnel/MITM relay timeout controls.
    #[must_use]
    pub(crate) fn with_connect_relay(mut self, connect_relay: ConnectRelayConfig) -> Self {
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
        self,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        let listener = TcpListener::bind(self.address)
            .await
            .map_err(|e| InterceptorError::BindFailed(e.to_string()))?;
        self.run_with_listener(listener, handler, cancel).await
    }
}

impl HttpInterceptor {
    /// Build the HTTPS MITM runtime (generating CA material) when active.
    ///
    /// The runtime is built only when interception is effectively active
    /// (enabled with at least one intercept host). An enabled-but-empty host
    /// list is treated as disabled, so CA material is not loaded at all.
    ///
    /// Callers that bind a listening socket should invoke this before binding:
    /// building the runtime is where CA generation happens, so a connectable
    /// port then implies CA readiness and a CA failure surfaces synchronously
    /// instead of leaving a dead bound port.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptorError::ServerError`] if TLS MITM runtime
    /// initialization (including CA material generation) fails.
    pub(crate) fn build_mitm_runtime(
        &self,
    ) -> Result<Option<Arc<HttpsMitmRuntime>>, InterceptorError> {
        if self.https_mitm_config.is_active() {
            let runtime = HttpsMitmRuntime::new(self.https_mitm_config.clone(), &self.ca_dir)
                .map_err(InterceptorError::ServerError)?;
            Ok(Some(Arc::new(runtime)))
        } else {
            Ok(None)
        }
    }

    /// Run the interceptor loop using an already bound listener.
    ///
    /// Builds the MITM runtime (generating CA material when active) before
    /// entering the accept loop. Callers that must guarantee CA readiness
    /// before the port becomes connectable should instead build the runtime
    /// with [`HttpInterceptor::build_mitm_runtime`] before binding and pass it
    /// to [`HttpInterceptor::run_with_listener_and_runtime`].
    ///
    /// # Errors
    ///
    /// Returns [`InterceptorError`] if TLS MITM runtime initialization fails
    /// or the server loop encounters an unrecoverable error.
    pub async fn run_with_listener(
        self,
        listener: TcpListener,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        let mitm_runtime = self.build_mitm_runtime()?;
        self.run_with_listener_and_runtime(listener, handler, cancel, mitm_runtime)
            .await
    }

    /// Run the interceptor loop with a pre-built MITM runtime.
    ///
    /// Unlike [`HttpInterceptor::run_with_listener`], this accepts an
    /// already-built `mitm_runtime`, letting callers generate CA material
    /// before binding the listener so a connectable port implies readiness.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptorError`] if the server loop encounters an
    /// unrecoverable error.
    pub(crate) async fn run_with_listener_and_runtime(
        mut self,
        listener: TcpListener,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        mitm_runtime: Option<Arc<HttpsMitmRuntime>>,
    ) -> Result<(), InterceptorError> {
        self.handler = Some(handler);
        let handler =
            Arc::clone(self.handler.as_ref().ok_or_else(|| {
                InterceptorError::ServerError("request handler not set".to_string())
            })?);
        let budget = Arc::new(BodyBudget::new(self.total_body_budget_bytes));

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, peer_addr)) = accepted {
                        tracing::debug!(
                            peer_addr = %peer_addr,
                            "http proxy accepted client connection"
                        );
                        let handler = Arc::clone(&handler);
                        let mitm_runtime = mitm_runtime.clone();
                        let max_request_body_bytes = self.max_request_body_bytes;
                        let connect_relay = self.connect_relay.clone();
                        let budget = Arc::clone(&budget);
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(
                                stream,
                                handler,
                                mitm_runtime,
                                max_request_body_bytes,
                                connect_relay,
                                budget,
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
    budget: Arc<BodyBudget>,
) -> Result<(), InterceptorError> {
    let io = TokioIo::new(socket);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                let mitm_runtime = mitm_runtime.clone();
                let connect_relay = connect_relay.clone();
                let budget = Arc::clone(&budget);
                async move {
                    handle_request(
                        req,
                        handler,
                        mitm_runtime,
                        max_request_body_bytes,
                        connect_relay,
                        budget,
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
    budget: Arc<BodyBudget>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    if req.method() == http::Method::CONNECT {
        return handle_connect_request(
            &mut req,
            handler,
            mitm_runtime,
            max_request_body_bytes,
            connect_relay,
            budget,
        )
        .await;
    }

    let session_hint = header_session_id(&req);
    // Capture host + session before `req` is consumed so a malformed
    // request can still emit an attributable deny audit event (FIR-208).
    let host = match host_with_default_port(&req, false) {
        Ok(host) => host,
        Err(detail) => {
            return Ok(deny_malformed(
                &handler,
                &session_hint,
                "raw.http",
                "",
                &detail.to_string(),
            )
            .await);
        }
    };
    let (raw, body_guard) =
        match build_raw_request(req, max_request_body_bytes, budget.clone()).await {
            Ok(result) => result,
            Err(detail) => {
                return Ok(deny_malformed(
                    &handler,
                    &session_hint,
                    "raw.http",
                    host.as_str(),
                    &detail.to_string(),
                )
                .await);
            }
        };
    let session_id = match raw.headers.get_firma_session_id() {
        Ok(session_id) => session_id.unwrap_or_default().to_owned(),
        Err(detail) => {
            return Ok(deny_malformed(
                &handler,
                &session_hint,
                "raw.http",
                host.as_str(),
                &detail.to_string(),
            )
            .await);
        }
    };
    tracing::debug!(
        method = %raw.method,
        host = %raw.host,
        path = %path_without_query(&raw.path),
        session_id = %session_id,
        "HTTP request received by sidecar"
    );

    let response = match handler.handle(raw, &session_id).await {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            dispatched_response(response)
        }
        HandledResponse::Deny {
            reason,
            detail,
            context: _,
        } => {
            tracing::warn!(
                session_id = %session_id,
                reason = ?reason,
                detail = %detail,
                "HTTP request denied by guard policy"
            );
            deny_json_response(
                StatusCode::FORBIDDEN,
                crate::handler::deny_body_json(reason, &detail),
            )
        }
        HandledResponse::Aborted { reason, detail } => deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(reason, &detail),
        ),
    };

    drop(body_guard);
    Ok(response)
}

/// Preflights the TLS acceptor for a MITM-candidate CONNECT target.
///
/// Always preflighted so a fallback to a blind CONNECT tunnel cannot
/// bypass enforcement. Strict hosts fail closed — on preflight failure
/// this emits a fail-closed deny audit event (FIR-208) and returns the
/// 403 to send back via `Err`. Non-strict hosts fall back to a blind
/// tunnel (returning `effective_mitm = None`) but only after the
/// CONNECT-level decision is enforced by the caller.
async fn preflight_mitm_acceptor(
    handler: &RequestHandler,
    session_id: &str,
    target_info: &ConnectTargetInfo,
    mitm_candidate: Option<Arc<HttpsMitmRuntime>>,
    strict_mitm: bool,
) -> Result<(Option<TlsAcceptor>, Option<Arc<HttpsMitmRuntime>>), Response<Full<Bytes>>> {
    let mut prepared_acceptor: Option<TlsAcceptor> = None;
    let mut effective_mitm = mitm_candidate;
    if let Some(runtime) = effective_mitm.as_ref() {
        match runtime.tls_acceptor_for_host(&target_info.host).await {
            Ok(acceptor) => prepared_acceptor = Some(acceptor),
            Err(e) => {
                let detail = anyhow::anyhow!("HTTPS_MITM_SETUP_FAILED: {e}");
                if strict_mitm {
                    tracing::error!(
                        host = %target_info.host,
                        "strict MITM preflight failed: {detail}"
                    );
                    let detail = detail.to_string();
                    handler
                        .emit_synthetic_deny(
                            session_id,
                            "network.connect",
                            &resource_label_from_host(&target_info.host),
                            DenyReason::FailClosed,
                            &detail,
                        )
                        .await;
                    return Err(deny_json_response(
                        StatusCode::FORBIDDEN,
                        crate::handler::deny_body_json(DenyReason::FailClosed, &detail),
                    ));
                }
                tracing::warn!(
                    host = %target_info.host,
                    "non-strict MITM preflight failed; enforcing CONNECT and falling back to blind tunnel: {detail}"
                );
                effective_mitm = None;
            }
        }
    }
    Ok((prepared_acceptor, effective_mitm))
}

async fn handle_connect_request(
    req: &mut Request<Incoming>,
    handler: Arc<RequestHandler>,
    mitm_runtime: Option<Arc<HttpsMitmRuntime>>,
    max_request_body_bytes: usize,
    connect_relay: ConnectRelayConfig,
    budget: Arc<BodyBudget>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let raw = match build_raw_request_head(req, true) {
        Ok(raw) => raw,
        Err(detail) => {
            return Ok(deny_malformed_connect(req, &handler, &detail.to_string()).await);
        }
    };
    let session_id = match raw.headers.get_firma_session_id() {
        Ok(session_id) => session_id.unwrap_or_default().to_owned(),
        Err(detail) => {
            return Ok(deny_malformed_connect(req, &handler, &detail.to_string()).await);
        }
    };
    let target_info = connect_target_info(&host_with_default_port(req, true)?)?;
    tracing::debug!(
        host = %target_info.host,
        port = target_info.port,
        session_id = %session_id,
        "CONNECT request received by sidecar"
    );
    let mitm_candidate = mitm_runtime
        .as_ref()
        .filter(|runtime| runtime.should_intercept_host(&target_info.host))
        .cloned();
    let strict_mitm = mitm_candidate
        .as_ref()
        .is_some_and(|runtime| runtime.is_strict_host(&target_info.host));

    let (prepared_acceptor, effective_mitm) = match preflight_mitm_acceptor(
        &handler,
        &session_id,
        &target_info,
        mitm_candidate,
        strict_mitm,
    )
    .await
    {
        Ok(pair) => pair,
        Err(response) => return Ok(response),
    };

    // MITM-intercepted hosts (preflight succeeded): by default skip CONNECT-level
    // enforcement because each decrypted inner request is enforced at L7.
    //
    // Safety hardening: for non-strict MITM candidates we still evaluate
    // CONNECT once up-front. If this session later needs to fall back to a
    // blind tunnel (e.g. non-TLS tunneled payload), destination-level policy
    // has already been enforced and no bypass is introduced.
    //
    // Blind-tunnel hosts AND non-strict MITM with failed preflight: CONNECT is
    // the only enforcement point, so enforce it.
    let connect_decision = if effective_mitm.is_some() && strict_mitm {
        ConnectDecision::Allow
    } else {
        handler.handle_connect(raw, &session_id).await
    };

    match connect_decision {
        ConnectDecision::Deny { reason, detail } => {
            log_connect_deny(&target_info, &session_id, reason, &detail);
            Ok(deny_json_response(
                StatusCode::FORBIDDEN,
                crate::handler::deny_body_json(reason, &detail),
            ))
        }
        ConnectDecision::Abort { reason, detail } => Ok(deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(reason, &detail),
        )),
        ConnectDecision::Allow => {
            let relay_mode = if effective_mitm.is_some() {
                "mitm"
            } else {
                "tunnel"
            };
            tracing::debug!(
                host = %target_info.host,
                port = target_info.port,
                session_id = %session_id,
                relay_mode = relay_mode,
                "CONNECT authorized and handled by sidecar"
            );
            let limits = connect_relay_limits(&connect_relay);
            let target = connect_target(&target_info.authority);
            let on_upgrade = hyper::upgrade::on(req);
            spawn_connect_relay(
                on_upgrade,
                target,
                target_info,
                session_id,
                handler,
                effective_mitm,
                prepared_acceptor,
                max_request_body_bytes,
                limits,
                strict_mitm,
                budget,
            );
            Ok(connect_established_response())
        }
    }
}

fn log_connect_deny(
    target_info: &ConnectTargetInfo,
    session_id: &str,
    reason: firma_core::DenyReason,
    detail: &str,
) {
    if reason == firma_core::DenyReason::TokenExpired {
        tracing::warn!(
            host = %target_info.host,
            port = target_info.port,
            session_id = %session_id,
            detail = %detail,
            "CONNECT denied due to expired capability token; renew token for this session_id and reload sidecar capability source"
        );
    }
    tracing::warn!(
        host = %target_info.host,
        port = target_info.port,
        session_id = %session_id,
        reason = ?reason,
        detail = %detail,
        "CONNECT denied by guard policy"
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "CONNECT relay setup needs explicit upgrade state, target/session context, MITM inputs, and resource limits"
)]
fn spawn_connect_relay(
    on_upgrade: hyper::upgrade::OnUpgrade,
    target: String,
    target_info: ConnectTargetInfo,
    session_id: String,
    handler: Arc<RequestHandler>,
    mitm_candidate: Option<Arc<HttpsMitmRuntime>>,
    prepared_acceptor: Option<TlsAcceptor>,
    max_request_body_bytes: usize,
    limits: ConnectRelayLimits,
    strict_mitm: bool,
    budget: Arc<BodyBudget>,
) {
    // Invariant enforced by handle_connect_request: when mitm_candidate is Some,
    // prepared_acceptor is also Some (preflight runs synchronously and either
    // succeeds, fails-closed for strict, or clears mitm_candidate for non-strict).
    // No silent blind-tunnel fallback here — that would re-introduce the
    // CONNECT enforcement bypass we close in the caller.
    match (mitm_candidate, prepared_acceptor) {
        (None, _) => {
            tokio::spawn(async move {
                match relay_connect_tunnel(on_upgrade, &target, limits).await {
                    Err(e) => {
                        let failure_class = classify_connect_relay_failure(&e);
                        tracing::warn!(
                            host = %target_info.host,
                            port = target_info.port,
                            session_id = %session_id,
                            policy_decision = "allow",
                            failure_class,
                            detail = %e,
                            "CONNECT relay failed after policy allow"
                        );
                        handler
                            .emit_connect_relay_failure_audit(&session_id, &target_info.host, &e)
                            .await;
                    }
                    Ok(stats)
                        if stats.downstream_to_upstream_bytes > 0
                            && stats.upstream_to_downstream_bytes == 0 =>
                    {
                        tracing::warn!(
                            host = %target_info.host,
                            port = target_info.port,
                            session_id = %session_id,
                            policy_decision = "allow",
                            downstream_to_upstream_bytes = stats.downstream_to_upstream_bytes,
                            upstream_to_downstream_bytes = stats.upstream_to_downstream_bytes,
                            "CONNECT tunnel closed without upstream response bytes"
                        );
                    }
                    Ok(_) => {}
                }
            });
        }
        (Some(_), Some(acceptor)) => {
            tokio::spawn(async move {
                let relay_target_info = target_info.clone();
                let relay_session_id = session_id.clone();
                let relay_handler = Arc::clone(&handler);
                let relay_budget = Arc::clone(&budget);
                if let Err(e) = relay_connect_mitm(
                    on_upgrade,
                    relay_target_info,
                    relay_handler,
                    relay_session_id,
                    acceptor,
                    max_request_body_bytes,
                    limits,
                    strict_mitm,
                    relay_budget,
                )
                .await
                {
                    let failure_class = classify_connect_relay_failure(&e);
                    tracing::warn!(
                        host = %target_info.host,
                        port = target_info.port,
                        session_id = %session_id,
                        policy_decision = "allow",
                        relay_mode = "mitm",
                        failure_class,
                        detail = %e,
                        "MITM CONNECT relay failed after policy allow"
                    );
                    handler
                        .emit_connect_relay_failure_audit(&session_id, &target_info.host, &e)
                        .await;
                }
            });
        }
        (Some(_), None) => {
            tracing::error!(
                host = %target_info.host,
                "spawn_connect_relay invariant violated: MITM runtime present without prepared acceptor; dropping connection fail-closed"
            );
        }
    }
}

#[derive(Clone)]
struct ConnectTargetInfo {
    host: String,
    port: u16,
    authority: Authority,
}

#[derive(Debug, Clone, Copy)]
struct TunnelRelayStats {
    downstream_to_upstream_bytes: u64,
    upstream_to_downstream_bytes: u64,
}

fn connect_target_info(authority: &Authority) -> anyhow::Result<ConnectTargetInfo> {
    let parsed_host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    let auth_str = if parsed_host.contains(':') {
        format!("[{parsed_host}]:{port}")
    } else {
        format!("{parsed_host}:{port}")
    };
    Ok(ConnectTargetInfo {
        host: parsed_host,
        port,
        authority: Authority::from_str(&auth_str)?,
    })
}

async fn relay_connect_tunnel(
    on_upgrade: hyper::upgrade::OnUpgrade,
    target: &str,
    limits: ConnectRelayLimits,
) -> Result<TunnelRelayStats, String> {
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
    let (downstream_to_upstream_bytes, upstream_to_downstream_bytes) = tokio::time::timeout(
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
    Ok(TunnelRelayStats {
        downstream_to_upstream_bytes,
        upstream_to_downstream_bytes,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "MITM CONNECT relay needs explicit stream, target, handler, TLS acceptor, and relay limits"
)]
async fn relay_connect_mitm(
    on_upgrade: hyper::upgrade::OnUpgrade,
    target: ConnectTargetInfo,
    handler: Arc<RequestHandler>,
    connect_session_id: String,
    acceptor: TlsAcceptor,
    max_request_body_bytes: usize,
    limits: ConnectRelayLimits,
    strict_mitm: bool,
    budget: Arc<BodyBudget>,
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
    let mut preface = [0_u8; CONNECT_PREFACE_MAX_BYTES];
    let preface_len = tokio::time::timeout(
        limits.setup_timeout,
        read_connect_preface(&mut downstream, &mut preface),
    )
    .await
    .map_err(|_| {
        format!(
            "downstream preface read timed out after {} seconds for {}",
            limits.setup_timeout.as_secs(),
            target.host
        )
    })?
    .map_err(|e| format!("downstream preface read failed for {}: {e}", target.host))?;
    let tls_start = first_non_crlf_index(&preface[..preface_len]);
    let first_non_crlf = preface.get(tls_start).copied().unwrap_or(0);
    let tls_header_valid = is_likely_tls_record_header(&preface[..preface_len], tls_start);
    if !tls_header_valid {
        if strict_mitm {
            return Err(format!(
                "strict MITM requires TLS tunneled traffic; received non-TLS CONNECT preface (first_non_crlf=0x{:02x}) for {}",
                first_non_crlf, target.host
            ));
        }
        tracing::warn!(
            host = %target.host,
            first_byte = format_args!("0x{:02x}", first_non_crlf),
            preface = %hex_preface(&preface[..preface_len]),
            "non-strict MITM detected non-TLS CONNECT payload/header; falling back to blind tunnel"
        );
        let _ = relay_connect_tunnel_from_stream_with_prefetch(
            downstream,
            &target.authority,
            limits,
            &preface[..preface_len],
        )
        .await?;
        return Ok(());
    }

    let downstream = PrefetchedStream::new(downstream, &preface[tls_start..preface_len]);
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
    let serve = http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                let target = target.clone();
                let connect_session_id = connect_session_id.clone();
                let budget = Arc::clone(&budget);
                async move {
                    handle_mitm_https_request(
                        req,
                        handler,
                        target,
                        &connect_session_id,
                        max_request_body_bytes,
                        budget,
                    )
                    .await
                }
            }),
        )
        .with_upgrades();
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

async fn read_connect_preface(
    downstream: &mut TokioIo<hyper::upgrade::Upgraded>,
    out: &mut [u8; CONNECT_PREFACE_MAX_BYTES],
) -> std::io::Result<usize> {
    // Ignore leading CR/LF bytes before the tunneled protocol payload.
    // Some client/proxy stacks emit an extra line break between CONNECT and TLS payload.
    let mut seen_non_crlf = false;
    let mut payload_bytes = 0usize;
    for idx in 0..out.len() {
        downstream.read_exact(&mut out[idx..=idx]).await?;
        let byte = out[idx];
        if !seen_non_crlf {
            if byte == b'\r' || byte == b'\n' {
                continue;
            }
            seen_non_crlf = true;
            // Fast-path: if the first payload byte cannot be a TLS record content
            // type, we already know this is non-TLS and can fall back immediately.
            if !matches!(byte, 20..=23) {
                return Ok(idx + 1);
            }
        }
        payload_bytes += 1;
        if seen_non_crlf && payload_bytes >= 5 {
            // Have at least 5 bytes from first non-CRLF onward to validate TLS record header.
            return Ok(idx + 1);
        }
    }
    Ok(out.len())
}

fn first_non_crlf_index(preface: &[u8]) -> usize {
    preface
        .iter()
        .position(|b| *b != b'\r' && *b != b'\n')
        .unwrap_or(preface.len())
}

fn is_likely_tls_record_header(preface: &[u8], start: usize) -> bool {
    if start >= preface.len() {
        return false;
    }
    let rem = &preface[start..];
    if rem.len() < 5 {
        return false;
    }
    let content_type_ok = matches!(rem[0], 20..=23);
    let major_ok = rem[1] == 0x03;
    let minor_ok = rem[2] <= 0x04;
    let record_len = u16::from_be_bytes([rem[3], rem[4]]);
    let len_ok = record_len > 0;
    content_type_ok && major_ok && minor_ok && len_ok
}

fn hex_preface(preface: &[u8]) -> String {
    use std::fmt::Write as _;
    preface.iter().enumerate().fold(
        String::with_capacity(preface.len().saturating_mul(3)),
        |mut out, (idx, byte)| {
            if idx > 0 {
                out.push(' ');
            }
            let _ = write!(&mut out, "{byte:02x}");
            out
        },
    )
}

struct PrefetchedStream<T> {
    inner: T,
    prefetched: [u8; CONNECT_PREFACE_MAX_BYTES],
    prefetched_len: usize,
    prefetched_pos: usize,
}

impl<T> PrefetchedStream<T> {
    fn new(inner: T, prefetched: &[u8]) -> Self {
        let mut local = [0_u8; CONNECT_PREFACE_MAX_BYTES];
        let len = prefetched.len().min(local.len());
        local[..len].copy_from_slice(&prefetched[..len]);
        Self {
            inner,
            prefetched: local,
            prefetched_len: len,
            prefetched_pos: 0,
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefetchedStream<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefetched_pos < self.prefetched_len && buf.remaining() > 0 {
            let remaining = self.prefetched_len - self.prefetched_pos;
            let to_copy = remaining.min(buf.remaining());
            let start = self.prefetched_pos;
            let end = start + to_copy;
            buf.put_slice(&self.prefetched[start..end]);
            self.prefetched_pos = end;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefetchedStream<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn relay_connect_tunnel_from_stream_with_prefetch(
    mut downstream: TokioIo<hyper::upgrade::Upgraded>,
    target: &Authority,
    limits: ConnectRelayLimits,
    prefetched: &[u8],
) -> Result<TunnelRelayStats, String> {
    let mut upstream =
        tokio::time::timeout(limits.setup_timeout, TcpStream::connect(target.as_str()))
            .await
            .map_err(|_| {
                format!(
                    "upstream connect timed out after {} seconds for {target}",
                    limits.setup_timeout.as_secs()
                )
            })?
            .map_err(|e| format!("upstream connect failed for {target}: {e}"))?;
    if !prefetched.is_empty() {
        tokio::time::timeout(limits.setup_timeout, upstream.write_all(prefetched))
            .await
            .map_err(|_| {
                format!(
                    "upstream prefetch write timed out after {} seconds for {target}",
                    limits.setup_timeout.as_secs()
                )
            })?
            .map_err(|e| format!("upstream prefetch write failed for {target}: {e}"))?;
    }
    let (downstream_to_upstream_bytes, upstream_to_downstream_bytes) = tokio::time::timeout(
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
    Ok(TunnelRelayStats {
        downstream_to_upstream_bytes,
        upstream_to_downstream_bytes,
    })
}

#[derive(Clone)]
struct ConnectRelayLimits {
    setup_timeout: Duration,
    session_max: Duration,
}

fn connect_relay_limits(config: &ConnectRelayConfig) -> ConnectRelayLimits {
    ConnectRelayLimits {
        setup_timeout: config.setup_timeout,
        session_max: config.session_max,
    }
}

fn classify_connect_relay_failure(detail: &str) -> &'static str {
    let lowered = detail.to_ascii_lowercase();
    if lowered.contains("timed out") {
        "timeout"
    } else if lowered.contains("connection refused") {
        "refused"
    } else if lowered.contains("connection reset") {
        "reset"
    } else if lowered.contains("tls") || lowered.contains("handshake") {
        "tls_handshake"
    } else if lowered.contains("dns") || lowered.contains("name or service not known") {
        "dns"
    } else {
        "other"
    }
}

fn connect_established_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

async fn handle_mitm_https_request(
    mut req: Request<Incoming>,
    handler: Arc<RequestHandler>,
    target: ConnectTargetInfo,
    connect_session_id: &str,
    max_request_body_bytes: usize,
    budget: Arc<BodyBudget>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    if req.method() == http::Method::CONNECT {
        let detail = "MALFORMED_REQUEST: nested CONNECT is not supported";
        handler
            .emit_synthetic_deny(
                connect_session_id,
                "network.connect",
                &resource_label_from_host(&target.host),
                DenyReason::MalformedRequest,
                detail,
            )
            .await;
        return Ok(deny_response(StatusCode::BAD_REQUEST, detail));
    }

    if is_websocket_upgrade_request(&req) {
        return handle_mitm_websocket_upgrade_request(
            &mut req,
            handler,
            target,
            connect_session_id,
        )
        .await;
    }

    let (raw, body_guard) =
        match build_raw_https_request(req, &target, max_request_body_bytes, budget.clone()).await {
            Ok(result) => result,
            Err(detail) => {
                return Ok(deny_malformed(
                    &handler,
                    connect_session_id,
                    "raw.http",
                    &target.host,
                    &detail.to_string(),
                )
                .await);
            }
        };

    let session_id = match raw.headers.get_firma_session_id() {
        Ok(session_id) => session_id
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(connect_session_id)
            .to_owned(),
        Err(detail) => {
            return Ok(deny_malformed(
                &handler,
                connect_session_id,
                "raw.http",
                &target.host,
                &detail.to_string(),
            )
            .await);
        }
    };

    let response = match handler.handle(raw, &session_id).await {
        HandledResponse::Ok(response) | HandledResponse::Passthrough(response) => {
            dispatched_response(response)
        }
        HandledResponse::Deny {
            reason,
            detail,
            context: _,
        } => {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                session_id = %session_id,
                reason = ?reason,
                detail = %detail,
                "MITM HTTPS request denied by guard policy"
            );
            deny_json_response(
                StatusCode::FORBIDDEN,
                crate::handler::deny_body_json(reason, &detail),
            )
        }
        HandledResponse::Aborted { reason, detail } => deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(reason, &detail),
        ),
    };
    drop(body_guard);
    Ok(response)
}

#[expect(
    clippy::too_many_lines,
    reason = "fail-closed websocket MITM authorization and response handling are kept in one routine"
)]
async fn handle_mitm_websocket_upgrade_request(
    req: &mut Request<Incoming>,
    handler: Arc<RequestHandler>,
    target: ConnectTargetInfo,
    connect_session_id: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let raw = match build_raw_https_request_head(req, &target) {
        Ok(raw) => raw,
        Err(detail) => {
            return Ok(deny_malformed(
                &handler,
                connect_session_id,
                "raw.http",
                &target.host,
                &detail.to_string(),
            )
            .await);
        }
    };
    let session_id = match raw.headers.get_firma_session_id() {
        Ok(session_id) => session_id
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(connect_session_id)
            .to_owned(),
        Err(detail) => {
            return Ok(deny_malformed(
                &handler,
                connect_session_id,
                "raw.http",
                &target.host,
                &detail.to_string(),
            )
            .await);
        }
    };

    let authorization = handler.authorize_upgrade(raw, &session_id).await;
    let (credentials, audit_payload) = match authorization {
        UpgradeAuthorization::Allow {
            credentials,
            audit_payload,
        } => {
            tracing::debug!(
                host = %target.host,
                port = target.port,
                session_id = %session_id,
                "websocket upgrade authorized by sidecar policy"
            );
            (credentials, *audit_payload)
        }
        UpgradeAuthorization::Deny { reason, detail } => {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                session_id = %session_id,
                reason = ?reason,
                detail = %detail,
                "websocket upgrade denied by guard policy"
            );
            return Ok(deny_json_response(
                StatusCode::FORBIDDEN,
                crate::handler::deny_body_json(reason, &detail),
            ));
        }
        UpgradeAuthorization::Abort { reason, detail } => {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                session_id = %session_id,
                reason = ?reason,
                detail = %detail,
                "websocket upgrade aborted by guard policy"
            );
            return Ok(deny_json_response(
                StatusCode::GATEWAY_TIMEOUT,
                crate::handler::abort_body_json(reason, &detail),
            ));
        }
    };

    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_string();
    let handshake_request =
        build_upstream_handshake_request(req, &target, &path_and_query, &credentials);

    let mut upstream = match connect_upstream_tls(&target).await {
        Ok(stream) => stream,
        Err(detail) => {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                session_id = %session_id,
                detail = %detail,
                "websocket upstream TLS connect failed"
            );
            // Post-ALLOW relay failure: no upstream response was produced,
            // so this is an ABORT, not a policy DENY (FIR-46).
            let detail = format!("upstream websocket connect failed: {detail}");
            handler
                .emit_upgrade_abort_audit(audit_payload, AbortReason::ConnectorFailure, &detail)
                .await;
            return Ok(deny_json_response(
                StatusCode::GATEWAY_TIMEOUT,
                crate::handler::abort_body_json(AbortReason::ConnectorFailure, &detail),
            ));
        }
    };

    if let Err(e) = upstream.write_all(&handshake_request).await {
        tracing::warn!(
            host = %target.host,
            port = target.port,
            session_id = %session_id,
            error = %e,
            "websocket upstream handshake write failed"
        );
        // Post-ALLOW relay failure: no upstream response was produced,
        // so this is an ABORT, not a policy DENY (FIR-46).
        let detail = format!("upstream websocket handshake write failed: {e}");
        handler
            .emit_upgrade_abort_audit(audit_payload, AbortReason::ConnectorFailure, &detail)
            .await;
        return Ok(deny_json_response(
            StatusCode::GATEWAY_TIMEOUT,
            crate::handler::abort_body_json(AbortReason::ConnectorFailure, &detail),
        ));
    }

    let (status, response_headers, prefetched) = match read_http_response_head(&mut upstream).await
    {
        Ok(parsed) => parsed,
        Err(detail) => {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                session_id = %session_id,
                detail = %detail,
                "websocket upstream handshake read failed"
            );
            // Post-ALLOW relay failure: no upstream response was produced,
            // so this is an ABORT, not a policy DENY (FIR-46).
            let detail = format!("upstream websocket handshake read failed: {detail}");
            handler
                .emit_upgrade_abort_audit(audit_payload, AbortReason::ConnectorFailure, &detail)
                .await;
            return Ok(deny_json_response(
                StatusCode::GATEWAY_TIMEOUT,
                crate::handler::abort_body_json(AbortReason::ConnectorFailure, &detail),
            ));
        }
    };

    handler
        .emit_upgrade_audit(audit_payload, status, prefetched.len())
        .await;

    if status != 101 {
        tracing::warn!(
            host = %target.host,
            port = target.port,
            session_id = %session_id,
            status = status,
            "websocket upstream rejected protocol upgrade"
        );
        // Unlike the relay-failure branches above, the upstream produced a
        // completed response (a non-101 status). That is a relayed upstream
        // outcome, not a post-ALLOW abort, so it stays on the connector
        // network-error surface and the ALLOW audit emitted above stands.
        return Ok(deny_json_response(
            StatusCode::BAD_GATEWAY,
            crate::handler::deny_body_json(
                DenyReason::ConnectorNetworkError,
                &format!("upstream websocket upgrade rejected with status {status}"),
            ),
        ));
    }

    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(e) => {
                tracing::warn!("websocket downstream upgrade failed: {e}");
                return;
            }
        };
        let mut downstream = TokioIo::new(upgraded);
        if !prefetched.is_empty()
            && let Err(e) = downstream.write_all(&prefetched).await
        {
            tracing::warn!("websocket downstream prefetch write failed: {e}");
            return;
        }
        if let Err(e) = copy_bidirectional(&mut downstream, &mut upstream).await {
            if is_expected_tls_close_error(&e) {
                tracing::debug!("websocket MITM relay closed by peer (expected shutdown): {e}");
            } else {
                tracing::warn!("websocket MITM relay failed: {e}");
            }
        }
    });
    tracing::debug!(
        host = %target.host,
        port = target.port,
        session_id = %session_id,
        "websocket upgrade handled by sidecar relay"
    );

    Ok(build_websocket_switching_response(response_headers))
}

fn is_websocket_upgrade_request(req: &Request<Incoming>) -> bool {
    req.method() == http::Method::GET
        && header_contains_token(req.headers(), "connection", "upgrade")
        && req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

fn header_contains_token(headers: &hyper::HeaderMap, name: &str, token: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
}

fn is_expected_tls_close_error(error: &std::io::Error) -> bool {
    let msg = error.to_string();
    msg.contains("close_notify") || msg.contains("unexpected-eof")
}

fn build_upstream_handshake_request(
    req: &Request<Incoming>,
    target: &ConnectTargetInfo,
    path_and_query: &str,
    credentials: &firma_core::InjectedCredentials,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(format!("GET {path_and_query} HTTP/1.1\r\n").as_bytes());
    let mut has_host = false;
    for (name, value) in req.headers() {
        if name.as_str().eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if name.as_str().starts_with("x-firma-") {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !has_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(target.authority.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (k, v) in credentials.headers() {
        out.extend_from_slice(k.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

async fn connect_upstream_tls(
    target: &ConnectTargetInfo,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    #[cfg(test)]
    let test_upstream = TEST_WEBSOCKET_UPSTREAM
        .lock()
        .ok()
        .and_then(|upstream| upstream.clone())
        .filter(|upstream| upstream.authority == target.authority);
    #[cfg(test)]
    let upstream = if let Some(upstream) = test_upstream.as_ref() {
        TcpStream::connect(upstream.address).await
    } else {
        TcpStream::connect(target.authority.as_str()).await
    }
    .map_err(|e| format!("TCP connect failed for {}: {e}", target.authority))?;
    #[cfg(not(test))]
    let upstream = TcpStream::connect(target.authority.as_str())
        .await
        .map_err(|e| format!("TCP connect failed for {}: {e}", target.authority))?;
    #[cfg(test)]
    let roots = if let Some(upstream) = test_upstream {
        let mut roots = RootCertStore::empty();
        roots
            .add(upstream.certificate)
            .map_err(|error| format!("invalid test upstream certificate: {error}"))?;
        roots
    } else {
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>()
    };
    #[cfg(not(test))]
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<RootCertStore>();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|e| format!("invalid upstream server name {}: {e}", target.host))?;
    connector
        .connect(server_name, upstream)
        .await
        .map_err(|e| format!("TLS connect failed for {}: {e}", target.host))
}

#[cfg(test)]
#[derive(Clone)]
struct TestWebsocketUpstream {
    authority: Authority,
    address: SocketAddr,
    certificate: CertificateDer<'static>,
}

#[cfg(test)]
static TEST_WEBSOCKET_UPSTREAM: std::sync::Mutex<Option<TestWebsocketUpstream>> =
    std::sync::Mutex::new(None);

async fn read_http_response_head<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    const MAX_HEAD: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            return Err("early eof while reading response head".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEAD {
            return Err("response head exceeds 64KiB".to_string());
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let head = String::from_utf8(buf[..head_end].to_vec())
        .map_err(|_| "response head is not valid UTF-8".to_string())?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "missing status line".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "malformed status line".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("invalid status code: {e}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    let prefetched = buf[head_end..].to_vec();
    Ok((status, headers, prefetched))
}

fn build_websocket_switching_response(headers: Vec<(String, String)>) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in headers {
        if let (Ok(hn), Ok(hv)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(&value),
        ) {
            builder = builder.header(hn, hv);
        }
    }
    builder
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

async fn build_raw_https_request(
    req: Request<Incoming>,
    target: &ConnectTargetInfo,
    max_request_body_bytes: usize,
    budget: Arc<BodyBudget>,
) -> anyhow::Result<(RawRequest, BudgetGuard)> {
    let mut raw = build_raw_https_request_head(&req, target)?;
    let (body, guard) =
        read_body_with_limit(req.into_body(), max_request_body_bytes, budget).await?;
    raw.body = body;
    Ok((raw, guard))
}

fn build_raw_https_request_head(
    req: &Request<Incoming>,
    target: &ConnectTargetInfo,
) -> anyhow::Result<RawRequest> {
    let method = Method(req.method().clone());
    let host_value = req
        .headers()
        .get("host")
        .map(|v| v.to_str())
        .transpose()?
        .map(Authority::from_str)
        .transpose()?
        .or_else(|| req.uri().authority().map(Authority::from))
        .unwrap_or_else(|| target.authority.clone());
    let host_info = connect_target_info(&host_value)?;

    if !host_matches_connect_target(&host_info, target) {
        return Err(anyhow::anyhow!(
            "MALFORMED_REQUEST: tunneled host mismatch with CONNECT target"
        ));
    }

    let path = extract_path(req.uri().to_string().as_bytes());
    let headers = HeaderMap(req.headers().clone());

    Ok(RawRequest {
        method,
        // Strip the default :443 so MITM-decrypted HTTPS requests
        // expose the same bare hostname to the mapping table that
        // bypass-tunnel HTTP requests do — see the rationale in
        // `build_raw_request_head`.
        host: strip_default_port(host_info.authority, true)?,
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
    budget: Arc<BodyBudget>,
) -> anyhow::Result<(RawRequest, BudgetGuard)> {
    let mut raw = build_raw_request_head(&req, false)?;
    let (body, guard) =
        read_body_with_limit(req.into_body(), max_request_body_bytes, budget).await?;
    raw.body = body;
    Ok((raw, guard))
}

async fn read_body_with_limit(
    mut body: Incoming,
    max_request_body_bytes: usize,
    budget: Arc<BodyBudget>,
) -> anyhow::Result<(Option<Vec<u8>>, BudgetGuard)> {
    if let Some(upper) = body.size_hint().upper()
        && upper > max_request_body_bytes as u64
    {
        return Err(anyhow::anyhow!(
            "MALFORMED_REQUEST: request body exceeds {max_request_body_bytes} bytes limit"
        ));
    }

    let mut guard = BudgetGuard::new(budget.clone());
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|e| anyhow::anyhow!("MALFORMED_REQUEST: failed to read body: {e}"))?;
        if let Ok(data) = frame.into_data() {
            let new_len = out.len().checked_add(data.len()).ok_or_else(|| {
                guard.release(out.len());
                anyhow::anyhow!("MALFORMED_REQUEST: request body size overflow")
            })?;
            if new_len > max_request_body_bytes {
                guard.release(out.len());
                return Err(anyhow::anyhow!(
                    "MALFORMED_REQUEST: request body exceeds {max_request_body_bytes} bytes limit"
                ));
            }
            if !budget.try_acquire(data.len()) {
                guard.release(out.len());
                return Err(anyhow::anyhow!(
                    "MALFORMED_REQUEST: sidecar body budget exceeded"
                ));
            }
            out.extend_from_slice(data.as_ref());
        }
    }

    guard.release(out.len());
    Ok((if out.is_empty() { None } else { Some(out) }, guard))
}

fn build_raw_request_head(req: &Request<Incoming>, is_connect: bool) -> anyhow::Result<RawRequest> {
    let method = Method(req.method().clone());
    let host_with_port = host_with_default_port(req, is_connect)?;
    let path = if is_connect {
        "/".to_string()
    } else {
        extract_path(req.uri().to_string().as_bytes())
    };
    let headers = firma_http::HeaderMap(req.headers().clone());
    let is_https = is_connect
        || req
            .uri()
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"));

    // Strip the default scheme port so mapping rules and resource UIDs
    // can be written as bare hostnames ("paste.rs", not "paste.rs:443").
    // After MITM decryption clients commonly send `Host: paste.rs:443`,
    // and without this normalization the request would miss every
    // mapping rule and silently passthrough enforcement.
    let host = strip_default_port(host_with_port, is_https)?;

    Ok(RawRequest {
        method,
        host,
        headers,
        path,
        body: None,
        is_https,
    })
}

fn strip_default_port(host: Authority, is_https: bool) -> anyhow::Result<Authority> {
    let default_port = if is_https { ":443" } else { ":80" };
    // Leave IPv6 bracketed authorities and non-default ports alone.
    if host.as_str().starts_with('[') {
        return Ok(host);
    }
    let Some(host) = host.as_str().strip_suffix(default_port) else {
        return Ok(host);
    };
    Authority::from_str(host).map_err(anyhow::Error::from)
}

fn host_with_default_port(req: &Request<Incoming>, is_connect: bool) -> anyhow::Result<Authority> {
    if let Some(authority) = req
        .headers()
        .get("host")
        .map(|v| v.to_str())
        .transpose()?
        .map(Authority::from_str)
        .transpose()?
        .or_else(|| req.uri().authority().map(Authority::from))
    {
        return Ok(authority);
    }

    req.uri()
        .host()
        .map(|h| {
            let port = req
                .uri()
                .port_u16()
                .unwrap_or(if is_connect { 443 } else { 80 });
            Authority::from_str(&format!("{h}:{port}"))
        })
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("MALFORMED_REQUEST: missing host"))
}

/// Builds the fail-closed deny response for a CONNECT request whose head
/// could not be turned into a `RawRequest` (unparseable host, malformed
/// session id). Re-deriving the host here would fail identically when the
/// host itself is the problem, so this falls back to an empty host label.
async fn deny_malformed_connect(
    req: &Request<Incoming>,
    handler: &RequestHandler,
    detail: &str,
) -> Response<Full<Bytes>> {
    let host = host_with_default_port(req, true)
        .map(|authority| authority.to_string())
        .unwrap_or_default();
    deny_malformed(
        handler,
        &header_session_id(req),
        "network.connect",
        &host,
        detail,
    )
    .await
}

/// Builds a `host/` resource label for a synthetic deny audit event,
/// falling back to `?` when the host could not be determined.
fn resource_label_from_host(host: &str) -> String {
    if host.is_empty() {
        "?".to_string()
    } else {
        format!("{host}/")
    }
}

fn path_without_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(path, _)| path)
}

/// Best-effort extraction of the `x-firma-session-id` header for audit
/// attribution on pre-pipeline denials.
fn header_session_id(req: &Request<Incoming>) -> String {
    req.headers()
        .get("x-firma-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Emits a malformed-request DENY audit event and builds the 403 to
/// return, so pre-pipeline rejections still surface in `firma monitor`
/// (FIR-208).
async fn deny_malformed(
    handler: &RequestHandler,
    session_id: &str,
    action: &str,
    host: &str,
    detail: &str,
) -> Response<Full<Bytes>> {
    handler
        .emit_synthetic_deny(
            session_id,
            action,
            &resource_label_from_host(host),
            DenyReason::MalformedRequest,
            detail,
        )
        .await;
    deny_response(StatusCode::FORBIDDEN, detail)
}

fn connect_target(authority: &Authority) -> String {
    let h = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(443);
    if h.contains(':') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

fn dispatched_response(response: DispatchedResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers.iter() {
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
#[expect(
    clippy::option_if_let_else,
    reason = "absolute-form versus origin-form path parsing is clearer as one optional-prefix branch"
)]
fn extract_path(raw_path: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw_path);
    if let Some(rest) = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
    {
        rest.find('/')
            .map_or_else(|| "/".to_string(), |i| rest[i..].to_string())
    } else {
        s.into_owned()
    }
}

// Resolves the upstream [`HttpPeer`] from a [`RawRequest`].
//
// Parses `host` into address and port, defaulting to 443 for HTTPS
// and 80 for HTTP.
// Note: CONNECT routing is handled explicitly in `handle_connect_request`.

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use firma_identifiers::{AgentId, TokenId};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::*;
    use firma_config_schema::sidecar::TenancyMode;

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
        listener.unwrap()
    }

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
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
            token_id: "ctok_01j0000000e008000000000001"
                .parse()
                .expect("literal token id"),
            agent_id: "agt_01j0000000e008000000000001"
                .parse()
                .expect("literal agent id"),
            session_id: "_test_".parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    /// Builds a pipeline that ALLOWs POST requests to `host` at `path`.
    ///
    /// Uses a wildcard host pattern (`*`) combined with the concrete path
    /// so the rule matches regardless of port number in the host header.
    fn test_pipeline_allow(path: &str) -> Arc<EnforcementPipeline> {
        test_pipeline_allow_method(Method::POST, path)
    }

    fn test_pipeline_allow_method(method: Method, path: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(method),
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
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
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
                method: Some(Method::CONNECT),
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
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
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

    struct FailingCredentialInjector;

    #[async_trait::async_trait]
    impl crate::credential::CredentialInjector for FailingCredentialInjector {
        async fn inject(
            &self,
            _envelope: &ExecutionEnvelope,
            connector_id: &str,
            _target: &str,
        ) -> Result<InjectedCredentials, crate::credential::CredentialInjectionError> {
            Err(crate::credential::CredentialInjectionError::FetchFailed {
                connector_id: connector_id.to_string(),
                reason: "vault unavailable".to_string(),
            })
        }
    }

    /// Builds an ALLOW pipeline whose credential injection always fails, so
    /// `enforce()` returns ABORT after the call is authorized. Drives the
    /// post-ALLOW abort path through the proxy.
    fn test_pipeline_abort(path: &str) -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
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
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(FailingCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    /// Like [`test_pipeline_abort`] but for CONNECT, so the tunnel is
    /// authorized and then aborted by the failing credential injection.
    fn test_pipeline_abort_connect() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::CONNECT),
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
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(FailingCredentialInjector),
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
                method: Some(Method::POST),
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
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
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
                method: Some(Method::CONNECT),
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
            Arc::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
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

    /// Like [`test_handler`] but returns the audit receiver so tests can
    /// assert which audit events the proxy emitted.
    fn test_handler_with_audit(
        pipeline: Arc<EnforcementPipeline>,
    ) -> (
        Arc<RequestHandler>,
        tokio::sync::mpsc::Receiver<crate::audit::AuditPayload>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let handler = Arc::new(RequestHandler::new(
            pipeline,
            crate::handler::tests::test_connector_registry(),
            tx,
        ));
        (handler, rx)
    }

    /// Starts a minimal HTTP server that always returns `200 OK`.
    /// Returns the address it is listening on.
    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        let listener = listener.unwrap();
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
        let listener = listener.unwrap();
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
        let stream = stream.as_mut().unwrap();

        stream.write_all(request.as_bytes()).await.unwrap();

        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        for _ in 0..16 {
            match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut chunk)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
                Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).to_string()
    }

    async fn read_connect_response(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
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
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        mitm_config: HttpsMitmConfig,
        ca_dir: std::path::PathBuf,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<(), super::super::InterceptorError>>,
    ) {
        let interceptor = HttpInterceptor::new(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_https_mitm(mitm_config, ca_dir);
        let mitm_runtime = interceptor
            .build_mitm_runtime()
            .unwrap_or_else(|e| panic!("failed to build MITM runtime: {e}"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind proxy: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read proxy address: {e}"));
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            interceptor
                .run_with_listener_and_runtime(listener, handler, cancel_clone, mitm_runtime)
                .await
        });
        (addr, handle)
    }

    async fn start_proxy_with_mitm_and_body_limit(
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        mitm_config: HttpsMitmConfig,
        ca_dir: std::path::PathBuf,
        max_request_body_bytes: usize,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<(), super::super::InterceptorError>>,
    ) {
        let interceptor = HttpInterceptor::new(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_https_mitm(mitm_config, ca_dir)
            .with_max_request_body_bytes(max_request_body_bytes);
        let mitm_runtime = interceptor
            .build_mitm_runtime()
            .unwrap_or_else(|e| panic!("failed to build MITM runtime: {e}"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind proxy: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read proxy address: {e}"));
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            interceptor
                .run_with_listener_and_runtime(listener, handler, cancel_clone, mitm_runtime)
                .await
        });
        (addr, handle)
    }

    async fn start_proxy_with_budget(
        addr: SocketAddr,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
        max_request_body_bytes: usize,
        total_body_budget_bytes: usize,
    ) -> tokio::task::JoinHandle<Result<(), super::super::InterceptorError>> {
        let interceptor = HttpInterceptor::new(addr)
            .with_max_request_body_bytes(max_request_body_bytes)
            .with_total_body_budget_bytes(total_body_budget_bytes);
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

    async fn mock_slow_upstream(delay: Duration) -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            let mut buf = vec![0u8; 4096];
                            let _ = stream.read(&mut buf).await;
                            tokio::time::sleep(delay).await;
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

    static TEST_WEBSOCKET_UPSTREAM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct TestWebsocketUpstreamRegistration;

    impl Drop for TestWebsocketUpstreamRegistration {
        fn drop(&mut self) {
            if let Ok(mut upstream) = TEST_WEBSOCKET_UPSTREAM.lock() {
                *upstream = None;
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the complete CONNECT, downstream TLS, WebSocket upgrade, and upstream TLS flow is intentionally exercised in one fixture"
    )]
    async fn websocket_handshake_through_mitm_proxy() -> anyhow::Result<Vec<u8>> {
        let _lock = TEST_WEBSOCKET_UPSTREAM_LOCK.lock().await;
        let host = "websocket-regression.test";
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![host.to_string()])?;
        let certificate = CertificateDer::from(cert.der().to_vec());
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_address = upstream_listener.local_addr()?;
        let authority = Authority::from_str(&format!("{host}:443"))?;
        *TEST_WEBSOCKET_UPSTREAM
            .lock()
            .map_err(|_| anyhow::anyhow!("test upstream lock poisoned"))? =
            Some(TestWebsocketUpstream {
                authority,
                address: upstream_address,
                certificate,
            });
        let _registration = TestWebsocketUpstreamRegistration;
        let (handshake_tx, handshake_rx) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await?;
            let mut stream = tls_acceptor.accept(stream).await?;
            let mut handshake = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let read = stream.read(&mut chunk).await?;
                anyhow::ensure!(read > 0, "upstream closed before receiving the handshake");
                handshake.extend_from_slice(&chunk[..read]);
                if handshake.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = handshake_tx.send(handshake);
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: websocket\r\n\r\n",
                )
                .await?;
            stream.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        });

        let ca_dir = tempfile::tempdir()?;
        let cancel = CancellationToken::new();
        let (proxy_address, proxy) = start_proxy_with_mitm(
            test_handler(test_pipeline_allow_method(Method::GET, "/socket")),
            cancel.clone(),
            HttpsMitmConfig {
                enabled: true,
                intercept_hosts: vec![host.to_string()],
                strict_hosts: vec![host.to_string()],
                cert_ttl_secs: 300,
                cert_cache_capacity: 16,
                ..HttpsMitmConfig::default()
            },
            ca_dir.path().to_path_buf(),
        )
        .await;
        let mut stream = TcpStream::connect(proxy_address).await?;
        stream
            .write_all(
                format!(
                    "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nx-firma-session-id: _test_\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let response = read_connect_response(&mut stream).await;
        anyhow::ensure!(
            response.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200, got {response:?}"
        );
        let ca_path = ca_dir.path().join("firma-ca.crt");
        let mut stream = connect_tls_with_ca(stream, &ca_path, host).await;
        let mut request = format!(
            "GET /socket HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             x-firma-session-id: _test_\r\n\
             x-opaque: "
        )
        .into_bytes();
        request.push(0xff);
        request.extend_from_slice(b"\r\n\r\n");
        stream.write_all(&request).await?;
        let mut response = [0_u8; 512];
        let read =
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut response)).await??;
        anyhow::ensure!(
            response[..read].starts_with(b"HTTP/1.1 101"),
            "expected WebSocket 101, got {:?}",
            String::from_utf8_lossy(&response[..read])
        );
        let handshake = handshake_rx.await?;

        drop(stream);
        cancel.cancel();
        upstream.await??;
        proxy.await??;
        Ok(handshake)
    }

    #[tokio::test]
    async fn websocket_mitm_strips_internal_headers_from_upstream() -> anyhow::Result<()> {
        let handshake = websocket_handshake_through_mitm_proxy().await?;

        assert!(
            !handshake
                .windows(b"x-firma-session-id:".len())
                .any(|window| window.eq_ignore_ascii_case(b"x-firma-session-id:")),
            "internal Firma headers must not reach the upstream handshake"
        );
        Ok(())
    }

    #[tokio::test]
    async fn websocket_mitm_preserves_opaque_headers_upstream() -> anyhow::Result<()> {
        let handshake = websocket_handshake_through_mitm_proxy().await?;

        assert!(
            handshake
                .windows(b"x-opaque: \xff\r\n".len())
                .any(|window| window.eq_ignore_ascii_case(b"x-opaque: \xff\r\n")),
            "opaque agent header values must survive the upstream handshake"
        );
        Ok(())
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
    fn test_header_contains_token_parses_comma_separated_tokens() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "connection",
            hyper::header::HeaderValue::from_static("keep-alive, Upgrade"),
        );
        assert!(header_contains_token(&headers, "connection", "upgrade"));
        assert!(!header_contains_token(&headers, "connection", "close"));
    }

    #[tokio::test]
    async fn test_read_http_response_head_parses_status_headers_and_prefetch() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let _ = server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nprefetch",
                )
                .await;
        });

        let (status, headers, prefetched) = read_http_response_head(&mut client)
            .await
            .unwrap_or_else(|e| panic!("expected parsed response head: {e}"));
        assert_eq!(status, 101);
        assert!(
            headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("upgrade")
                    && v.eq_ignore_ascii_case("websocket"))
        );
        assert_eq!(prefetched, b"prefetch".to_vec());
    }

    #[test]
    fn test_connect_target_info_parses_ipv4_authority() {
        let info = connect_target_info(&Authority::from_static("api.openai.com:443"))
            .expect("valid authority");
        assert_eq!(info.host, "api.openai.com");
        assert_eq!(info.port, 443);
        assert_eq!(info.authority, Authority::from_static("api.openai.com:443"));
    }

    #[test]
    fn test_connect_target_info_parses_ipv6_authority() {
        let info =
            connect_target_info(&Authority::from_static("[::1]:8443")).expect("valid authority");
        assert_eq!(info.host, "::1");
        assert_eq!(info.port, 8443);
        assert_eq!(info.authority, Authority::from_static("[::1]:8443"));
    }

    #[test]
    fn test_host_matches_connect_target_requires_host_and_port_match() {
        let connect = connect_target_info(&Authority::from_static("api.openai.com:443"))
            .expect("valid authority");
        assert!(host_matches_connect_target(
            &connect_target_info(&Authority::from_static("api.openai.com:443"))
                .expect("valid authority"),
            &connect
        ));
        assert!(!host_matches_connect_target(
            &connect_target_info(&Authority::from_static("api.openai.com:8443"))
                .expect("valid authority"),
            &connect
        ));
        assert!(!host_matches_connect_target(
            &connect_target_info(&Authority::from_static("chat.openai.com:443"))
                .expect("valid authority"),
            &connect
        ));
    }

    #[test]
    fn test_classify_connect_relay_failure() {
        assert_eq!(
            classify_connect_relay_failure("upstream connect timed out after 10 seconds"),
            "timeout"
        );
        assert_eq!(
            classify_connect_relay_failure("upstream connect failed: Connection refused"),
            "refused"
        );
        assert_eq!(
            classify_connect_relay_failure("tunnel relay failed: Connection reset by peer"),
            "reset"
        );
        assert_eq!(
            classify_connect_relay_failure("downstream TLS handshake failed: bad cert"),
            "tls_handshake"
        );
        assert_eq!(
            classify_connect_relay_failure("dns resolution failed"),
            "dns"
        );
    }

    // ── pipeline sanity checks ─────────────────────────────────────────

    #[test]
    fn test_strip_default_port() {
        // HTTPS default port stripped, non-default kept.
        assert_eq!(
            strip_default_port(Authority::from_static("paste.rs:443"), true)
                .expect("valid authority"),
            Authority::from_static("paste.rs")
        );
        assert_eq!(
            strip_default_port(Authority::from_static("paste.rs:8443"), true)
                .expect("valid authority"),
            Authority::from_static("paste.rs:8443")
        );
        assert_eq!(
            strip_default_port(Authority::from_static("api.openai.com:443"), true)
                .expect("valid authority"),
            Authority::from_static("api.openai.com")
        );

        // HTTP default port stripped, HTTPS port left alone on http path.
        assert_eq!(
            strip_default_port(Authority::from_static("example.com:80"), false)
                .expect("valid authority"),
            Authority::from_static("example.com")
        );
        assert_eq!(
            strip_default_port(Authority::from_static("example.com:443"), false)
                .expect("valid authority"),
            Authority::from_static("example.com:443")
        );

        // Bare host left alone.
        assert_eq!(
            strip_default_port(Authority::from_static("example.com"), true)
                .expect("valid authority"),
            Authority::from_static("example.com")
        );

        // IPv6 bracketed authorities are left alone.
        assert_eq!(
            strip_default_port(Authority::from_static("[::1]:443"), true).expect("valid authority"),
            Authority::from_static("[::1]:443")
        );
    }

    #[tokio::test]
    async fn test_pipeline_allow_matches_with_port_in_host() {
        let pipeline = test_pipeline_allow("/v1/chat/completions");
        let raw = RawRequest {
            method: Method::POST,
            host: Authority::from_static("127.0.0.1:9999"),
            path: "/v1/chat/completions".to_string(),
            headers: HeaderMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: false,
        };
        let (decision, _payload) = pipeline.enforce(&raw, "_test_").await;
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
             X-Firma-Session-Id: _test_\r\n\
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
    async fn test_proxy_aborts_with_gateway_timeout() {
        let proxy_addr = free_addr();
        // Credential injection fails before dispatch, so no upstream is
        // contacted; any host that matches the wildcard ALLOW rule works.
        let host = "api.openai.com";
        let handler = test_handler(test_pipeline_abort("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-Firma-Session-Id: _test_\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {{}}"
        );

        let response = proxy_response(proxy_addr, &request).await;
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(status, 504, "post-ALLOW abort should return 504");
        let body = response
            .find("\r\n\r\n")
            .map(|i| &response[i + 4..])
            .unwrap_or_default();
        let parsed: serde_json::Value =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("abort body invalid JSON: {e}"));
        assert_eq!(parsed["aborted"], serde_json::Value::Bool(true));
        assert_eq!(parsed["reason"], "CREDENTIAL_INJECTION_FAILED");

        cancel.cancel();
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
    async fn test_proxy_connect_aborts_with_gateway_timeout() {
        let (target_addr, target_cancel) = mock_connect_target().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", target_addr.port());
        // CONNECT is authorized, then credential injection fails → ABORT.
        let handler = test_handler(test_pipeline_abort_connect());
        let cancel = CancellationToken::new();
        let server_handle = start_proxy(proxy_addr, handler, cancel.clone()).await;

        let request = format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-Firma-Session-Id: _test_\r\n\
             \r\n"
        );

        let status = proxy_request(proxy_addr, &request).await;
        assert_eq!(status, 504, "aborted CONNECT should return 504, not tunnel");

        cancel.cancel();
        target_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_mitm_intercepts_and_applies_l7_deny() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
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

        let (proxy_addr, server_handle) = start_proxy_with_mitm(
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
    async fn test_proxy_connect_mitm_non_strict_falls_back_for_non_tls_payload() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let handler = test_handler(test_pipeline_allow_connect());
        let cancel = CancellationToken::new();

        let mitm_config = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec!["localhost".to_string()],
            // Non-strict host should fail open to blind tunnel when payload is non-TLS.
            strict_hosts: vec![],
            cert_ttl_secs: 300,
            cert_cache_capacity: 16,
            ..HttpsMitmConfig::default()
        };

        let (target_addr, target_cancel) = mock_connect_target().await;
        let (proxy_addr, server_handle) = start_proxy_with_mitm(
            handler,
            cancel.clone(),
            mitm_config,
            ca_tempdir.path().to_path_buf(),
        )
        .await;

        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to proxy: {e}"));
        let host = format!("localhost:{}", target_addr.port());
        let connect_req = format!(
            "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nx-firma-session-id: _test_\r\n\r\n"
        );
        stream
            .write_all(connect_req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("failed to write CONNECT request: {e}"));
        let connect_response = read_connect_response(&mut stream).await;
        assert!(
            connect_response.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200, got: {connect_response:?}"
        );

        // Send a non-TLS payload. MITM path should auto-fallback (non-strict host)
        // and preserve raw CONNECT tunnel semantics.
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
    async fn test_proxy_connect_mitm_tolerates_crlf_preface_before_tls() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
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

        let (proxy_addr, server_handle) = start_proxy_with_mitm(
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

        // Repro shape seen in the field: CRLF emitted before TLS preface.
        stream
            .write_all(b"\r\n")
            .await
            .unwrap_or_else(|e| panic!("failed to write CRLF preface: {e}"));

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
            "expected L7 deny over MITM path even with CRLF preface, got: {response}"
        );

        cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_mitm_non_strict_non_tls_still_enforces_connect_policy() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        // Deny all CONNECT destinations.
        let handler = test_handler(test_pipeline_deny_connect_for_host("*"));
        let cancel = CancellationToken::new();

        let mitm_config = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec!["localhost".to_string()],
            strict_hosts: vec![],
            cert_ttl_secs: 300,
            cert_cache_capacity: 16,
            ..HttpsMitmConfig::default()
        };

        let (proxy_addr, server_handle) = start_proxy_with_mitm(
            handler,
            cancel.clone(),
            mitm_config,
            ca_tempdir.path().to_path_buf(),
        )
        .await;

        let status = proxy_request(
            proxy_addr,
            "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nx-firma-session-id: _test_\r\n\r\n",
        )
        .await;
        assert_eq!(
            status, 403,
            "non-strict MITM host must still enforce CONNECT policy before any fallback"
        );

        cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_mitm_rejects_oversized_tunneled_body() {
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
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

        let (proxy_addr, server_handle) = start_proxy_with_mitm_and_body_limit(
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

        let (proxy_addr, server_handle) = start_proxy_with_mitm(
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

    #[tokio::test]
    async fn test_proxy_connect_strict_mitm_preflight_failure_emits_deny_audit() {
        // Regression (FIR-208): a strict-MITM preflight failure is a
        // fail-closed network-layer DENY. It must surface in monitor, so
        // the proxy has to emit an audit event — not just return 403.
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let (handler, mut audit_rx) = test_handler_with_audit(test_pipeline_allow_connect());
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

        let (proxy_addr, server_handle) = start_proxy_with_mitm(
            handler,
            cancel.clone(),
            mitm_config,
            ca_tempdir.path().to_path_buf(),
        )
        .await;

        let request =
            format!("CONNECT {connect_authority} HTTP/1.1\r\nHost: {connect_authority}\r\n\r\n");
        let _ = proxy_response(proxy_addr, &request).await;

        let payload = audit_rx.try_recv().unwrap_or_else(|e| {
            panic!("expected a deny audit event for fail-closed preflight: {e}")
        });
        assert_eq!(payload.decision, crate::audit::Decision::Deny);
        assert!(
            payload.deny_reason.contains("HTTPS_MITM_SETUP_FAILED"),
            "deny audit should carry the fail-closed detail, got {:?}",
            payload.deny_reason
        );
        assert!(
            payload.resource.contains(&invalid_dns_host),
            "deny audit should identify the target host, got {:?}",
            payload.resource
        );

        cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_connect_non_strict_mitm_preflight_failure_enforces_connect_decision() {
        // Non-strict MITM eligible host whose TLS preflight fails must NOT
        // silently fall back to a blind tunnel. The CONNECT-level policy must
        // run; if it denies, the client must receive a 403 instead of a 200.
        let ca_tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let invalid_dns_host = "exa_mple.com".to_string();
        let connect_authority = format!("{invalid_dns_host}:443");

        let handler = test_handler(test_pipeline_deny_connect_for_host("*"));
        let cancel = CancellationToken::new();

        // Intercept-eligible but NOT in strict_hosts → non-strict path.
        let mitm_config = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec![invalid_dns_host.clone()],
            strict_hosts: vec![],
            cert_ttl_secs: 300,
            cert_cache_capacity: 16,
            ..HttpsMitmConfig::default()
        };

        let (proxy_addr, server_handle) = start_proxy_with_mitm(
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
            "non-strict MITM preflight failure must enforce CONNECT, not blind-tunnel-bypass: {response}"
        );

        cancel.cancel();
        let _ = server_handle.await;
    }

    // ── BodyBudget unit tests ──────────────────────────────────────────

    #[test]
    fn test_body_budget_acquire_within_ceiling() {
        let budget = BodyBudget::new(16);
        assert!(budget.try_acquire(8));
        assert!(budget.try_acquire(8));
        assert!(!budget.try_acquire(1));
    }

    #[test]
    fn test_body_budget_release_allows_reacquire() {
        let budget = BodyBudget::new(8);
        assert!(budget.try_acquire(8));
        assert!(budget.try_release(8));
        assert!(budget.try_acquire(8));
    }

    #[test]
    fn test_body_budget_acquire_zero_always_succeeds() {
        let budget = BodyBudget::new(0);
        assert!(budget.try_acquire(0));
    }

    #[test]
    fn test_body_budget_release_zero_is_noop() {
        let budget = BodyBudget::new(8);
        assert!(budget.try_acquire(4));
        assert!(budget.try_release(0));
        assert!(budget.try_acquire(4));
    }

    // ── Body-budget integration tests ──────────────────────────────────

    #[tokio::test]
    async fn test_proxy_rejects_request_when_body_budget_exhausted() {
        let (upstream_addr, upstream_cancel) = mock_slow_upstream(Duration::from_millis(500)).await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        let budget = 4usize;
        let max_body = 4usize;
        let server_handle =
            start_proxy_with_budget(proxy_addr, handler, cancel.clone(), max_body, budget).await;

        let session_a = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-Firma-Session-Id: _test_\r\n\
             Content-Length: 4\r\n\
             \r\n\
             AAAA"
        );
        let session_b = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-Firma-Session-Id: _test_\r\n\
             Content-Length: 4\r\n\
             \r\n\
             BBBB"
        );

        let mut stream_a = TcpStream::connect(proxy_addr).await.unwrap();
        stream_a.write_all(session_a.as_bytes()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response_b = proxy_response(proxy_addr, &session_b).await;
        let status_b = response_b
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(
            status_b, 403,
            "expected 403 for budget-exhausted request, got: {response_b}"
        );
        assert!(
            response_b.contains("body budget exceeded"),
            "expected budget-exceeded message, got: {response_b}"
        );

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_proxy_body_budget_released_after_request_completes() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let proxy_addr = free_addr();
        let host = format!("127.0.0.1:{}", upstream_addr.port());
        let handler = test_handler(test_pipeline_allow("/v1/chat/completions"));
        let cancel = CancellationToken::new();

        let budget = 4usize;
        let max_body = 4usize;
        let server_handle =
            start_proxy_with_budget(proxy_addr, handler, cancel.clone(), max_body, budget).await;

        let request = format!(
            "POST http://{host}/v1/chat/completions HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-Firma-Session-Id: _test_\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {{}}"
        );

        let status1 = proxy_request(proxy_addr, &request).await;
        assert_eq!(status1, 200, "first request should succeed");

        let status2 = proxy_request(proxy_addr, &request).await;
        assert_eq!(
            status2, 200,
            "second request should succeed after budget is released"
        );

        cancel.cancel();
        upstream_cancel.cancel();
        let _ = server_handle.await;
    }
}
