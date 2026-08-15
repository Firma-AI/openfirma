//! Request handler.
//!
//! Owns the post-enforcement call path shared by all interceptors:
//! enforcement, dispatch for allowed traffic, denial translation, and audit
//! payload emission. When a secret gateway is configured (see
//! [`RequestHandler::with_gateway_client`]), the same path also rehydrates
//! outbound secret placeholders and masks inbound secret values; when HTTP
//! secret providers are configured (see
//! [`RequestHandler::with_http_secret_providers`]), it additionally
//! intercepts and mints placeholders for matching HTTP-vault responses.

use std::{borrow::Cow, collections::HashMap, fmt::Display, str::FromStr, sync::Arc};

use firma_core::{
    AbortReason, ActionParams, AgentId, ConnectorError, ConnectorResponse, DenyReason,
    ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams,
    InjectedCredentials, SecretMatcher, SessionId, TransportView, envelope::InvalidMethod,
};
use firma_http::HeaderMap;
use firma_secret_provider::{
    CompiledMatcher, MatchingResolution, PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX_LEN,
    SecretPlaceholder, gateway::client::GatewayClient, spec::http::HttpIntegrationSpec,
};
use headers::HeaderMapExt;
use tokio::sync::mpsc;

use crate::{
    audit::{AuditPayload, Decision},
    body_encoding::{self, SupportedEncoding},
    composio::{ComposioAction, ComposioCatalogs, DecodeResult, decode, is_protected_host},
    connector::ConnectorRegistry,
    normalizer::{
        NormalizedEnvelope,
        mapping::{glob_match, normalize_host_pattern},
    },
    pipeline::{
        CompositeActionResult, CompositeDisposition, EnforcementDecision, EnforcementPipeline,
        RawRequest, audit_payload_from_decision, monitor_override,
    },
    secret_rewrite::{ContentType, mask_body, rehydrate_body},
    secret_store::SidecarSecretStore,
};

/// Response produced by the transport-agnostic request handler.
#[derive(Debug)]
pub enum HandledResponse {
    /// Request was allowed and the target replied.
    Ok(DispatchedResponse),
    /// Non-protected request was forwarded without enforcement.
    Passthrough(DispatchedResponse),
    /// Request was blocked before dispatch.
    Deny {
        /// Denial reason selected by the enforcement pipeline.
        reason: DenyReason,
        /// Human-readable denial detail.
        detail: String,
        /// Structural context of the denial. `Tool` means the body is
        /// returned as a tool result (agent loop continues); `Api`
        /// means a synchronous terminal failure (HTTP 403 for HTTP
        /// interceptors). See FEP §5.1–§5.2.
        ///
        /// In V1 all wired interceptors serve HTTP-class traffic and
        /// treat both contexts identically (403 + `deny_body_json`)
        /// per the task 008 V1 scope note. The field is populated so
        /// a future tool-call transport can read it without any
        /// further handler/pipeline change.
        // V1 interceptors discard `context` (Tool and Api get the
        // same 403 response). Tests read it. `cfg_attr` keeps the
        // non-test build warning-clean without marking the attribute
        // unfulfilled during test compilation.
        context: DenialContext,
    },
    /// Request was approved by enforcement but the dispatch could not
    /// complete. The agent-visible outcome is a gateway-timeout class
    /// error; the token state stays `ACTIVE` (no terminal transition).
    Aborted {
        /// Typed abort reason.
        reason: AbortReason,
        /// Human-readable abort detail.
        detail: String,
    },
}

/// CONNECT-specific decision surface used by the HTTP proxy interceptor.
#[derive(Debug)]
pub enum ConnectDecision {
    /// CONNECT target is allowed and tunneling may proceed.
    Allow,
    /// CONNECT target is denied before tunnel establishment.
    Deny {
        /// Denial reason selected by the enforcement pipeline.
        reason: DenyReason,
        /// Human-readable denial detail.
        detail: String,
    },
    /// CONNECT target was authorized, then blocked by a post-ALLOW abort.
    Abort {
        /// Abort reason selected by the enforcement pipeline.
        reason: AbortReason,
        /// Human-readable abort detail.
        detail: String,
    },
}

/// Authorization result for HTTP upgrade requests (for example WebSocket
/// handshakes) where the interceptor owns upstream byte relay.
#[derive(Debug)]
pub enum UpgradeAuthorization {
    /// Upgrade request is authorized. The interceptor must complete upstream
    /// relay and then call [`RequestHandler::emit_upgrade_audit`].
    Allow {
        /// Credentials injected by policy pipeline for this request.
        credentials: InjectedCredentials,
        /// Pending audit payload captured at authorization time.
        audit_payload: Box<AuditPayload>,
    },
    /// Upgrade request denied by policy pipeline.
    Deny {
        /// Denial reason selected by the enforcement pipeline.
        reason: DenyReason,
        /// Human-readable denial detail.
        detail: String,
    },
    /// Upgrade request blocked by a post-ALLOW abort.
    Abort {
        /// Abort reason selected by the enforcement pipeline.
        reason: AbortReason,
        /// Human-readable abort detail.
        detail: String,
    },
}

/// Structural context of a denial.
///
/// Derived from the `NormalizedEnvelope` carried on
/// [`EnforcementDecision::Deny`]. Interceptors select the transport
/// response shape from this value without re-inspecting the envelope.
///
/// See FEP §5.1–§5.2 for the behavioural contract:
/// - `Tool`: agent loop continues; body is a structured tool result.
/// - `Api`: synchronous terminal failure; body is the canonical deny
///   JSON (HTTP 403 for HTTP interceptors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialContext {
    /// Denial originated from a tool-call transport.
    Tool,
    /// Denial originated from an API-class transport (HTTP, DB, etc.)
    /// or before normalization produced an envelope (fail-closed).
    Api,
}

/// Maps an [`ActionParams`] variant to its [`DenialContext`].
///
/// `ToolUse` → `Tool`; `Http` / `DbQuery` → `Api`.
#[must_use]
fn denial_context_from_params(params: &ActionParams) -> DenialContext {
    match params {
        ActionParams::ToolUse(_) => DenialContext::Tool,
        ActionParams::Http(_) | ActionParams::DbQuery(_) => DenialContext::Api,
    }
}

/// Derives the denial context from a normalized envelope.
///
/// Fail-closed default: when no envelope is available (pre-normalization
/// denial such as `MalformedRequest` or `UnclassifiedIntent`), returns
/// [`DenialContext::Api`] — the hard-block shape. A tool denial on a
/// non-tool call would silently mask the failure.
#[must_use]
fn denial_context_of(envelope: Option<&NormalizedEnvelope>) -> DenialContext {
    envelope.map_or(DenialContext::Api, |e| {
        denial_context_from_params(&e.intent.params)
    })
}

/// Builds the fail-closed denial for a request whose secret placeholders
/// could not be fully resolved before dispatch.
///
/// Overrides `audit_payload` to record a `FailClosed` denial in place of the
/// pre-dispatch decision it was built from, mirroring the dispatch-level
/// override used when a `MODIFY` cannot be applied — dispatch never runs, so
/// nothing is forwarded with unresolved placeholder tokens in its body.
#[must_use]
fn rehydrate_fail_closed_response(
    audit_payload: &mut AuditPayload,
    context: DenialContext,
    error: &str,
) -> HandledResponse {
    let detail = format!("secret placeholders could not be resolved; failing closed: {error}");
    audit_payload.decision = Decision::Deny;
    audit_payload.deny_reason = format!("{}: {detail}", DenyReason::FailClosed);
    HandledResponse::Deny {
        reason: DenyReason::FailClosed,
        detail,
        context,
    }
}

/// Builds the abort for a request whose target matches a `Blocked` HTTP
/// secret provider path.
///
/// Overrides `audit_payload` to record the abort in place of the
/// pre-dispatch decision it was built from — dispatch never runs, so the
/// blocked command never reaches the upstream vault.
#[must_use]
fn http_secret_blocked_response(
    audit_payload: &mut AuditPayload,
    provider_id: &str,
) -> HandledResponse {
    let detail = format!("HTTP secret provider \"{provider_id}\" blocks this command");
    audit_payload.decision = Decision::Abort;
    audit_payload.deny_reason = format!(
        "{}: {detail}",
        AbortReason::CredentialInjectionBlocked.code()
    );
    HandledResponse::Aborted {
        reason: AbortReason::CredentialInjectionBlocked,
        detail,
    }
}

/// Builds the abort for a response whose secret-handling layer (HTTP secret
/// provider interception or store-based masking) could not safely forward
/// the body — e.g. a response whose HTTP secret provider extracted a secret
/// and substituted its placeholder, but then failed to push that secret to
/// the broker (see [`RequestHandler::rewrite_with_http_intercept`]), or a
/// response that couldn't be decoded to mask a rehydrated secret's echo (see
/// [`mask_dispatched`]). Overrides `audit_payload` in place of the
/// dispatched-response outcome, since the response can no longer be
/// forwarded as-is.
#[must_use]
fn secret_abort_response(
    audit_payload: &mut AuditPayload,
    reason: AbortReason,
    detail: String,
) -> HandledResponse {
    audit_payload.decision = Decision::Abort;
    audit_payload.deny_reason = format!("{}: {detail}", reason.code());
    HandledResponse::Aborted { reason, detail }
}

/// Builds the structured denial for [`EnforcementDecision::Deny`], logging a
/// renewal hint when the capability token has expired.
#[must_use]
fn deny_response(
    reason: DenyReason,
    detail: String,
    envelope: Option<&NormalizedEnvelope>,
    request: &RawRequest,
    session_id: &str,
) -> HandledResponse {
    if reason == DenyReason::TokenExpired {
        tracing::warn!(
            method = %request.method,
            host = %request.host,
            path = %request.path,
            session_id = %session_id,
            detail = %detail,
            "request denied because capability token expired; renew token (same session_id) and reload sidecar capability source"
        );
    }
    let context = denial_context_of(envelope);
    HandledResponse::Deny {
        reason,
        detail,
        context,
    }
}

/// Builds the structured denial for AARM R4 `STEP_UP`: the call is blocked
/// pending human approval or stronger authentication.
#[must_use]
fn step_up_response(challenge: String, envelope: Option<&NormalizedEnvelope>) -> HandledResponse {
    let context = denial_context_of(envelope);
    HandledResponse::Deny {
        reason: DenyReason::StepUpRequired,
        detail: challenge,
        context,
    }
}

/// Builds the structured denial for AARM R4 `DEFER`: the call is blocked and
/// should be retried after `retry_after_ms`.
#[must_use]
fn defer_response(retry_after_ms: u64, envelope: Option<&NormalizedEnvelope>) -> HandledResponse {
    let context = denial_context_of(envelope);
    HandledResponse::Deny {
        reason: DenyReason::Deferred,
        detail: format!("retry_after_ms: {retry_after_ms}"),
        context,
    }
}

/// Checks the two conditions that must block dispatch even though
/// enforcement itself allowed the request: unresolved secret placeholders
/// ([`rehydrate_fail_closed_response`]) and a `Blocked` HTTP secret provider
/// path ([`http_secret_blocked_response`]). Returns `None` when neither
/// applies and the caller may proceed to dispatch.
#[must_use]
fn pre_dispatch_gate(
    rehydrate_result: &Result<Option<SidecarSecretStore>, String>,
    blocked_provider: Option<&str>,
    context: DenialContext,
    audit_payload: &mut AuditPayload,
) -> Option<HandledResponse> {
    if let Err(detail) = rehydrate_result {
        return Some(rehydrate_fail_closed_response(
            audit_payload,
            context,
            detail,
        ));
    }
    if let Some(provider_id) = blocked_provider {
        return Some(http_secret_blocked_response(audit_payload, provider_id));
    }
    None
}

/// Serialize a denial into the canonical JSON body used by HTTP-facing
/// interceptors.
#[must_use]
pub(crate) fn deny_body_json(reason: DenyReason, detail: &str) -> Vec<u8> {
    serde_json::json!({
        "denied": true,
        "reason": reason,
        "detail": detail,
    })
    .to_string()
    .into_bytes()
}

/// Serialize a tool-call denial into the canonical JSON body shape
/// defined by FEP §5.1.
///
/// The agent receives this as it would any other tool result; the
/// session continues. No HTTP status semantics are implied — the body
/// is the tool's structured result.
#[must_use]
// Public API reserved for a future tool-call interceptor; V1 has no
// tool-call transport so the function is only called from tests.
#[cfg(test)]
fn tool_denial_body_json(
    reason: DenyReason,
    detail: &str,
    action_class: &str,
    tool_name: &str,
) -> Vec<u8> {
    serde_json::json!({
        "denied": true,
        "reason": reason,
        "action_class": action_class,
        "tool_name": tool_name,
        "detail": detail,
    })
    .to_string()
    .into_bytes()
}

/// Serialize an abort into the canonical JSON body used by HTTP-facing
/// interceptors.
///
/// Agents key off the `aborted` boolean flag to distinguish abort
/// responses from upstream-reported errors.
#[must_use]
pub(crate) fn abort_body_json(reason: AbortReason, detail: &str) -> Vec<u8> {
    serde_json::json!({
        "aborted": true,
        "reason": reason.code(),
        "detail": detail,
    })
    .to_string()
    .into_bytes()
}

/// Connector-side metadata captured after dispatch so the handler
/// can enrich the audit payload with the call outcome (status,
/// latency, body size) and, when needed, override the pipeline's
/// pre-dispatch decision (connector-originated DENY / ABORT).
struct DispatchOutcome {
    decision_override: Option<DecisionOverride>,
    dispatch_status: i32,
    dispatch_latency_us: i64,
    response_size: i64,
}

/// Proto-wire decision + `deny_reason` string applied to the audit
/// payload when the connector layer overrides the pipeline's Allow
/// outcome.
struct DecisionOverride {
    decision: Decision,
    deny_reason: String,
}

impl DispatchOutcome {
    /// Produces a [`DispatchOutcome`] for a connector-originated ABORT.
    ///
    /// No upstream response was received, so the numeric fields stay zero.
    fn abort_from_connector(reason: AbortReason, detail: &str) -> Self {
        Self {
            decision_override: Some(DecisionOverride {
                decision: Decision::Abort,
                deny_reason: format!("{}: {detail}", reason.code()),
            }),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
        }
    }

    /// Applies the outcome to the audit payload in place.
    fn enrich(self, payload: &mut AuditPayload) {
        self.enrich_ref(payload);
    }

    /// Applies a shared dispatch outcome to one child audit payload.
    fn enrich_ref(&self, payload: &mut AuditPayload) {
        payload.dispatch_status = self.dispatch_status;
        payload.dispatch_latency_us = self.dispatch_latency_us;
        payload.response_size = self.response_size;
        if let Some(decision) = &self.decision_override {
            payload.decision = decision.decision;
            payload.deny_reason.clone_from(&decision.deny_reason);
        }
    }
}

fn dispatch_latency_us(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

fn i64_from_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Extracts the host portion of a resource URL for connector
/// selection.
///
/// Returns `None` when the resource cannot be parsed as an absolute
/// URL; callers default to the registry default in that case.
fn extract_host(resource: &str) -> Option<String> {
    reqwest::Url::parse(resource)
        .ok()
        .and_then(|url| url.host_str().map(std::string::ToString::to_string))
}

fn dispatched_from(response: ConnectorResponse) -> DispatchedResponse {
    DispatchedResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    }
}

/// Response returned by the current raw-forward placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchedResponse {
    /// Target HTTP status code.
    pub(crate) status: u16,
    /// Target response headers.
    pub(crate) headers: HeaderMap,
    /// Target response body.
    pub(crate) body: Vec<u8>,
}

/// Scan `body` for [`PLACEHOLDER_PREFIX`]-prefixed placeholder tokens and
/// return a deduplicated list. Each token runs from the prefix through
/// consecutive alphanumeric characters, matching [`SecretPlaceholder`]'s
/// Crockford-base32 encoding (never `_`, `-`, or other separators).
///
/// Dedup is `Vec::contains`, an O(n²) scan over the *distinct* tokens found
/// so far — deliberately, not a `HashSet`: callers zip this list
/// positionally against `resolve_batch`'s results, so insertion order must
/// be preserved, and `n` is bounded by how many distinct placeholders one
/// request body plausibly carries (single digits), where the constant
/// factor of a `Vec` scan beats hashing.
///
/// Two placeholders with no separator between them (e.g. `fsp_XXXfsp_YYY`)
/// put the second one's `fsp_` prefix inside the greedily-consumed
/// alphanumeric run of the first. Parsing only the maximal run as one token
/// would fail (it's oversized) and, worse, skipping past it on failure would
/// skip the embedded second prefix too, dropping both placeholders.
///
/// Instead, on a failed parse this shrinks the candidate span one byte at a
/// time from the right and retries, down to the bare prefix. Crockford-base32
/// [`SecretPlaceholder`] encoding is fixed-length — a token is exactly
/// `PLACEHOLDER_PREFIX.len() + PLACEHOLDER_SUFFIX_LEN` bytes — so at most one
/// candidate span can ever parse successfully, and it can never extend past
/// `path_start + PLACEHOLDER_SUFFIX_LEN`. Shrinking only within that bound
/// still lands on the first placeholder's true end, i.e. right where a second
/// merged `fsp_` prefix starts, but caps the per-prefix work at O(26)
/// candidates instead of O(run length): without the bound, an adversarial
/// body of `fsp_` plus a long alphanumeric run that never forms a valid token
/// would force a quadratic `from_utf8` scan of every shrink candidate.
fn collect_placeholders(body: &[u8]) -> Vec<SecretPlaceholder> {
    let prefix_len = PLACEHOLDER_PREFIX.len();
    let mut result = Vec::new();
    let mut i = 0;
    while i + prefix_len <= body.len() {
        if body[i..].starts_with(PLACEHOLDER_PREFIX.as_bytes()) {
            let path_start = i + prefix_len;
            let mut end = path_start;
            while end < body.len() && body[end].is_ascii_alphanumeric() {
                end += 1;
            }
            let max_candidate_end = end.min(path_start + PLACEHOLDER_SUFFIX_LEN);
            let found = (path_start..=max_candidate_end)
                .rev()
                .find_map(|candidate_end| {
                    let token = std::str::from_utf8(&body[i..candidate_end]).ok()?;
                    let placeholder = SecretPlaceholder::from_str(token).ok()?;
                    Some((placeholder, candidate_end))
                });
            match found {
                Some((placeholder, consumed_end)) => {
                    if !result.contains(&placeholder) {
                        result.push(placeholder);
                    }
                    i = consumed_end;
                }
                // No candidate span parsed: don't skip past the whole
                // failed run, it may still contain another prefix's worth
                // of bytes (see doc comment above).
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    result
}

/// An HTTP secret intercept abort: the reason code plus a human-readable
/// detail, mirroring the `HandledResponse::Aborted` shape it eventually
/// becomes.
type InterceptAbort = (AbortReason, String);

/// Resolves `dispatched.body` to a plaintext view the secret matcher can
/// scan, decoding a supported `Content-Encoding` first (see
/// [`body_encoding`]), and returns the encoding alongside it so the caller
/// can re-encode after rewriting.
///
/// Errs (fail closed) when the encoding isn't one [`body_encoding`] can
/// decode, or when decoding a supported one fails — either way the body
/// can't be inspected, so it must not be forwarded unexamined.
async fn decode_for_inspection<'a>(
    dispatched: &'a DispatchedResponse,
    provider_id: &str,
    max_decompressed_body_bytes: usize,
) -> Result<(Cow<'a, [u8]>, Option<SupportedEncoding>), InterceptAbort> {
    body_encoding::decode_body(
        &dispatched.body,
        &dispatched.headers,
        max_decompressed_body_bytes,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            provider_id = %provider_id,
            %error,
            "HTTP secret intercept: failed to decode response body; aborting rather than \
             forward a body the matcher cannot inspect"
        );
        let detail = format!(
            "HTTP secret provider \"{provider_id}\" response body could not be decoded for \
             secret inspection: {error}"
        );
        (AbortReason::CredentialInjectionFailed, detail)
    })
}

/// Re-encodes a rewritten body back to `encoding` (a no-op when `None`) so
/// the forwarded response's declared `Content-Encoding` still matches its
/// bytes.
async fn recompress_after_rewrite(
    rewritten: Vec<u8>,
    encoding: Option<SupportedEncoding>,
    provider_id: &str,
) -> Result<Vec<u8>, InterceptAbort> {
    body_encoding::encode_body(rewritten, encoding)
        .await
        .map_err(|error| {
            tracing::error!(
                provider_id = %provider_id,
                %error,
                "HTTP secret intercept: failed to re-compress rewritten response body"
            );
            let detail = format!(
                "HTTP secret provider \"{provider_id}\" extracted a secret but failed to \
                 re-compress the response body: {error}"
            );
            (AbortReason::CredentialInjectionFailed, detail)
        })
}

/// Masks `dispatched.body` against `store`'s known secrets.
///
/// Decodes a supported `Content-Encoding` before scanning for an echoed
/// secret and re-encodes the masked result afterward, so a compressed
/// response can't defeat masking (see [`body_encoding`]). Resolves the
/// response's content type from its `Content-Type` header, falling back to
/// sniffing the decoded body and then to [`ContentType::Raw`] when neither
/// is conclusive — masking still runs on unrecognized content as a raw byte
/// scan rather than skipping it outright, since declining to mask would risk
/// forwarding a secret re-echo unredacted.
///
/// Fails closed (`Err`) when the body's declared `Content-Encoding` can't be
/// decoded or the masked result can't be re-encoded: this function only ever
/// runs when `store` is non-empty, i.e. a real secret was rehydrated into
/// this exchange, so a body that can't be inspected here is a genuine leak
/// risk, not just a missed convenience.
async fn mask_dispatched(
    mut dispatched: DispatchedResponse,
    store: &SidecarSecretStore,
    max_decompressed_body_bytes: usize,
) -> Result<DispatchedResponse, InterceptAbort> {
    if dispatched.body.is_empty() {
        return Ok(dispatched);
    }
    let (plaintext, encoding) = body_encoding::decode_body(
        &dispatched.body,
        &dispatched.headers,
        max_decompressed_body_bytes,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            %error,
            "secret masking: failed to decode response body; aborting rather than forward a \
             body that cannot be checked for a rehydrated secret's echo"
        );
        let detail = format!("response body could not be decoded for secret masking: {error}");
        (AbortReason::CredentialInjectionFailed, detail)
    })?;

    let content_type_val = dispatched.headers.typed_get::<headers::ContentType>();
    let content_type =
        ContentType::resolve(content_type_val, &plaintext).unwrap_or(ContentType::Raw);
    let ops = store.mask_ops(&plaintext, content_type);
    if ops.is_empty() {
        return Ok(dispatched);
    }

    let masked = mask_body(&plaintext, &ops);
    let final_body = body_encoding::encode_body(masked, encoding)
        .await
        .map_err(|error| {
            tracing::error!(%error, "secret masking: failed to re-compress masked response body");
            let detail = format!("masked response body failed to re-compress: {error}");
            (AbortReason::CredentialInjectionFailed, detail)
        })?;

    if dispatched.headers.contains_key("content-length") {
        dispatched
            .headers
            .insert("content-length", http::HeaderValue::from(final_body.len()));
    }
    dispatched.body = final_body;
    Ok(dispatched)
}

/// Applies [`mask_dispatched`] to `response`'s body when it carries one
/// (`Ok`/`Passthrough`), converting a masking failure into an abort via
/// [`secret_abort_response`] rather than forwarding an unmaskable body.
async fn mask_handled_response(
    response: HandledResponse,
    store: &SidecarSecretStore,
    max_decompressed_body_bytes: usize,
    audit_payload: &mut AuditPayload,
) -> HandledResponse {
    match response {
        HandledResponse::Ok(d) => {
            match mask_dispatched(d, store, max_decompressed_body_bytes).await {
                Ok(d) => HandledResponse::Ok(d),
                Err((reason, detail)) => secret_abort_response(audit_payload, reason, detail),
            }
        }
        HandledResponse::Passthrough(d) => {
            match mask_dispatched(d, store, max_decompressed_body_bytes).await {
                Ok(d) => HandledResponse::Passthrough(d),
                Err((reason, detail)) => secret_abort_response(audit_payload, reason, detail),
            }
        }
        other => other,
    }
}

/// HTTP-origin secret interception: the Sidecar-local mirror of an HTTP
/// vault registry entry, used to mint placeholders locally (see
/// [`RequestHandler::intercept_http_secrets`]). A provider being listed here
/// (mirroring firma-run's `http_secret_providers` config) is itself the
/// authorization — no separate policy check gates it.
struct HttpSecretMediation {
    providers: Vec<HttpIntegrationSpec>,
}

/// Default cap on how large a request or response body may grow when
/// decompressed for secret rehydration/masking, used when the handler isn't
/// explicitly configured via [`RequestHandler::with_max_decompressed_body_bytes`].
/// Mirrors [`crate::config::SidecarConfig`]'s own default for
/// `interceptor.max_decompressed_body_bytes`.
const DEFAULT_MAX_DECOMPRESSED_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Shared handler used by every interceptor.
pub struct RequestHandler {
    audit_sink_sender: mpsc::Sender<AuditPayload>,
    composio_catalogs: Option<Arc<ComposioCatalogs>>,
    connector_registry: Arc<ConnectorRegistry>,
    pipeline: Arc<EnforcementPipeline>,
    gateway_client: Option<Arc<GatewayClient>>,
    http_secret_mediation: Option<HttpSecretMediation>,
    max_decompressed_body_bytes: usize,
}

impl RequestHandler {
    /// Constructs a request handler from the enforcement pipeline, the
    /// connector registry, and the audit payload channel.
    #[must_use]
    pub fn new(
        pipeline: Arc<EnforcementPipeline>,
        connector_registry: Arc<ConnectorRegistry>,
        audit_sink_sender: mpsc::Sender<AuditPayload>,
    ) -> Self {
        Self {
            audit_sink_sender,
            composio_catalogs: None,
            connector_registry,
            pipeline,
            gateway_client: None,
            http_secret_mediation: None,
            max_decompressed_body_bytes: DEFAULT_MAX_DECOMPRESSED_BODY_BYTES,
        }
    }

    /// Overrides the cap on decompressed request/response body size (see
    /// [`DEFAULT_MAX_DECOMPRESSED_BODY_BYTES`]) applied when decoding a
    /// `Content-Encoding`'d body for secret rehydration or masking. Guards
    /// against a decompression bomb forcing an unbounded allocation.
    #[must_use]
    pub fn with_max_decompressed_body_bytes(mut self, max_decompressed_body_bytes: usize) -> Self {
        self.max_decompressed_body_bytes = max_decompressed_body_bytes;
        self
    }

    /// Enable secret placeholder rehydration via the firma-run secret gateway.
    ///
    /// When set, the handler resolves [`PLACEHOLDER_PREFIX`]-prefixed tokens
    /// in outbound request bodies before dispatch and masks raw secret
    /// values in inbound response bodies before returning them to the agent.
    #[must_use]
    pub fn with_gateway_client(mut self, gc: GatewayClient) -> Self {
        self.gateway_client = Some(Arc::new(gc));
        self
    }

    /// Enable HTTP-origin secret interception for the given `providers` (the
    /// Sidecar's mirror of firma-run's HTTP-shaped `secret_providers`
    /// config, synthesized in at startup). A no-op when `providers` is
    /// empty. Requires [`Self::with_gateway_client`] to have been called
    /// too: when a provider's matcher matches a response but no gateway
    /// client is configured, the extracted secret cannot be pushed to the
    /// broker, so the response is aborted fail-closed rather than forwarded
    /// unmediated (see [`RequestHandler::intercept_http_secrets`]).
    #[must_use]
    pub fn with_http_secret_providers(mut self, providers: Vec<HttpIntegrationSpec>) -> Self {
        if !providers.is_empty() {
            self.http_secret_mediation = Some(HttpSecretMediation { providers });
        }
        self
    }

    /// Resolve [`PLACEHOLDER_PREFIX`]-prefixed placeholder tokens in the request body.
    ///
    /// Decodes a supported `Content-Encoding` before scanning for
    /// placeholders and re-encodes the rehydrated result afterward, so a
    /// compressed request body's placeholders are still found and resolved
    /// (see [`body_encoding`]). When the body's declared encoding can't be
    /// decoded, falls back to scanning the raw (still-encoded) bytes exactly
    /// as before this fallback existed — for genuinely compressed data this
    /// essentially never matches [`PLACEHOLDER_PREFIX`], so unrelated
    /// traffic in an encoding this layer doesn't support keeps working
    /// unaffected. Only if that raw scan *does* turn up something
    /// placeholder-shaped does this fail closed (see below), since at that
    /// point rehydrating without being able to reliably re-encode the result
    /// would risk forwarding a mix of real secrets and literal placeholder
    /// tokens.
    ///
    /// Queries the secret gateway for each unique placeholder found, builds a
    /// per-request [`SidecarSecretStore`], and rewrites the body with the real
    /// secret bytes. The store is returned for use in response masking.
    ///
    /// Returns `Ok(None)` when no gateway is configured or the body contains
    /// no placeholders. Returns `Err` when the body contains placeholders
    /// that cannot be fully resolved and substituted. The caller must fail
    /// closed on `Err` and never dispatch the request: forwarding a body
    /// with some placeholders rehydrated and others left literal (or all
    /// left literal) can trigger partial side effects upstream — e.g.
    /// writing, overwriting, or deleting the wrong secret — so evaluation of
    /// every placeholder must succeed before anything is sent out.
    async fn rehydrate_request(
        &self,
        mut request: RawRequest,
    ) -> (RawRequest, Result<Option<SidecarSecretStore>, String>) {
        let Some(ref gateway_client) = self.gateway_client else {
            return (request, Ok(None));
        };

        let body = match &request.body {
            Some(b) if !b.is_empty() => b.clone(),
            _ => return (request, Ok(None)),
        };

        let (plaintext, encoding, decode_error) = match body_encoding::decode_body(
            &body,
            &request.headers,
            self.max_decompressed_body_bytes,
        )
        .await
        {
            Ok((plaintext, encoding)) => (plaintext, encoding, None),
            Err(error) => (Cow::Borrowed(body.as_slice()), None, Some(error)),
        };

        let placeholders = collect_placeholders(&plaintext);
        if placeholders.is_empty() {
            return (request, Ok(None));
        }

        if let Some(error) = decode_error {
            let detail = format!(
                "secret gateway: request body looks like it contains placeholders but its \
                 content-encoding could not be decoded to rehydrate them safely: {error}"
            );
            tracing::warn!("{detail}");
            return (request, Err(detail));
        }

        let host = request.host.clone();

        let mut store = SidecarSecretStore::new();
        match gateway_client.resolve_batch(&placeholders, host).await {
            Ok(Ok(results)) => {
                for (placeholder, secret) in placeholders.iter().zip(results) {
                    if let Err(e) = store.insert(placeholder.clone(), secret) {
                        let detail = format!(
                            "secret gateway: failed to build store entry for {placeholder}: {e}"
                        );
                        tracing::warn!("{detail}");
                        return (request, Err(detail));
                    }
                }
            }
            Ok(Err(e)) => {
                let detail = format!("secret gateway: placeholder resolution failed: {e}");
                tracing::warn!("{detail}");
                return (request, Err(detail));
            }
            Err(e) => {
                let detail = format!("secret gateway: batch resolve failed: {e}");
                tracing::warn!("{detail}");
                return (request, Err(detail));
            }
        }

        if store.len() != placeholders.len() {
            let detail = format!(
                "secret gateway: resolved {} of {} placeholders",
                store.len(),
                placeholders.len()
            );
            tracing::warn!("{detail}");
            return (request, Err(detail));
        }

        let content_type_val = request.headers.typed_get::<headers::ContentType>();
        let ct = ContentType::resolve(content_type_val, &plaintext).unwrap_or_else(|_| {
            // Unrecognized content type: fall back to raw byte
            // substitution rather than failing closed, mirroring the
            // masking side's fallback (a placeholder-bearing plaintext
            // body that isn't sniffable — no leading `{`/`[`/`<` and no
            // `=` — still substitutes in place safely, exactly as a Raw
            // response body does).
            tracing::warn!(
                "secret gateway: unrecognized request content type; rehydrating as raw bytes"
            );
            ContentType::Raw
        });
        let ops = store.rehydrate_ops(&plaintext);
        let rehydrated = rehydrate_body(&plaintext, ct, &ops);
        let final_body = match body_encoding::encode_body(rehydrated, encoding).await {
            Ok(body) => body,
            Err(error) => {
                let detail = format!(
                    "secret gateway: rehydrated request body failed to re-compress: {error}"
                );
                tracing::warn!("{detail}");
                return (request, Err(detail));
            }
        };
        if request.headers.contains_key("content-length") {
            request
                .headers
                .insert("content-length", http::HeaderValue::from(final_body.len()));
        }
        request.body = Some(final_body);

        (request, Ok(Some(store)))
    }

    /// Install validated pinned Composio catalogs.
    #[must_use]
    pub fn with_composio_catalogs(mut self, catalogs: Arc<ComposioCatalogs>) -> Self {
        self.composio_catalogs = Some(catalogs);
        self
    }

    /// Handles one normalized transport request.
    ///
    /// The handler emits exactly one audit payload per call after dispatch
    /// work has completed for allow and passthrough outcomes.
    pub async fn handle(&self, request: RawRequest, session_id: &str) -> HandledResponse {
        if let Some(response) = self.handle_composio(&request, session_id).await {
            return response;
        }

        let (decision, mut audit_payload) = self.pipeline.enforce(&request, session_id).await;

        // Only decisions that go on to dispatch need their body rehydrated;
        // skip the gateway round-trip entirely for a decision that's already
        // going to deny/abort/block the call — it wastes a connection and
        // needlessly reveals the request's placeholder tokens to the broker.
        let dispatches = matches!(
            decision,
            EnforcementDecision::Allow { .. }
                | EnforcementDecision::Modify { .. }
                | EnforcementDecision::Passthrough { .. }
        );
        let (request, rehydrate_result) = if dispatches {
            self.rehydrate_request(request).await
        } else {
            (request, Ok(None))
        };

        // Resolved before dispatch, not just for post-dispatch rewrite: a
        // `Blocked` HTTP secret provider path must never reach the
        // connector. Resolving it only after dispatch (as the response
        // rewrite in `intercept_http_secrets` does for `Matcher`) would let
        // the destructive command already execute upstream before the
        // sidecar aborted the response.
        let blocked_provider =
            self.http_secret_provider_decision(&request)
                .and_then(|(provider_id, resolution)| {
                    matches!(resolution, MatchingResolution::Blocked).then_some(provider_id)
                });

        let response = self
            .dispatch_decision(
                decision,
                &rehydrate_result,
                blocked_provider,
                &request,
                session_id,
                &mut audit_payload,
            )
            .await;

        // Interception (extracting genuine HTTP-vault secrets) runs before
        // masking (redacting rehydration echoes): if a rehydrated request's
        // secret gets echoed back by an HTTP-vault response, masking-first
        // would turn that echo into a placeholder *before* interception's
        // matcher ever saw it, so interception would extract and push the
        // literal placeholder string as if it were a fresh secret — losing
        // the real value and corrupting the broker's mapping. Running
        // interception first means it always sees the true response bytes.
        let response = self
            .intercept_http_secrets(&request, response, &mut audit_payload)
            .await;

        let response = match rehydrate_result.ok().flatten() {
            Some(store) => {
                mask_handled_response(
                    response,
                    &store,
                    self.max_decompressed_body_bytes,
                    &mut audit_payload,
                )
                .await
            }
            None => response,
        };

        if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
            tracing::error!("failed to send audit event: {err}");
        }

        response
    }

    /// Routes an [`EnforcementDecision`] to its dispatch path, or to a
    /// pre-dispatch denial/abort when `rehydrate_result` is `Err` or
    /// `blocked_provider` is set and the decision would otherwise have
    /// dispatched the request.
    async fn dispatch_decision(
        &self,
        decision: EnforcementDecision,
        rehydrate_result: &Result<Option<SidecarSecretStore>, String>,
        blocked_provider: Option<&str>,
        request: &RawRequest,
        session_id: &str,
        audit_payload: &mut AuditPayload,
    ) -> HandledResponse {
        match decision {
            EnforcementDecision::Allow {
                envelope,
                credentials,
                ..
            } => match pre_dispatch_gate(
                rehydrate_result,
                blocked_provider,
                denial_context_from_params(&envelope.intent.params),
                audit_payload,
            ) {
                Some(response) => response,
                None => {
                    self.dispatch_allow(*envelope, request, credentials, audit_payload)
                        .await
                }
            },
            EnforcementDecision::Modify {
                envelope,
                credentials,
                modifications,
                ..
            } => match pre_dispatch_gate(
                rehydrate_result,
                blocked_provider,
                denial_context_from_params(&envelope.intent.params),
                audit_payload,
            ) {
                Some(response) => response,
                None => {
                    self.dispatch_modify(
                        *envelope,
                        request,
                        credentials,
                        modifications,
                        audit_payload,
                    )
                    .await
                }
            },
            EnforcementDecision::Passthrough { .. } => match pre_dispatch_gate(
                rehydrate_result,
                blocked_provider,
                DenialContext::Api,
                audit_payload,
            ) {
                Some(response) => response,
                None => {
                    self.dispatch_passthrough(request, session_id, audit_payload)
                        .await
                }
            },
            EnforcementDecision::Deny {
                reason,
                detail,
                envelope,
                ..
            } => deny_response(reason, detail, envelope.as_ref(), request, session_id),
            EnforcementDecision::Abort { reason, detail, .. } => {
                HandledResponse::Aborted { reason, detail }
            }
            EnforcementDecision::StepUp {
                challenge,
                envelope,
                ..
            } => step_up_response(challenge, envelope.as_ref()),
            EnforcementDecision::Defer {
                retry_after_ms,
                envelope,
                ..
            } => defer_response(retry_after_ms, envelope.as_ref()),
        }
    }

    /// Resolves the HTTP secret provider entry (if any) whose host/path glob
    /// matches `request`, and how its response should be handled.
    ///
    /// Synchronous — pure matcher lookup, no I/O — so it is safe to call
    /// before dispatch to gate on [`MatchingResolution::Blocked`], as well as
    /// after dispatch (in [`Self::intercept_http_secrets`]) to select the
    /// response-rewrite matcher.
    fn http_secret_provider_decision<'a>(
        &'a self,
        request: &RawRequest,
    ) -> Option<(&'a str, MatchingResolution<'a>)> {
        let mediation = self.http_secret_mediation.as_ref()?;
        let host = normalize_host_pattern(request.host.as_str());
        mediation.providers.iter().find_map(|p| {
            glob_match(&normalize_host_pattern(&p.host), &host)
                .then(|| (p.provider_id.as_str(), p.matcher_for(&request.path)))
        })
    }

    /// HTTP-origin secret interception: if `request` matches a configured
    /// HTTP secret provider whose matcher applies to this path, run the
    /// provider's matcher over the response body, mint placeholders locally,
    /// push each extracted secret to firma-run's broker, and substitute the
    /// placeholders into the body before it reaches the agent. A matching
    /// provider entry is itself the authorization — no separate policy check
    /// gates it.
    ///
    /// `MatchingResolution::Blocked` paths are gated before dispatch (see the
    /// `blocked_provider` check in `handle`), not here — by the time a
    /// response reaches this function the request has already gone out, so
    /// this layer only ever rewrites, never blocks.
    ///
    /// A no-op — `response` passes through unchanged — when no HTTP secret
    /// providers are configured, no entry matches `request`, the entry
    /// resolves to `PassThrough`/`Blocked`, or `response` was never
    /// dispatched (the pipeline denied/aborted before reaching the
    /// connector, so no vault body exists to mediate). A matcher that fails
    /// to compile or extract also falls back to forwarding the response as
    /// dispatched (fail-open on the interception layer itself — the
    /// underlying request was already permitted by the main enforcement
    /// pipeline, and nothing sensitive was actually found).
    ///
    /// A `Matcher` entry that *did* match but has no gateway configured is
    /// different: the response was dispatched from a provider explicitly
    /// flagged as sensitive, so a body that can't be mediated must not reach
    /// the agent — this aborts rather than forwards. A failure to *push* an
    /// already-extracted secret to the broker is handled the same way: see
    /// [`Self::rewrite_with_http_intercept`].
    async fn intercept_http_secrets(
        &self,
        request: &RawRequest,
        response: HandledResponse,
        audit_payload: &mut AuditPayload,
    ) -> HandledResponse {
        let Some((provider_id, decision)) = self.http_secret_provider_decision(request) else {
            return response;
        };

        let matcher = match decision {
            MatchingResolution::Matcher(matcher) => matcher,
            MatchingResolution::PassThrough | MatchingResolution::Blocked => return response,
        };

        // Only `Ok`/`Passthrough` carry a body that actually reached the
        // vault; anything else (deny/abort/step-up/defer) never dispatched,
        // so there's nothing here to mediate or fail closed on.
        if !matches!(
            response,
            HandledResponse::Ok(_) | HandledResponse::Passthrough(_)
        ) {
            return response;
        }

        let Some(gateway_client) = self.gateway_client.as_ref() else {
            let detail = format!(
                "HTTP secret provider \"{provider_id}\" matched but no secret gateway is \
                 configured"
            );
            tracing::error!(
                provider_id = %provider_id,
                "HTTP secret provider matched but no secret gateway is configured; aborting \
                 rather than forward a possibly sensitive response unmediated"
            );
            return secret_abort_response(
                audit_payload,
                AbortReason::CredentialInjectionFailed,
                detail,
            );
        };

        let rewrite = async |dispatched: DispatchedResponse| {
            self.rewrite_with_http_intercept(dispatched, provider_id, matcher, gateway_client)
                .await
        };

        match response {
            HandledResponse::Ok(dispatched) => match rewrite(dispatched).await {
                Ok(dispatched) => HandledResponse::Ok(dispatched),
                Err((reason, detail)) => secret_abort_response(audit_payload, reason, detail),
            },
            HandledResponse::Passthrough(dispatched) => match rewrite(dispatched).await {
                Ok(dispatched) => HandledResponse::Passthrough(dispatched),
                Err((reason, detail)) => secret_abort_response(audit_payload, reason, detail),
            },
            other => other,
        }
    }

    /// Runs `provider`'s matcher over `dispatched.body`, minting a
    /// placeholder for each extracted secret and pushing it to firma-run's
    /// broker via `gateway`. Returns `dispatched` with the body rewritten to
    /// placeholders.
    ///
    /// Returns `Ok(dispatched)` unmodified when the matcher fails to compile
    /// or the extraction pass itself fails — fail-open, since no secret has
    /// been extracted or promised to the agent yet.
    ///
    /// Returns `Err` when the matcher successfully extracted a secret and
    /// substituted its placeholder into the body, but the push to the broker
    /// that would make the placeholder resolvable failed: the substitution
    /// already happened in-place as the single-pass rewrite scanned, so at
    /// that point the only way to avoid handing the agent a placeholder the
    /// broker never learned (an unresolvable token, indistinguishable from a
    /// silently lost credential) is to abort the whole response rather than
    /// forward it.
    async fn rewrite_with_http_intercept(
        &self,
        mut dispatched: DispatchedResponse,
        provider_id: &str,
        matcher: &SecretMatcher,
        gateway: &GatewayClient,
    ) -> Result<DispatchedResponse, InterceptAbort> {
        let (plaintext, encoding) =
            decode_for_inspection(&dispatched, provider_id, self.max_decompressed_body_bytes)
                .await?;

        let matcher = match CompiledMatcher::compile(matcher) {
            Ok(m) => m,
            Err(error) => {
                tracing::warn!(
                    provider_id = %provider_id,
                    %error,
                    "HTTP secret intercept: matcher compile failed; forwarding unmodified"
                );
                return Ok(dispatched);
            }
        };

        // Minting must happen synchronously — the single-pass rewrite
        // substitutes the placeholder in place of the plaintext value as it
        // scans — so pushes to the broker are collected here and sent after.
        // `item_domain` is empty unless the matcher's `domain_selector`
        // extracted one from the item; it is deliberately *not* defaulted to
        // the vault's own request host — an HTTP vault's response is a
        // credential meant for later use against some other downstream
        // host, not the vault itself, so an unscoped (wildcard) push is the
        // useful default here, mirroring a CLI intercept whose matcher has
        // no `domain_selector`.
        let mut pushes = Vec::new();
        let rewritten = matcher.rewrite(&plaintext, &mut |_name, value, item_domain, _item| {
            let placeholder = SecretPlaceholder::new();
            pushes.push((placeholder.clone(), value, item_domain));
            placeholder
        });

        let rewritten = match rewritten {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(
                    provider_id = %provider_id,
                    %error,
                    "HTTP secret intercept: extraction failed; forwarding unmodified"
                );
                return Ok(dispatched);
            }
        };

        // Push every extracted secret to the broker before the rewritten
        // body is re-encoded and forwarded. A push failure here aborts the
        // whole response — the agent never sees a placeholder the broker
        // doesn't know — but secrets pushed earlier in this loop stay
        // registered in the broker even though the response is discarded:
        // the gateway protocol has no remove operation to roll them back, so
        // the error below names them. That is stale dictionary state only
        // (a random placeholder no agent has ever been handed), never a
        // forwarded token.
        let mut pushed_placeholders = Vec::new();
        let total_pushes = pushes.len();
        for (placeholder, value, item_domain) in pushes {
            if let Err(error) = gateway
                .push_secret(placeholder.clone(), value, item_domain)
                .await
            {
                tracing::error!(
                    provider_id = %provider_id,
                    %placeholder,
                    %error,
                    pushed = pushed_placeholders.len(),
                    "HTTP secret intercept: failed to push extracted secret to broker; \
                     aborting rather than hand the agent an unresolvable placeholder"
                );
                let detail = format!(
                    "HTTP secret provider \"{provider_id}\" extracted {total_pushes} secret(s) \
                     but failed to push one to the broker ({placeholder}): {error}. {} \
                     already-pushed placeholder(s) stay registered in the broker because the \
                     gateway protocol has no remove operation to roll them back.",
                    pushed_placeholders.len()
                );
                return Err((AbortReason::CredentialInjectionFailed, detail));
            }
            pushed_placeholders.push(placeholder);
        }

        let final_body = recompress_after_rewrite(rewritten, encoding, provider_id).await?;

        if dispatched.headers.contains_key("content-length") {
            dispatched
                .headers
                .insert("content-length", http::HeaderValue::from(final_body.len()));
        }
        dispatched.body = final_body;
        Ok(dispatched)
    }

    /// Dispatches a `PASSTHROUGH` decision: builds a minimal envelope and
    /// forwards without enforcement credentials. Re-wraps `Ok` as `Passthrough`
    /// so callers can distinguish authorized traffic from non-protected traffic.
    async fn dispatch_passthrough(
        &self,
        request: &RawRequest,
        session_id: &str,
        audit_payload: &mut AuditPayload,
    ) -> HandledResponse {
        match passthrough_envelope(request, session_id) {
            Ok(envelope) => {
                let (response, outcome) =
                    self.dispatch(envelope, InjectedCredentials::empty()).await;
                outcome.enrich(audit_payload);
                if let HandledResponse::Ok(dispatched) = response {
                    HandledResponse::Passthrough(dispatched)
                } else {
                    response
                }
            }
            Err(err) => {
                let detail = err.to_string();
                audit_payload.decision = Decision::Abort;
                audit_payload.deny_reason =
                    format!("{}: {detail}", AbortReason::ConnectorInvalidRequest.code());
                handle_error(detail)
            }
        }
    }

    /// Dispatches an `ALLOW` decision through the connector registry.
    async fn dispatch_allow(
        &self,
        envelope: ExecutionEnvelope,
        request: &RawRequest,
        credentials: InjectedCredentials,
        audit_payload: &mut AuditPayload,
    ) -> HandledResponse {
        let mut dispatch_envelope = envelope;
        hydrate_dispatch_http_fields(&mut dispatch_envelope, request);
        let (response, outcome) = self.dispatch(dispatch_envelope, credentials).await;
        outcome.enrich(audit_payload);
        response
    }

    /// Returns `Some` when `request` targets a configured Composio catalog
    /// host, handling it entirely through the Composio-specific decision
    /// path below instead of the main `handle` flow.
    ///
    /// This bypasses secret rehydration, response masking, and HTTP secret
    /// provider interception entirely: a Composio-protected request body
    /// carrying a gateway placeholder is forwarded upstream as a literal
    /// token, and any secret the response echoes back is never masked. This
    /// is a pre-existing asymmetry with the main path, not something this
    /// function newly introduces — flagged here since it is easy to miss.
    async fn handle_composio(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> Option<HandledResponse> {
        let catalogs = self.composio_catalogs.as_deref()?;
        match decode(request, catalogs) {
            DecodeResult::Unrelated => None,
            DecodeResult::Passthrough => {
                Some(self.handle_composio_passthrough(request, session_id).await)
            }
            DecodeResult::Actions(actions) => Some(
                self.handle_composio_actions(request, session_id, &actions)
                    .await,
            ),
            DecodeResult::Deny(denial) => {
                let decision = EnforcementDecision::Deny {
                    reason: DenyReason::MalformedRequest,
                    stage: crate::enforcement::decision::EnforcementStage::Normalization,
                    detail: format!("{}: {}", denial.code, denial.detail),
                    envelope: None,
                    identity: None,
                };
                let mut audit_payload = audit_payload_from_decision(
                    &decision,
                    request,
                    session_id,
                    std::time::Duration::ZERO,
                    None,
                );
                // Monitor mode observes protocol-level denials too: forward
                // the original request once and keep the would-deny reason in
                // the audit record, matching the pipeline's monitor override.
                if self.pipeline.is_monitor() {
                    monitor_override(&mut audit_payload);
                    return Some(
                        self.forward_composio_observed(request, session_id, audit_payload)
                            .await,
                    );
                }
                self.emit_audit(audit_payload).await;
                Some(response_from_blocking_decision(&decision))
            }
        }
    }

    async fn handle_composio_passthrough(
        &self,
        request: &RawRequest,
        session_id: &str,
    ) -> HandledResponse {
        let decision = EnforcementDecision::Passthrough {
            detail: "recognized Composio non-execution request".to_string(),
        };
        let audit_payload = audit_payload_from_decision(
            &decision,
            request,
            session_id,
            std::time::Duration::ZERO,
            None,
        );
        self.forward_composio_observed(request, session_id, audit_payload)
            .await
    }

    /// Dispatch the original Composio request once with no injected
    /// credentials, enrich and emit the given audit payload, and surface a
    /// successful dispatch as a passthrough response.
    async fn forward_composio_observed(
        &self,
        request: &RawRequest,
        session_id: &str,
        mut audit_payload: AuditPayload,
    ) -> HandledResponse {
        let response = match passthrough_envelope(request, session_id) {
            Ok(envelope) => {
                let (response, outcome) =
                    self.dispatch(envelope, InjectedCredentials::empty()).await;
                outcome.enrich(&mut audit_payload);
                match response {
                    HandledResponse::Ok(dispatched) => HandledResponse::Passthrough(dispatched),
                    other => other,
                }
            }
            Err(err) => handle_error(err),
        };
        self.emit_audit(audit_payload).await;
        response
    }

    async fn handle_composio_actions(
        &self,
        request: &RawRequest,
        session_id: &str,
        actions: &[ComposioAction],
    ) -> HandledResponse {
        let result = self
            .pipeline
            .enforce_composite(request, session_id, actions)
            .await;
        let response = match result.disposition {
            CompositeDisposition::Dispatch {
                transport,
                monitor_override,
            } => {
                let dispatch = match transport {
                    Some((envelope, credentials)) => {
                        let mut dispatch_envelope = *envelope;
                        hydrate_dispatch_http_fields(&mut dispatch_envelope, request);
                        self.dispatch(dispatch_envelope, credentials).await
                    }
                    None => match passthrough_envelope(request, session_id) {
                        Ok(envelope) => self.dispatch(envelope, InjectedCredentials::empty()).await,
                        Err(err) => {
                            let response = handle_error(err);
                            let outcome = DispatchOutcome::abort_from_connector(
                                AbortReason::ConnectorInvalidRequest,
                                "could not construct Composio monitor dispatch",
                            );
                            (response, outcome)
                        }
                    },
                };
                let (response, outcome) = dispatch;
                let mut response = response;
                for child in result.children {
                    self.emit_enriched_composite_audit(child, &outcome).await;
                }
                if monitor_override && let HandledResponse::Ok(dispatched) = response {
                    response = HandledResponse::Passthrough(dispatched);
                }
                return response;
            }
            CompositeDisposition::Block { blocker_index } => {
                result.children.get(blocker_index).map_or_else(
                    || HandledResponse::Deny {
                        reason: DenyReason::FailClosed,
                        detail: "Composio aggregate result had no blocker; failing closed"
                            .to_string(),
                        context: DenialContext::Api,
                    },
                    |child| response_from_blocking_decision(&child.decision),
                )
            }
        };
        for child in result.children {
            self.emit_audit(child.audit_payload).await;
        }
        response
    }

    async fn emit_enriched_composite_audit(
        &self,
        mut child: CompositeActionResult,
        outcome: &DispatchOutcome,
    ) {
        outcome.enrich_ref(&mut child.audit_payload);
        self.emit_audit(child.audit_payload).await;
    }

    async fn emit_audit(&self, payload: AuditPayload) {
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Dispatches a `MODIFY` decision: applies the structural transformation
    /// to the dispatch clone, then forwards to the connector.
    ///
    /// `redact_header` strips the header from the agent-produced request only;
    /// it does not prevent credential injection from adding the same header
    /// back to the outbound request. The redaction is scoped to what the
    /// agent sent, not to what the sidecar injects downstream.
    async fn dispatch_modify(
        &self,
        envelope: ExecutionEnvelope,
        request: &RawRequest,
        credentials: InjectedCredentials,
        modifications: firma_core::ModificationSpec,
        audit_payload: &mut AuditPayload,
    ) -> HandledResponse {
        let mut dispatch_envelope = envelope;
        hydrate_dispatch_http_fields(&mut dispatch_envelope, request);
        // Fail closed: a modification that cannot be applied (e.g. a
        // `redact_header` policy targeting a non-HTTP action) must not
        // fall through to dispatch. Forwarding the unmodified request
        // would leak the header the policy asked to strip, so block
        // instead and override the audit to record the dispatch-level
        // denial rather than the pipeline's pre-dispatch MODIFY outcome.
        if let Err(err) = modifications.apply(&mut dispatch_envelope) {
            tracing::error!(
                error = %err,
                "modification failed to apply; the policy targets HTTP headers \
                 but the action is not HTTP — failing closed"
            );
            let detail = "modification could not be applied; failing closed".to_string();
            audit_payload.decision = Decision::Deny;
            audit_payload.deny_reason = format!("{}: {detail}", DenyReason::FailClosed);
            return HandledResponse::Deny {
                reason: DenyReason::FailClosed,
                detail,
                context: denial_context_from_params(&dispatch_envelope.intent.params),
            };
        }
        let (response, outcome) = self.dispatch(dispatch_envelope, credentials).await;
        outcome.enrich(audit_payload);
        response
    }

    /// Handles CONNECT authorization without performing connector HTTP dispatch.
    ///
    /// On [`ConnectDecision::Allow`], the HTTP proxy interceptor proceeds with
    /// tunnel establishment and byte relay.
    pub(crate) async fn handle_connect(
        &self,
        mut request: RawRequest,
        session_id: &str,
    ) -> ConnectDecision {
        let (decision, mut audit_payload) = self.pipeline.enforce(&request, session_id).await;

        let outcome = match decision {
            EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
                audit_payload.dispatch_status = 200;
                ConnectDecision::Allow
            }
            EnforcementDecision::Modify { modifications, .. } => {
                // AARM R4 `MODIFY`: apply the redaction to the request headers
                // before the tunnel is established, so the agent's headers are
                // stripped even for CONNECT. The modification is audit-recorded
                // (decision = `MODIFY`).
                apply_modification_to_request(&modifications, &mut request);
                audit_payload.dispatch_status = 200;
                ConnectDecision::Allow
            }
            EnforcementDecision::Deny { reason, detail, .. } => {
                ConnectDecision::Deny { reason, detail }
            }
            EnforcementDecision::Abort { reason, detail, .. } => {
                ConnectDecision::Abort { reason, detail }
            }
            EnforcementDecision::StepUp { challenge, .. } => ConnectDecision::Deny {
                reason: firma_core::DenyReason::StepUpRequired,
                detail: challenge,
            },
            EnforcementDecision::Defer { retry_after_ms, .. } => ConnectDecision::Deny {
                reason: firma_core::DenyReason::Deferred,
                detail: format!("retry_after_ms: {retry_after_ms}"),
            },
        };

        if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
            tracing::error!("failed to send audit event: {err}");
        }

        outcome
    }

    /// Authorizes an HTTP upgrade request without dispatching via the connector
    /// registry.
    ///
    /// Intended for upgraded protocols (for example WebSocket) where dispatch
    /// switches from request/response to long-lived byte relay.
    pub async fn authorize_upgrade(
        &self,
        mut request: RawRequest,
        session_id: &str,
    ) -> UpgradeAuthorization {
        if is_protected_host(&request.host) {
            let detail = "Composio protocol upgrades are unsupported".to_string();
            let decision = EnforcementDecision::Deny {
                reason: DenyReason::FailClosed,
                stage: crate::enforcement::decision::EnforcementStage::Normalization,
                detail: detail.clone(),
                envelope: None,
                identity: None,
            };
            let mut audit_payload = audit_payload_from_decision(
                &decision,
                &request,
                session_id,
                std::time::Duration::ZERO,
                None,
            );
            // Monitor mode observes the upgrade instead of blocking it: the
            // relay proceeds without injected credentials and the audit
            // record keeps the would-deny reason.
            if self.pipeline.is_monitor() {
                monitor_override(&mut audit_payload);
                return UpgradeAuthorization::Allow {
                    credentials: InjectedCredentials::empty(),
                    audit_payload: Box::new(audit_payload),
                };
            }
            if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                tracing::error!("failed to send audit event: {err}");
            }
            return UpgradeAuthorization::Deny {
                reason: DenyReason::FailClosed,
                detail,
            };
        }

        let (decision, audit_payload) = self.pipeline.enforce(&request, session_id).await;

        match decision {
            EnforcementDecision::Allow { credentials, .. } => UpgradeAuthorization::Allow {
                credentials,
                audit_payload: Box::new(audit_payload),
            },
            EnforcementDecision::Modify {
                credentials,
                modifications,
                ..
            } => {
                // AARM R4 `MODIFY`: apply the redaction to the request headers
                // before the upgrade is authorized, so the agent's headers are
                // stripped. The modification is audit-recorded (decision =
                // `MODIFY`).
                apply_modification_to_request(&modifications, &mut request);
                UpgradeAuthorization::Allow {
                    credentials,
                    audit_payload: Box::new(audit_payload),
                }
            }
            EnforcementDecision::Passthrough { .. } => UpgradeAuthorization::Allow {
                credentials: InjectedCredentials::empty(),
                audit_payload: Box::new(audit_payload),
            },
            EnforcementDecision::Deny { reason, detail, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Deny { reason, detail }
            }
            EnforcementDecision::Abort { reason, detail, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Abort { reason, detail }
            }
            EnforcementDecision::StepUp { challenge, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Deny {
                    reason: firma_core::DenyReason::StepUpRequired,
                    detail: challenge,
                }
            }
            EnforcementDecision::Defer { retry_after_ms, .. } => {
                if let Err(err) = self.audit_sink_sender.send(audit_payload).await {
                    tracing::error!("failed to send audit event: {err}");
                }
                UpgradeAuthorization::Deny {
                    reason: firma_core::DenyReason::Deferred,
                    detail: format!("retry_after_ms: {retry_after_ms}"),
                }
            }
        }
    }

    /// Emits audit payload for an authorized HTTP upgrade flow.
    pub(crate) async fn emit_upgrade_audit(
        &self,
        mut payload: AuditPayload,
        dispatch_status: u16,
        response_size: usize,
    ) {
        payload.dispatch_status = i32::from(dispatch_status);
        payload.dispatch_latency_us = 0;
        payload.response_size = i64::try_from(response_size).unwrap_or(i64::MAX);
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Emits an ABORT audit event when an upgrade was policy-allowed but
    /// the upstream relay failed before producing a target response.
    ///
    /// Reuses the verified ALLOW payload (so `agent_id` / `token_id` are
    /// preserved, as the post-ALLOW abort always has an identity) and rewrites
    /// the decision to [`Decision::Abort`]. No upstream response was produced, so
    /// the dispatch fields stay zero.
    pub(crate) async fn emit_upgrade_abort_audit(
        &self,
        mut payload: AuditPayload,
        reason: AbortReason,
        detail: &str,
    ) {
        payload.decision = Decision::Abort;
        payload.deny_reason = format!("{}: {detail}", reason.code());
        payload.dispatch_status = 0;
        payload.dispatch_latency_us = 0;
        payload.response_size = 0;
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Emits a synthetic audit event when CONNECT was policy-allowed but
    /// upstream tunnel establishment/relay failed after authorization.
    pub(crate) async fn emit_connect_relay_failure_audit(
        &self,
        session_id: &str,
        host: &str,
        detail: &str,
    ) {
        let payload = AuditPayload {
            session_id: session_id.to_string(),
            token_id: String::new(),
            agent_id: String::new(),
            action: "network.connect".to_string(),
            resource: format!("{host}/"),
            decision: Decision::Abort,
            deny_reason: format!("CONNECT_RELAY_FAILURE: {detail}"),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        };
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Emits a synthetic DENY audit event for a network-layer denial
    /// raised before the enforcement pipeline runs.
    ///
    /// Covers fail-closed paths an interceptor rejects up front —
    /// malformed requests and strict-MITM preflight failures — that
    /// otherwise return 403 to the client with no audit trail, leaving
    /// the deny invisible to `firma monitor` (FIR-208). No capability was
    /// validated on these paths, so `agent_id` / `token_id` are empty.
    pub(crate) async fn emit_synthetic_deny(
        &self,
        session_id: &str,
        action: &str,
        resource: &str,
        reason: DenyReason,
        detail: &str,
    ) {
        let payload = AuditPayload {
            session_id: session_id.to_string(),
            token_id: String::new(),
            agent_id: String::new(),
            action: action.to_string(),
            resource: resource.to_string(),
            decision: Decision::Deny,
            deny_reason: format!("{reason}: {detail}"),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        };
        if let Err(err) = self.audit_sink_sender.send(payload).await {
            tracing::error!("failed to send audit event: {err}");
        }
    }

    /// Dispatches an approved call through the connector registry.
    ///
    /// Returns the [`HandledResponse`] plus a [`DispatchOutcome`] that
    /// captures the raw dispatch metadata needed to enrich the audit
    /// payload (status, latency, response size, decision override on
    /// abort or connector-originated deny).
    async fn dispatch(
        &self,
        envelope: ExecutionEnvelope,
        credentials: InjectedCredentials,
    ) -> (HandledResponse, DispatchOutcome) {
        let resource_display = envelope.intent().resource_display();
        let host = extract_host(&resource_display).unwrap_or_default();
        let connector = self.connector_registry.select(&host);
        let view = TransportView::new(envelope, credentials);
        match connector.dispatch(&view).await {
            Ok(response) => {
                let outcome = DispatchOutcome {
                    decision_override: None,
                    dispatch_status: i32::from(response.status),
                    dispatch_latency_us: dispatch_latency_us(response.dispatch_latency),
                    response_size: i64_from_usize(response.response_size),
                };
                (HandledResponse::Ok(dispatched_from(response)), outcome)
            }
            Err(ConnectorError::Timeout(duration)) => {
                let detail = format!("connector timeout after {duration:?}");
                let outcome = DispatchOutcome {
                    decision_override: Some(DecisionOverride {
                        decision: Decision::Abort,
                        deny_reason: format!(
                            "{code}: {detail}",
                            code = AbortReason::ConnectorTimeout.code()
                        ),
                    }),
                    dispatch_status: 0,
                    dispatch_latency_us: 0,
                    response_size: 0,
                };
                (
                    HandledResponse::Aborted {
                        reason: AbortReason::ConnectorTimeout,
                        detail,
                    },
                    outcome,
                )
            }
            Err(ConnectorError::Network(detail)) => {
                let outcome =
                    DispatchOutcome::abort_from_connector(AbortReason::ConnectorFailure, &detail);
                (
                    HandledResponse::Aborted {
                        reason: AbortReason::ConnectorFailure,
                        detail,
                    },
                    outcome,
                )
            }
            Err(ConnectorError::InvalidRequest(detail)) => {
                let outcome = DispatchOutcome::abort_from_connector(
                    AbortReason::ConnectorInvalidRequest,
                    &detail,
                );
                (
                    HandledResponse::Aborted {
                        reason: AbortReason::ConnectorInvalidRequest,
                        detail,
                    },
                    outcome,
                )
            }
        }
    }
}

fn handle_error(err: impl Display) -> HandledResponse {
    HandledResponse::Aborted {
        reason: AbortReason::ConnectorInvalidRequest,
        detail: err.to_string(),
    }
}

fn response_from_blocking_decision(decision: &EnforcementDecision) -> HandledResponse {
    match decision {
        EnforcementDecision::Deny {
            reason,
            detail,
            envelope,
            ..
        } => HandledResponse::Deny {
            reason: *reason,
            detail: detail.clone(),
            context: denial_context_of(envelope.as_ref()),
        },
        EnforcementDecision::Abort { reason, detail, .. } => HandledResponse::Aborted {
            reason: *reason,
            detail: detail.clone(),
        },
        EnforcementDecision::Modify { envelope, .. } => HandledResponse::Deny {
            reason: DenyReason::FailClosed,
            detail: "Composio argument modification is unsupported; failing closed".to_string(),
            context: denial_context_from_params(&envelope.intent().params),
        },
        EnforcementDecision::StepUp {
            challenge,
            envelope,
            ..
        } => HandledResponse::Deny {
            reason: DenyReason::StepUpRequired,
            detail: challenge.clone(),
            context: denial_context_of(envelope.as_ref()),
        },
        EnforcementDecision::Defer {
            retry_after_ms,
            envelope,
            ..
        } => HandledResponse::Deny {
            reason: DenyReason::Deferred,
            detail: format!("retry_after_ms: {retry_after_ms}"),
            context: denial_context_of(envelope.as_ref()),
        },
        EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
            HandledResponse::Deny {
                reason: DenyReason::FailClosed,
                detail: "Composio aggregate selected a non-blocking result; failing closed"
                    .to_string(),
                context: DenialContext::Api,
            }
        }
    }
}

fn hydrate_dispatch_http_fields(envelope: &mut ExecutionEnvelope, request: &RawRequest) {
    let ActionParams::Http(http) = &mut envelope.intent.params else {
        return;
    };
    // `envelope.intent.params.http.headers` was built by the normalizer's
    // `sanitize_headers` for the audit-trail envelope, which strips
    // sensitive headers like `cookie` and `authorization` so they never
    // reach logs. Dispatch to the upstream connector must still carry
    // those headers, so rebuild from the original `request.headers` here
    // and only strip the internal `x-firma-*` control headers.
    http.headers = strip_firma_headers(&request.headers);
    http.body.clone_from(&request.body);
}

fn strip_firma_headers(headers: &HeaderMap) -> HeaderMap {
    headers
        .iter()
        .filter(|(k, _v)| !k.as_str().starts_with("x-firma-"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Apply a [`ModificationSpec`] redaction to the raw request headers before
/// the caller proceeds with tunnel establishment or protocol upgrade.
///
/// This is used by `handle_connect` and `authorize_upgrade`, which don't go
/// through the connector HTTP dispatch path (and therefore can't apply the
/// modification to a dispatch clone). The redaction is applied directly to
/// the agent's request headers.
fn apply_modification_to_request(
    modifications: &firma_core::ModificationSpec,
    request: &mut RawRequest,
) {
    match modifications {
        firma_core::ModificationSpec::RedactHeader(name) => {
            request.headers.remove(name);
        }
    }
}

/// Builds a minimal [`ExecutionEnvelope`] for a non-protected
/// (Passthrough) request so it can flow through the same connector
/// dispatch path as authorized traffic.
///
/// No capability token is present for passthrough calls; the envelope
/// carries an empty capability string and a synthetic action class.
fn passthrough_envelope<'a>(
    request: &'a RawRequest,
    session_id: &str,
) -> Result<ExecutionEnvelope, InvalidMethod<'a>> {
    let method = HttpMethod::try_from(&request.method)?;
    let scheme = if request.is_https { "https" } else { "http" };
    let mut resource = std::collections::BTreeMap::new();
    resource.insert("host".to_string(), request.host.as_str().to_owned());
    resource.insert("path".to_string(), request.path.clone());
    let headers = strip_firma_headers(&request.headers);
    let intent = ExecutionIntent {
        action_class: "passthrough".to_string(),
        resource,
        params: ActionParams::Http(HttpParams {
            method,
            headers,
            body: request.body.clone(),
            query: HashMap::new(),
        }),
        raw_transport: scheme.to_string(),
        raw_action_ref: format!("{} {}", request.method, request.path),
    };
    let session_id = session_id
        .parse::<SessionId>()
        .unwrap_or_else(|_| passthrough_session_id());
    Ok(ExecutionEnvelope::new(
        intent,
        String::new(),
        ExecutionMetadata {
            session_id,
            agent_id: passthrough_agent_id(),
            timestamp: chrono::Utc::now(),
            trace_id: None,
            risk_score: None,
            thread_id: None,
            parent_action_id: None,
        },
        None,
    ))
}

#[expect(
    clippy::expect_used,
    reason = "literal passthrough ids are non-empty by construction; parse cannot fail"
)]
fn passthrough_agent_id() -> AgentId {
    "agt_01j0000000e008000000000001"
        .parse()
        .expect("literal passthrough agent id is valid")
}

#[expect(
    clippy::expect_used,
    reason = "literal passthrough ids are non-empty by construction; parse cannot fail"
)]
fn passthrough_session_id() -> SessionId {
    "_passthrough_"
        .parse()
        .expect("literal passthrough session id is non-empty")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{collections::HashMap, net::SocketAddr, time::Duration};

    use async_trait::async_trait;
    use base64::Engine as _;
    use chrono::Utc;
    use firma_core::{
        CapabilityClaims, Connector, RevocationStore, StepUpSpec, TokenError, TokenId,
        TokenVerifier, TransportView,
    };
    use firma_http::{Authority, Method};
    use firma_secret_provider::{
        gateway::{client::config::GatewayClientConfig, endpoint::GatewayEndpoint},
        non_empty::NonEmptyString,
        spec::http::{HttpMatcherRule, PathAndMatcher, PathOnly},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::config::TenancyMode;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::{PolicyEvaluation, PolicyVerdict};
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, IntentNormalizer,
        MappingTable, PipelineArgs,
    };

    #[expect(
        clippy::redundant_pub_crate,
        reason = "shared by sibling interceptor test modules"
    )]
    pub(crate) fn test_connector_registry() -> Arc<ConnectorRegistry> {
        let default = crate::connector::provider::GenericHttpConnector::default_for_unconfigured()
            .expect("default connector should build in tests");
        Arc::new(ConnectorRegistry::new(Arc::new(default)))
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

    /// Policy stub whose `evaluate_verdict` always returns `STEP_UP`, to
    /// exercise `handle()`'s `EnforcementDecision::StepUp` arm — no policy
    /// engine wiring in the other test helpers ever produces this outcome.
    struct StepUpPolicy;
    impl PolicyEvaluation for StepUpPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn evaluate_verdict(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<PolicyVerdict, String> {
            Ok(PolicyVerdict::StepUp {
                challenge: StepUpSpec::new("manager approval required")
                    .expect("non-empty challenge literal"),
            })
        }

        fn is_fresh(&self) -> bool {
            true
        }

        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    /// Policy stub whose `evaluate_verdict` always returns `DEFER`, to
    /// exercise `handle()`'s `EnforcementDecision::Defer` arm.
    struct DeferPolicy;
    impl PolicyEvaluation for DeferPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn evaluate_verdict(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> Result<PolicyVerdict, String> {
            Ok(PolicyVerdict::Defer {
                backoff: Duration::from_millis(250),
            })
        }

        fn is_fresh(&self) -> bool {
            true
        }

        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    struct FailingCredentialInjector;

    #[async_trait]
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

    struct InvalidRequestConnector;

    #[async_trait]
    impl Connector for InvalidRequestConnector {
        async fn dispatch(
            &self,
            _view: &TransportView,
        ) -> Result<ConnectorResponse, ConnectorError> {
            Err(ConnectorError::InvalidRequest(
                "cannot translate request".to_string(),
            ))
        }
    }

    fn test_claims_for_session(session_id: &str) -> CapabilityClaims {
        CapabilityClaims {
            token_id: "ctok_01j0000000e008000000000001"
                .parse()
                .expect("literal token id"),
            agent_id: "agt_01j0000000e008000000000001"
                .parse()
                .expect("literal agent id"),
            session_id: session_id.parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_pipeline(
        rules: Vec<MappingRuleConfig>,
        default_protected: bool,
        has_capability: bool,
    ) -> Arc<EnforcementPipeline> {
        test_pipeline_for_session(rules, default_protected, has_capability, "sess_001")
    }

    fn test_pipeline_for_session(
        rules: Vec<MappingRuleConfig>,
        default_protected: bool,
        has_capability: bool,
        session_id: &str,
    ) -> Arc<EnforcementPipeline> {
        let claims = test_claims_for_session(session_id);
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile { rules };
        let table = MappingTable::from_config(&file, &registry, default_protected)
            .unwrap_or_else(|e| panic!("{e}"));
        let entries = if has_capability {
            vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]
        } else {
            Vec::new()
        };

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer: IntentNormalizer::new(table),
            capability_validator: CapabilityValidator::new(
                CapabilityMap::new(entries),
                Arc::new(MockVerifier { claims }),
                std::sync::Arc::new(NoRevocations),
                Duration::from_secs(0),
                TenancyMode::SingleAgent,
            ),
            constraint_enforcer: ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy)),
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_pipeline_with_failing_credentials(
        rules: Vec<MappingRuleConfig>,
        session_id: &str,
    ) -> Arc<EnforcementPipeline> {
        let claims = test_claims_for_session(session_id);
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile { rules };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer: IntentNormalizer::new(table),
            capability_validator: CapabilityValidator::new(
                CapabilityMap::new(vec![CapabilityEntry {
                    raw_token: "v4.public.test_token".to_string(),
                    claims: claims.clone(),
                }]),
                Arc::new(MockVerifier { claims }),
                std::sync::Arc::new(NoRevocations),
                Duration::from_secs(0),
                TenancyMode::SingleAgent,
            ),
            constraint_enforcer: ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy)),
            credential_injector: Box::new(FailingCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    /// Like [`test_pipeline_for_session`], but with a caller-supplied
    /// policy so tests can drive remediation verdicts (`STEP_UP`/`DEFER`)
    /// that `AllowAllPolicy` can never produce.
    fn test_pipeline_with_policy(
        rules: Vec<MappingRuleConfig>,
        session_id: &str,
        policy: Arc<dyn PolicyEvaluation>,
    ) -> Arc<EnforcementPipeline> {
        let claims = test_claims_for_session(session_id);
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile { rules };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer: IntentNormalizer::new(table),
            capability_validator: CapabilityValidator::new(
                CapabilityMap::new(vec![CapabilityEntry {
                    raw_token: "v4.public.test_token".to_string(),
                    claims: claims.clone(),
                }]),
                Arc::new(MockVerifier { claims }),
                std::sync::Arc::new(NoRevocations),
                Duration::from_secs(0),
                TenancyMode::SingleAgent,
            ),
            constraint_enforcer: ConstraintEnforcer::new(policy),
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn allow_rule() -> MappingRuleConfig {
        MappingRuleConfig {
            method: Some(Method::POST),
            host: "*".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "communication.external.send".to_string(),
        }
    }

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
                            let mut buf = vec![0u8; 4096];
                            let _ = stream.read(&mut buf).await;
                            let response = "HTTP/1.1 201 Created\r\nx-test: ok\r\nContent-Length: 2\r\n\r\nOK";
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

    fn raw_request(host: Authority, method: Method) -> RawRequest {
        RawRequest {
            method,
            host,
            path: "/v1/chat/completions".to_string(),
            headers: HeaderMap::new(),
            body: Some(b"{}".to_vec()),
            is_https: false,
        }
    }

    #[tokio::test]
    async fn test_handle_allow_forwards_and_emits_audit() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_allow"),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
                "sess_allow",
            )
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                assert_eq!(dispatched.status, 201);
                assert_eq!(dispatched.body, b"OK");
                assert_eq!(
                    dispatched.headers.get("x-test"),
                    Some(&http::HeaderValue::from_static("ok"))
                );
            }
            other => panic!("expected ok response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_allow");
        assert_eq!(payload.decision, Decision::Allow);
        assert!(rx.try_recv().is_err());
        upstream_cancel.cancel();
    }

    #[tokio::test]
    async fn test_handle_deny_skips_forward_and_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::POST),
                "sess_deny",
            )
            .await;

        match response {
            HandledResponse::Deny {
                reason,
                detail,
                context,
            } => {
                assert_eq!(reason, DenyReason::TokenInvalid);
                assert!(!detail.is_empty());
                // Stage 1 TokenInvalid denies carry no envelope, so
                // the handler falls back to Api per the fail-closed
                // default.
                assert_eq!(context, DenialContext::Api);
            }
            other => panic!("expected deny response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_deny");
        assert_eq!(payload.decision, Decision::Deny);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_allow_audit_has_dispatch_outcome_fields() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_audit"),
            test_connector_registry(),
            tx,
        );

        let _ = handler
            .handle(
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
                "sess_audit",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Allow);
        assert_eq!(payload.dispatch_status, 201);
        assert_eq!(payload.response_size, 2);
        assert!(
            payload.dispatch_latency_us >= 0,
            "dispatch_latency_us must be populated"
        );
        assert!(payload.deny_reason.is_empty());
        upstream_cancel.cancel();
    }

    #[tokio::test]
    async fn test_handle_deny_audit_has_zero_dispatch_fields() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        let _ = handler
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::POST),
                "sess",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(payload.dispatch_status, 0);
        assert_eq!(payload.dispatch_latency_us, 0);
        assert_eq!(payload.response_size, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_network_error_aborts() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_net"),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                // Port 1 is reserved — connect attempt fails reliably.
                raw_request(Authority::from_static("127.0.0.1:1"), Method::POST),
                "sess_net",
            )
            .await;

        match response {
            HandledResponse::Aborted { reason, .. } => {
                assert_eq!(reason, AbortReason::ConnectorFailure);
            }
            other => panic!("expected network abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_FAILURE"),
            "deny_reason should carry CONNECTOR_FAILURE prefix, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn dispatch_modify_fails_closed_when_target_is_not_http() {
        use firma_core::{ModificationSpec, ToolUseParams};
        // The V1 normalizer only ever produces HTTP params, but a future
        // non-HTTP transport could route a MODIFY decision to
        // `dispatch_modify` with ToolUse params. The policy asked for a
        // header redaction that can't apply to a tool call; forwarding the
        // unmodified request would leak the header the policy said to
        // strip, so the handler must fail closed instead of dispatching.
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, true),
            test_connector_registry(),
            tx,
        );

        let mut audit_payload = AuditPayload {
            session_id: "sess_modify".to_string(),
            token_id: "tok".to_string(),
            agent_id: "agent".to_string(),
            action: "tool.generic".to_string(),
            resource: "my_tool".to_string(),
            decision: Decision::Modify,
            deny_reason: "redacted_header:x-sensitive".to_string(),
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: "test-v1".to_string(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        };

        let envelope = ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "tool.generic".to_string(),
                resource: ExecutionIntent::resource_map_from("my_tool"),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "my_tool".to_string(),
                    input: HashMap::new(),
                }),
                raw_transport: "mcp".to_string(),
                raw_action_ref: "my_tool".to_string(),
            },
            "v4.public.test_token".to_string(),
            ExecutionMetadata {
                session_id: "sess_modify".parse().expect("literal session id"),
                agent_id: "agt_01j0000000e008000000000001"
                    .parse()
                    .expect("literal agent id"),
                timestamp: Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        );

        let modifications =
            ModificationSpec::parse("redact_header:x-sensitive").expect("valid redact_header spec");
        let request = raw_request(Authority::from_static("127.0.0.1:9"), Method::POST);

        let response = handler
            .dispatch_modify(
                envelope,
                &request,
                InjectedCredentials::empty(),
                modifications,
                &mut audit_payload,
            )
            .await;

        match response {
            HandledResponse::Deny {
                reason,
                detail,
                context,
            } => {
                assert_eq!(reason, DenyReason::FailClosed);
                assert!(
                    detail.contains("modification could not be applied"),
                    "detail should explain the fail-closed reason, got: {detail}"
                );
                assert_eq!(context, DenialContext::Tool);
            }
            other => panic!("expected fail-closed Deny, got {other:?}"),
        }

        // The audit must reflect the dispatch-level denial, not the
        // pipeline's pre-dispatch MODIFY outcome, and the connector must
        // never have been called (dispatch_status stays zero).
        assert_eq!(audit_payload.decision, Decision::Deny);
        assert!(
            audit_payload.deny_reason.contains("fail closed"),
            "audit deny_reason should carry the fail-closed marker, got: {}",
            audit_payload.deny_reason
        );
        assert_eq!(audit_payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_timeout_produces_aborted() {
        use crate::connector::provider::{GenericHttpConnector, HttpConnectorConfig};

        // wiremock server that sleeps 2s before responding.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;

        // Registry whose default connector times out in 100ms — every
        // host (including the wiremock one) goes through it and trips
        // the timeout well before wiremock replies.
        let fast_default = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: Duration::from_millis(100),
            rate_limit: None,
        })
        .expect("fast default connector should build");
        let registry = Arc::new(crate::connector::ConnectorRegistry::new(Arc::new(
            fast_default,
        )));

        let addr = server.address();
        let host =
            Authority::from_str(&format!("127.0.0.1:{}", addr.port())).expect("valid authority");

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_timeout"),
            registry,
            tx,
        );

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_timeout")
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::ConnectorTimeout);
                assert!(detail.contains("connector timeout"));
            }
            other => panic!("expected aborted, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_TIMEOUT"),
            "deny_reason should carry CONNECTOR_TIMEOUT prefix, got {:?}",
            payload.deny_reason,
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_handle_connector_invalid_request_aborts() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_invalid"),
            Arc::new(crate::connector::ConnectorRegistry::new(Arc::new(
                InvalidRequestConnector,
            ))),
            tx,
        );

        let response = handler
            .handle(
                raw_request(
                    Authority::from_static("api.invalid-request.test"),
                    Method::POST,
                ),
                "sess_invalid",
            )
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::ConnectorInvalidRequest);
                assert_eq!(detail, "cannot translate request");
            }
            other => panic!("expected invalid-request abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_INVALID_REQUEST"),
            "deny_reason should carry CONNECTOR_INVALID_REQUEST prefix, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_handle_target_5xx_relayed_as_ok() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_5xx"),
            test_connector_registry(),
            tx,
        );

        let addr = server.address();
        let response = handler
            .handle(
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", addr.port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
                "sess_5xx",
            )
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                assert_eq!(dispatched.status, 503);
                assert_eq!(dispatched.body, b"down".to_vec());
            }
            other => panic!("expected ok-with-5xx, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Allow);
        assert_eq!(payload.dispatch_status, 503);
    }

    #[tokio::test]
    async fn test_handle_step_up_denies_with_challenge_as_detail() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_with_policy(vec![allow_rule()], "sess_step_up", Arc::new(StepUpPolicy)),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::POST),
                "sess_step_up",
            )
            .await;

        match response {
            HandledResponse::Deny {
                reason,
                detail,
                context,
            } => {
                assert_eq!(reason, DenyReason::StepUpRequired);
                assert_eq!(detail, "manager approval required");
                // HTTP action params map to the Api denial context.
                assert_eq!(context, DenialContext::Api);
            }
            other => panic!("expected step-up deny, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_step_up");
    }

    #[tokio::test]
    async fn test_handle_defer_denies_with_retry_after_ms_in_detail() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_with_policy(vec![allow_rule()], "sess_defer", Arc::new(DeferPolicy)),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::POST),
                "sess_defer",
            )
            .await;

        match response {
            HandledResponse::Deny {
                reason,
                detail,
                context,
            } => {
                assert_eq!(reason, DenyReason::Deferred);
                assert_eq!(detail, "retry_after_ms: 250");
                assert_eq!(context, DenialContext::Api);
            }
            other => panic!("expected defer deny, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_defer");
    }

    #[tokio::test]
    async fn test_handle_passthrough_with_unsupported_method_aborts() {
        // TRACE is accepted by `firma_http::Method` but rejected by
        // `HttpMethod::try_from` (envelope.rs only recognizes GET/POST/PUT/
        // DELETE/PATCH/HEAD/OPTIONS/CONNECT). A passthrough request with an
        // unrecognized method never reaches the mapping table's method
        // check (that only runs for matched/protected requests), so it must
        // fail later, in `passthrough_envelope`, and the handler must
        // convert that error into an abort rather than panicking or
        // silently dropping the request.
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], false, true),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(Authority::from_static("127.0.0.1:9"), Method::TRACE),
                "sess_trace",
            )
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::ConnectorInvalidRequest);
                assert!(!detail.is_empty());
            }
            other => panic!("expected aborted for unsupported method, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_trace");
        assert_eq!(
            payload.decision,
            Decision::Abort,
            "the audit must record the abort, not the pre-dispatch Allow"
        );
        assert!(
            payload
                .deny_reason
                .contains(AbortReason::ConnectorInvalidRequest.code()),
            "deny_reason should carry the abort reason, got: {}",
            payload.deny_reason
        );
    }

    /// Minimal fake gateway: accepts one connection, reads one
    /// `secret.push` line, captures it, and echoes back the given
    /// `placeholder` as the confirmation response — enough to exercise
    /// [`RequestHandler::rewrite_with_http_intercept`] without depending on
    /// firma-run (which firma-sidecar does not, and must not, depend on).
    async fn fake_push_gateway() -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<serde_json::Value>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let addr = listener.local_addr().expect("local_addr");
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                if let Ok(n) = stream.read(&mut buf).await {
                    let line = String::from_utf8_lossy(&buf[..n]);
                    let request: serde_json::Value =
                        serde_json::from_str(line.trim()).expect("valid push request JSON");
                    let placeholder = request["placeholder"].clone();
                    let _ = tx.send(request);
                    let response = serde_json::json!({ "type": "ok", "placeholder": placeholder })
                        .to_string()
                        + "\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });
        (addr, rx)
    }

    /// Minimal fake gateway resolve endpoint: accepts one connection, reads
    /// one `secret.resolve` request line, and replies with a single `ok`
    /// result carrying `secret_b64` — enough to exercise
    /// [`RequestHandler::rehydrate_request`] end-to-end without depending on
    /// firma-run.
    async fn fake_resolve_gateway(secret_b64: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                if stream.read(&mut buf).await.is_ok() {
                    let response =
                        format!(r#"[{{"type":"ok","secret_b64":"{secret_b64}"}}]"#) + "\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });
        addr
    }

    /// Mock upstream that captures the raw bytes of the single request it
    /// receives — so a test can assert what the connector actually
    /// forwarded — and replies with a fixed 200 response carrying
    /// `response_body`.
    async fn mock_upstream_capturing(
        response_body: Vec<u8>,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::sync::oneshot::Receiver<Vec<u8>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().expect("local_addr");
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((mut stream, _)) = accepted {
                        let mut buf = vec![0u8; 8192];
                        if let Ok(n) = stream.read(&mut buf).await {
                            let _ = tx.send(buf[..n].to_vec());
                        }
                        let mut response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            response_body.len()
                        )
                        .into_bytes();
                        response.extend_from_slice(&response_body);
                        let _ = stream.write_all(&response).await;
                        let _ = stream.shutdown().await;
                    }
                }
                () = cancel_clone.cancelled() => {}
            }
        });

        (addr, cancel, rx)
    }

    #[tokio::test]
    async fn test_handle_rehydrates_outbound_placeholder_and_masks_response_echo() {
        // Round-trips both halves of gateway-backed secret handling that no
        // existing test covers together: an outbound placeholder in the
        // agent's request body is resolved and substituted with the real
        // secret before the connector ever sees it (`rehydrate_request`),
        // and if the upstream echoes that secret back, the response
        // returned to the agent has it masked back to the placeholder
        // (`mask_handled_response`).
        let secret_value = "sk-real-secret-value";
        let placeholder = SecretPlaceholder::new();
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret_value);
        let gateway_addr = fake_resolve_gateway(secret_b64).await;

        let response_body = format!(r#"{{"echo":"{secret_value}"}}"#).into_bytes();
        let (upstream_addr, upstream_cancel, captured_rx) =
            mock_upstream_capturing(response_body).await;

        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_rehydrate"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ));

        let mut request = raw_request(
            Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                .expect("valid authority"),
            Method::POST,
        );
        request.body = Some(format!(r#"{{"key":"{placeholder}"}}"#).into_bytes());

        let response = handler.handle(request, "sess_rehydrate").await;

        match response {
            HandledResponse::Ok(dispatched) => {
                let body = String::from_utf8(dispatched.body).expect("utf8 body");
                assert!(
                    !body.contains(secret_value),
                    "response to the agent must mask the real secret value, got: {body}"
                );
                assert!(
                    body.contains(&placeholder.to_string()),
                    "response should re-mask the echoed secret back to its placeholder, got: {body}"
                );
            }
            other => panic!("expected ok, got {other:?}"),
        }

        let captured = captured_rx.await.expect("upstream captured a request");
        let captured = String::from_utf8_lossy(&captured);
        assert!(
            captured.contains(secret_value),
            "connector must forward the rehydrated real secret, got: {captured}"
        );
        assert!(
            !captured.contains(&placeholder.to_string()),
            "the placeholder token must never reach the upstream, got: {captured}"
        );

        upstream_cancel.cancel();
    }

    #[tokio::test]
    async fn test_handle_rehydrates_plaintext_body_with_unrecognized_content_type() {
        // Regression: a placeholder-bearing body that sniffing can't
        // classify — no leading `{`/`[`/`<` and no `=` — used to fail the
        // content-type resolution and deny the request, even though raw byte
        // substitution is safe (the masking side already falls back to Raw).
        // It must now rehydrate as Raw and dispatch normally.
        let secret_value = "sk-real-secret-value";
        let placeholder = SecretPlaceholder::new();
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret_value);
        let gateway_addr = fake_resolve_gateway(secret_b64).await;

        let (upstream_addr, upstream_cancel, captured_rx) =
            mock_upstream_capturing(Vec::new()).await;

        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_raw_rehydrate"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ));

        let mut request = raw_request(
            Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                .expect("valid authority"),
            Method::POST,
        );
        request.body = Some(format!("Bearer {placeholder}").into_bytes());

        let response = handler.handle(request, "sess_raw_rehydrate").await;
        assert!(
            matches!(response, HandledResponse::Ok(_)),
            "plaintext placeholder body must dispatch, got {response:?}"
        );

        let captured = captured_rx.await.expect("upstream captured a request");
        let captured = String::from_utf8_lossy(&captured);
        assert!(
            captured.contains(secret_value),
            "connector must forward the rehydrated real secret, got: {captured}"
        );
        assert!(
            !captured.contains(&placeholder.to_string()),
            "the placeholder token must never reach the upstream, got: {captured}"
        );

        upstream_cancel.cancel();
    }

    /// Fake gateway resolve endpoint that reports the requested placeholder
    /// as unknown, exercising the fail-closed branch of
    /// [`RequestHandler::rehydrate_request`].
    async fn fake_resolve_gateway_err() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                if stream.read(&mut buf).await.is_ok() {
                    let response =
                        r#"[{"type":"err","error":"unknown placeholder"}]"#.to_string() + "\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_handle_fails_closed_when_gateway_cannot_resolve_placeholder() {
        // A request body with a placeholder the gateway cannot resolve must
        // never reach the connector: forwarding it with the placeholder
        // still literal (or only partially rehydrated) risks partial side
        // effects upstream, e.g. a vault call writing, overwriting, or
        // deleting the wrong secret. `handle` must deny before dispatch
        // rather than forward the literal token.
        let placeholder = SecretPlaceholder::new();
        let gateway_addr = fake_resolve_gateway_err().await;

        let (upstream_addr, upstream_cancel, captured_rx) =
            mock_upstream_capturing(Vec::new()).await;

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_rehydrate_fail"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ));

        let mut request = raw_request(
            Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                .expect("valid authority"),
            Method::POST,
        );
        request.body = Some(format!(r#"{{"key":"{placeholder}"}}"#).into_bytes());

        let response = handler.handle(request, "sess_rehydrate_fail").await;

        match response {
            HandledResponse::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::FailClosed);
            }
            other => panic!("expected fail-closed deny, got {other:?}"),
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(200), captured_rx)
                .await
                .is_err(),
            "connector must never be contacted when a placeholder could not be resolved"
        );

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Deny);

        upstream_cancel.cancel();
    }

    fn aws_secrets_manager_provider(host: &Authority) -> HttpIntegrationSpec {
        HttpIntegrationSpec {
            provider_id: "aws-secrets-manager".to_string(),
            host: host.to_string(),
            matchers: vec![HttpMatcherRule::SensitiveCommand(PathAndMatcher {
                path: None,
                matcher: firma_core::SecretMatcher::Json {
                    record_path: "$".to_string(),
                    value_path: "$.SecretString".to_string(),
                    name: firma_core::SecretNameSource::Path {
                        path: "$.Name".to_string(),
                    },
                    item_selector: None,
                    domain_selector: None,
                },
            })],
        }
    }

    #[tokio::test]
    async fn test_handle_intercepts_http_vault_response_and_pushes_secret() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "SecretString": "s3cr3t-db-pass",
                    "Name": "dbpass",
                })),
            )
            .mount(&server)
            .await;

        let (gateway_addr, push_rx) = fake_push_gateway().await;
        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");

        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_secret"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ))
        .with_http_secret_providers(vec![aws_secrets_manager_provider(&host)]);

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_http_secret")
            .await;

        let body_placeholder = match response {
            HandledResponse::Ok(dispatched) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&dispatched.body).expect("json body");
                assert_eq!(body["Name"], "dbpass");
                body["SecretString"]
                    .as_str()
                    .expect("SecretString is a placeholder string")
                    .to_string()
            }
            other => panic!("expected ok, got {other:?}"),
        };
        assert!(
            body_placeholder.starts_with(PLACEHOLDER_PREFIX),
            "expected a minted placeholder, got {body_placeholder}"
        );

        let pushed = push_rx.await.expect("gateway received a push");
        assert_eq!(pushed["placeholder"], body_placeholder);
        let value_b64 = pushed["value_b64"].as_str().expect("value_b64 field");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value_b64)
            .expect("valid base64");
        assert_eq!(decoded, b"s3cr3t-db-pass");
        // The matcher has no domain_selector, so the push must be unscoped
        // (resolves for any request host) rather than defaulted to the
        // vault's own host — an HTTP vault's response is a credential meant
        // for later use against some other downstream host.
        assert_eq!(
            pushed["domain"],
            serde_json::json!([]),
            "expected unscoped push, got domain: {:?}",
            pushed["domain"]
        );
    }

    /// Fake gateway push endpoint that always rejects the push, exercising
    /// the fail-closed branch of
    /// [`RequestHandler::rewrite_with_http_intercept`].
    async fn fake_push_gateway_err() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                if stream.read(&mut buf).await.is_ok() {
                    let response =
                        serde_json::json!({ "type": "err", "error": "broker unavailable" })
                            .to_string()
                            + "\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_handle_aborts_when_http_secret_push_fails() {
        // The matcher extracts a secret and substitutes its placeholder into
        // the body in a single synchronous pass, before the push to the
        // broker is even attempted. If that push then fails, the
        // already-substituted placeholder can never resolve — handing it to
        // the agent would be indistinguishable from silently losing the
        // credential. `handle` must abort the whole response instead of
        // forwarding a body carrying a dead placeholder.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "SecretString": "s3cr3t-db-pass",
                    "Name": "dbpass",
                })),
            )
            .mount(&server)
            .await;

        let gateway_addr = fake_push_gateway_err().await;
        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_push_fail"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ))
        .with_http_secret_providers(vec![aws_secrets_manager_provider(&host)]);

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_http_push_fail")
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(
                    detail.contains("aws-secrets-manager"),
                    "detail should name the provider, got: {detail}"
                );
            }
            other => panic!("expected push-failure abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.contains("CREDENTIAL_INJECTION_FAILED"),
            "deny_reason should carry the abort code, got: {}",
            payload.deny_reason
        );
    }

    /// Combined fake gateway serving both `secret.resolve` (always answering
    /// with the single seeded `secret_b64`) and `secret.push` (always
    /// accepting, echoing the placeholder) over independent connections —
    /// needed to exercise a request that both rehydrates an outbound
    /// placeholder and triggers HTTP-vault interception on the response in
    /// the same round trip. Every request line received is forwarded on the
    /// returned channel so a test can inspect gateway traffic.
    async fn fake_resolve_and_push_gateway(
        secret_b64: String,
    ) -> (
        SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let addr = listener.local_addr().expect("local_addr");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let secret_b64 = secret_b64.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&buf[..n]) else {
                        return;
                    };
                    let response = match request["action"].as_str() {
                        Some("secret.resolve") => {
                            format!(r#"[{{"type":"ok","secret_b64":"{secret_b64}"}}]"#) + "\n"
                        }
                        Some("secret.push") => {
                            let placeholder = request["placeholder"].clone();
                            serde_json::json!({ "type": "ok", "placeholder": placeholder })
                                .to_string()
                                + "\n"
                        }
                        _ => return,
                    };
                    let _ = tx.send(request);
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn test_handle_interception_before_masking_preserves_real_secret_on_broker() {
        // Regression test for an ordering bug: if masking (rewriting a
        // rehydrated secret's echo back to its original placeholder) ran
        // before HTTP-vault interception, interception's matcher would see
        // the already-masked *placeholder string* instead of the real
        // echoed secret, extract that placeholder text as if it were a
        // fresh secret, and push it to the broker under a brand-new
        // placeholder — losing the real secret and corrupting the broker's
        // mapping. `handle` runs interception before masking so interception
        // always sees the true response bytes.
        let secret_value = "sk-real-secret-value";
        let placeholder = SecretPlaceholder::new();
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret_value);
        let (gateway_addr, mut gateway_rx) = fake_resolve_and_push_gateway(secret_b64).await;

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "SecretString": secret_value,
                    "Name": "dbpass",
                })),
            )
            .mount(&server)
            .await;

        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_order"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ))
        .with_http_secret_providers(vec![aws_secrets_manager_provider(&host)]);

        let mut request = raw_request(host, Method::POST);
        request.body = Some(format!(r#"{{"key":"{placeholder}"}}"#).into_bytes());

        let response = handler.handle(request, "sess_order").await;

        match response {
            HandledResponse::Ok(dispatched) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&dispatched.body).expect("json body");
                let new_placeholder = body["SecretString"].as_str().expect("placeholder string");
                assert!(
                    new_placeholder.starts_with(PLACEHOLDER_PREFIX),
                    "expected a minted placeholder, got {new_placeholder}"
                );
            }
            other => panic!("expected ok, got {other:?}"),
        }

        let pushed = loop {
            let msg = gateway_rx
                .recv()
                .await
                .expect("gateway received at least a push");
            if msg["action"] == "secret.push" {
                break msg;
            }
        };
        let value_b64 = pushed["value_b64"].as_str().expect("value_b64 field");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value_b64)
            .expect("valid base64");
        assert_eq!(
            decoded,
            secret_value.as_bytes(),
            "the broker must learn the real secret value, not the literal original \
             placeholder string a mask-before-intercept ordering bug would push instead"
        );
    }

    #[tokio::test]
    async fn test_handle_no_http_secret_provider_configured_forwards_body_unmodified() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "SecretString": "s3cr3t-db-pass",
                    "Name": "dbpass",
                })),
            )
            .mount(&server)
            .await;

        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        // No `with_http_secret_providers` call: interception must be a no-op.
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_secret_none"),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
                        .expect("valid authority"),
                    Method::POST,
                ),
                "sess_http_secret_none",
            )
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&dispatched.body).expect("json body");
                assert_eq!(body["SecretString"], "s3cr3t-db-pass");
            }
            other => panic!("expected ok, got {other:?}"),
        }
    }

    fn blocked_command_provider(host: &Authority) -> HttpIntegrationSpec {
        HttpIntegrationSpec {
            provider_id: "blocked-vault".to_string(),
            host: host.to_string(),
            matchers: vec![HttpMatcherRule::BlockedCommand(PathOnly {
                path: NonEmptyString::new("/v1/chat/completions".to_string())
                    .expect("non-empty path literal"),
            })],
        }
    }

    fn safe_command_provider(host: &Authority) -> HttpIntegrationSpec {
        HttpIntegrationSpec {
            provider_id: "safe-vault".to_string(),
            host: host.to_string(),
            matchers: vec![HttpMatcherRule::SafeCommand(PathOnly {
                path: NonEmptyString::new("/v1/chat/completions".to_string())
                    .expect("non-empty path literal"),
            })],
        }
    }

    #[tokio::test]
    async fn test_handle_http_secret_provider_blocked_path_aborts_before_dispatch() {
        // A `BlockedCommand` match is a hard block that overrides whatever
        // the enforcement pipeline decided, and it must fire before the
        // connector is ever contacted: dispatching first and aborting after
        // would let a destructive vault command (e.g. delete/overwrite)
        // execute upstream before the sidecar had a chance to block it.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("should not leak"))
            .expect(0)
            .mount(&server)
            .await;

        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_blocked"),
            test_connector_registry(),
            tx,
        )
        .with_http_secret_providers(vec![blocked_command_provider(&host)]);

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_http_blocked")
            .await;

        match response {
            HandledResponse::Aborted { reason, .. } => {
                assert_eq!(reason, AbortReason::CredentialInjectionBlocked);
            }
            other => panic!("expected blocked abort, got {other:?}"),
        }

        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "connector must never contact the upstream for a blocked HTTP secret provider path"
        );
    }

    #[tokio::test]
    async fn test_handle_http_secret_provider_safe_command_passes_body_through_unmodified() {
        // A `SafeCommand` match resolves to `PassThrough`: the interception
        // layer must return the dispatched response as-is, without ever
        // reaching the matcher/gateway machinery.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "SecretString": "s3cr3t-db-pass",
                })),
            )
            .mount(&server)
            .await;

        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_safe"),
            test_connector_registry(),
            tx,
        )
        .with_http_secret_providers(vec![safe_command_provider(&host)]);

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_http_safe")
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&dispatched.body).expect("json body");
                assert_eq!(body["SecretString"], "s3cr3t-db-pass");
            }
            other => panic!("expected ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_http_secret_provider_matched_without_gateway_fails_closed() {
        // A provider is configured (mediation matches), but no secret
        // gateway was ever wired up via `with_gateway_client`. The response
        // was dispatched from a provider explicitly flagged as sensitive, so
        // a body that can't be mediated must abort rather than reach the
        // agent unexamined.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "SecretString": "s3cr3t-db-pass",
                    "Name": "dbpass",
                })),
            )
            .mount(&server)
            .await;

        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_no_gateway"),
            test_connector_registry(),
            tx,
        )
        // Provider configured, but no `with_gateway_client` call.
        .with_http_secret_providers(vec![aws_secrets_manager_provider(&host)]);

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_http_no_gateway")
            .await;

        match response {
            HandledResponse::Aborted { reason, detail } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(
                    detail.contains("aws-secrets-manager"),
                    "detail should name the provider, got: {detail}"
                );
            }
            other => panic!("expected abort, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_http_secret_provider_matcher_compile_failure_forwards_unmodified() {
        // A `Regex` matcher missing the required `value`/`name` named
        // groups fails to compile. `rewrite_with_http_intercept` must fail
        // open (forward the dispatched response unmodified) rather than
        // aborting or panicking, since the underlying request was already
        // permitted by the main enforcement pipeline.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("token=abc123"))
            .mount(&server)
            .await;

        let (gateway_addr, _push_rx) = fake_push_gateway().await;
        let host = Authority::from_str(&format!("127.0.0.1:{}", server.address().port()))
            .expect("valid authority");
        let provider = HttpIntegrationSpec {
            provider_id: "broken-matcher".to_string(),
            host: host.to_string(),
            matchers: vec![HttpMatcherRule::SensitiveCommand(PathAndMatcher {
                path: None,
                matcher: firma_core::SecretMatcher::Regex {
                    pattern: "no_named_groups_here".to_string(),
                },
            })],
        };

        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_for_session(vec![allow_rule()], true, true, "sess_http_bad_matcher"),
            test_connector_registry(),
            tx,
        )
        .with_gateway_client(GatewayClient::new(
            GatewayEndpoint::parse(&format!("tcp:{gateway_addr}")).expect("valid addr"),
            GatewayClientConfig::default(),
        ))
        .with_http_secret_providers(vec![provider]);

        let response = handler
            .handle(raw_request(host, Method::POST), "sess_http_bad_matcher")
            .await;

        match response {
            HandledResponse::Ok(dispatched) => {
                assert_eq!(dispatched.body, b"token=abc123");
            }
            other => panic!("expected ok, got {other:?}"),
        }
    }

    #[test]
    fn test_abort_body_json_shape_matches_contract() {
        let body = abort_body_json(AbortReason::ConnectorTimeout, "timeout after 100ms");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["aborted"], serde_json::Value::Bool(true));
        assert_eq!(parsed["reason"], "CONNECTOR_TIMEOUT");
        assert_eq!(parsed["detail"], "timeout after 100ms");
    }

    #[test]
    fn test_abort_body_json_supports_connector_failure_reason() {
        let body = abort_body_json(AbortReason::ConnectorFailure, "connection refused");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["aborted"], serde_json::Value::Bool(true));
        assert_eq!(parsed["reason"], "CONNECTOR_FAILURE");
        assert_eq!(parsed["detail"], "connection refused");
    }

    #[test]
    fn test_deny_body_json_shape_matches_contract() {
        let body = deny_body_json(DenyReason::PolicyDenied, "policy X blocked");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["denied"], serde_json::Value::Bool(true));
        assert!(parsed["reason"].is_string());
        assert_eq!(parsed["detail"], "policy X blocked");
    }

    #[test]
    fn tool_denial_body_json_has_documented_shape() {
        let body = tool_denial_body_json(
            DenyReason::PolicyDenied,
            "disallowed by bundle v3",
            "tool.generic",
            "my_tool",
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(parsed["denied"], serde_json::Value::Bool(true));
        assert_eq!(
            parsed["reason"],
            serde_json::json!(DenyReason::PolicyDenied)
        );
        assert_eq!(parsed["action_class"], "tool.generic");
        assert_eq!(parsed["tool_name"], "my_tool");
        assert_eq!(parsed["detail"], "disallowed by bundle v3");
    }

    #[test]
    fn deny_body_json_shape_unchanged_by_task_008() {
        let body = deny_body_json(DenyReason::ScopeViolation, "out of scope");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert!(parsed.get("tool_name").is_none());
        assert!(parsed.get("action_class").is_none());
        assert_eq!(parsed["denied"], serde_json::Value::Bool(true));
        assert_eq!(
            parsed["reason"],
            serde_json::json!(DenyReason::ScopeViolation)
        );
        assert_eq!(parsed["detail"], "out of scope");
    }

    #[test]
    fn denial_context_of_tooluse_envelope_is_tool() {
        use firma_core::ToolUseParams;
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "tool.generic".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("my_tool"),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "my_tool".to_string(),
                    input: HashMap::new(),
                }),
                raw_transport: "mcp".to_string(),
                raw_action_ref: "my_tool".to_string(),
            },
            timestamp: Utc::now(),
        };
        assert_eq!(denial_context_of(Some(&envelope)), DenialContext::Tool);
    }

    #[test]
    fn denial_context_of_http_envelope_is_api() {
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "filesystem.read".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from(
                    "https://example.test/resource",
                ),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HeaderMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "http".to_string(),
                raw_action_ref: "GET /resource".to_string(),
            },
            timestamp: Utc::now(),
        };
        assert_eq!(denial_context_of(Some(&envelope)), DenialContext::Api);
    }

    #[test]
    fn denial_context_of_dbquery_envelope_is_api() {
        use firma_core::DbQueryParams;
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "credential.read".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("pg://orders"),
                params: ActionParams::DbQuery(DbQueryParams {
                    query_name: "select_orders".to_string(),
                    bindings: HashMap::new(),
                    db_name: "orders".to_string(),
                    read_only: true,
                }),
                raw_transport: "pg".to_string(),
                raw_action_ref: "SELECT".to_string(),
            },
            timestamp: Utc::now(),
        };
        assert_eq!(denial_context_of(Some(&envelope)), DenialContext::Api);
    }

    #[test]
    fn denial_context_of_none_envelope_is_api_fail_closed() {
        assert_eq!(denial_context_of(None), DenialContext::Api);
    }

    #[test]
    fn handled_response_deny_with_tooluse_envelope_carries_tool_context() {
        // Fabricated-envelope path per FEP §5.1. The handler's Deny
        // arm is a pure mapping over (reason, detail, envelope); this
        // reproduces it exactly and asserts the context field is set
        // to Tool for a ToolUse envelope.
        use firma_core::ToolUseParams;
        let envelope = NormalizedEnvelope {
            intent: ExecutionIntent {
                action_class: "tool.generic".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("my_tool"),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "my_tool".to_string(),
                    input: HashMap::new(),
                }),
                raw_transport: "mcp".to_string(),
                raw_action_ref: "my_tool".to_string(),
            },
            timestamp: Utc::now(),
        };
        let response = HandledResponse::Deny {
            reason: DenyReason::PolicyDenied,
            detail: "fabricated tool denial".to_string(),
            context: denial_context_of(Some(&envelope)),
        };
        match response {
            HandledResponse::Deny {
                context,
                reason,
                detail,
            } => {
                assert_eq!(context, DenialContext::Tool);
                assert_eq!(reason, DenyReason::PolicyDenied);
                assert_eq!(detail, "fabricated tool denial");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_passthrough_forwards_and_emits_audit() {
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], false, true),
            test_connector_registry(),
            tx,
        );

        let response = handler
            .handle(
                raw_request(
                    Authority::from_str(&format!("127.0.0.1:{}", upstream_addr.port()))
                        .expect("valid authority"),
                    Method::GET,
                ),
                "sess_passthrough",
            )
            .await;

        match response {
            HandledResponse::Passthrough(dispatched) => {
                assert_eq!(dispatched.status, 201);
                assert_eq!(dispatched.body, b"OK");
            }
            other => panic!("expected passthrough response, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_passthrough");
        assert_eq!(payload.decision, Decision::Allow);
        assert!(rx.try_recv().is_err());
        upstream_cancel.cancel();
    }

    #[tokio::test]
    async fn test_emit_synthetic_deny_sends_deny_audit_event() {
        // Regression (FIR-208): pre-pipeline network-layer denials
        // (malformed request, strict-MITM preflight fail-closed) return
        // 403 to the client but historically emitted NO audit event, so
        // they never surfaced in `firma monitor`. emit_synthetic_deny
        // gives those paths an audit record.
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        handler
            .emit_synthetic_deny(
                "sess_x",
                "network.connect",
                "exa_mple.com/",
                DenyReason::FailClosed,
                "HTTPS_MITM_SETUP_FAILED: dns resolution failed",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(payload.session_id, "sess_x");
        assert_eq!(payload.action, "network.connect");
        assert_eq!(payload.resource, "exa_mple.com/");
        assert!(
            payload.deny_reason.contains("HTTPS_MITM_SETUP_FAILED"),
            "deny_reason should carry the detail, got {:?}",
            payload.deny_reason
        );
        assert!(
            payload.agent_id.is_empty() && payload.token_id.is_empty(),
            "pre-validation denial has no known identity"
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_emit_upgrade_abort_audit_rewrites_decision_and_keeps_identity() {
        // A websocket upgrade is authorized (ALLOW payload with verified
        // identity), then the upstream relay fails. The abort audit must
        // rewrite the decision to ABORT and carry the reason code while
        // preserving the verified agent/token attribution.
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(vec![allow_rule()], true, false),
            test_connector_registry(),
            tx,
        );

        let allow_payload = AuditPayload {
            session_id: "sess_ws".to_string(),
            token_id: "tok_ws".to_string(),
            agent_id: "agent_ws".to_string(),
            action: "communication.external.send".to_string(),
            resource: "api.openai.com/".to_string(),
            // Inbound ALLOW decision; the helper rewrites it.
            decision: Decision::Allow,
            deny_reason: String::new(),
            enforcement_latency_us: 0,
            context_hash: "ctx".to_string(),
            bundle_version: "v1".to_string(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        };

        handler
            .emit_upgrade_abort_audit(
                allow_payload,
                AbortReason::ConnectorFailure,
                "upstream websocket connect failed: connection refused",
            )
            .await;

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload.deny_reason.starts_with("CONNECTOR_FAILURE"),
            "deny_reason should carry CONNECTOR_FAILURE prefix, got {:?}",
            payload.deny_reason
        );
        // Verified identity from the ALLOW payload is preserved.
        assert_eq!(payload.agent_id, "agent_ws");
        assert_eq!(payload.token_id, "tok_ws");
        assert_eq!(payload.session_id, "sess_ws");
        assert_eq!(payload.dispatch_status, 0);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_connect_allow_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(
                vec![MappingRuleConfig {
                    method: Some(Method::CONNECT),
                    host: "*".to_string(),
                    path: Some("/".to_string()),
                    action_class: "communication.external.send".to_string(),
                }],
                true,
                true,
            ),
            test_connector_registry(),
            tx,
        );

        let outcome = handler
            .handle_connect(
                RawRequest {
                    method: Method::CONNECT,
                    host: Authority::from_static("api.openai.com:443"),
                    path: "/".to_string(),
                    headers: HeaderMap::new(),
                    body: None,
                    is_https: true,
                },
                "sess_001",
            )
            .await;

        assert!(matches!(outcome, ConnectDecision::Allow));
        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_001");
        assert_eq!(payload.decision, Decision::Allow);
        assert_eq!(payload.dispatch_status, 200);
    }

    #[tokio::test]
    async fn test_handle_connect_deny_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline(
                vec![MappingRuleConfig {
                    method: Some(Method::CONNECT),
                    host: "*".to_string(),
                    path: Some("/".to_string()),
                    action_class: "communication.external.send".to_string(),
                }],
                true,
                false,
            ),
            test_connector_registry(),
            tx,
        );

        let outcome = handler
            .handle_connect(
                RawRequest {
                    method: Method::CONNECT,
                    host: Authority::from_static("api.openai.com:443"),
                    path: "/".to_string(),
                    headers: HeaderMap::new(),
                    body: None,
                    is_https: true,
                },
                "sess_001",
            )
            .await;

        match outcome {
            ConnectDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::TokenInvalid);
            }
            other => panic!("expected connect deny, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_001");
        assert_eq!(payload.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_handle_connect_abort_blocks_tunnel_and_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_with_failing_credentials(
                vec![MappingRuleConfig {
                    method: Some(Method::CONNECT),
                    host: "*".to_string(),
                    path: Some("/".to_string()),
                    action_class: "communication.external.send".to_string(),
                }],
                "sess_connect_abort",
            ),
            test_connector_registry(),
            tx,
        );

        let outcome = handler
            .handle_connect(
                RawRequest {
                    method: Method::CONNECT,
                    host: Authority::from_static("api.openai.com:443"),
                    path: "/".to_string(),
                    headers: HeaderMap::new(),
                    body: None,
                    is_https: true,
                },
                "sess_connect_abort",
            )
            .await;

        match outcome {
            ConnectDecision::Abort { reason, detail } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(detail.contains("vault unavailable"));
            }
            other => panic!("expected connect abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_connect_abort");
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload
                .deny_reason
                .starts_with("CREDENTIAL_INJECTION_FAILED"),
            "deny_reason should carry credential abort code, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    #[tokio::test]
    async fn test_authorize_upgrade_abort_blocks_upgrade_and_emits_audit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let handler = RequestHandler::new(
            test_pipeline_with_failing_credentials(vec![allow_rule()], "sess_upgrade_abort"),
            test_connector_registry(),
            tx,
        );

        let authorization = handler
            .authorize_upgrade(
                raw_request(Authority::from_static("api.openai.com"), Method::POST),
                "sess_upgrade_abort",
            )
            .await;

        match authorization {
            UpgradeAuthorization::Abort { reason, detail } => {
                assert_eq!(reason, AbortReason::CredentialInjectionFailed);
                assert!(detail.contains("vault unavailable"));
            }
            other => panic!("expected upgrade abort, got {other:?}"),
        }

        let payload = rx
            .try_recv()
            .unwrap_or_else(|e| panic!("expected one audit payload: {e}"));
        assert_eq!(payload.session_id, "sess_upgrade_abort");
        assert_eq!(payload.decision, Decision::Abort);
        assert!(
            payload
                .deny_reason
                .starts_with("CREDENTIAL_INJECTION_FAILED"),
            "deny_reason should carry credential abort code, got {:?}",
            payload.deny_reason
        );
        assert_eq!(payload.dispatch_status, 0);
    }

    // ── collect_placeholders ───────────────────────────────────────────────

    #[test]
    fn collect_placeholders_finds_single_token() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("Authorization: Bearer {placeholder}\r\n");
        let tokens = collect_placeholders(body.as_bytes());
        assert_eq!(tokens, &[placeholder]);
    }

    #[test]
    fn collect_placeholders_deduplicates() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("{placeholder} and again {placeholder}");
        let tokens = collect_placeholders(body.as_bytes());
        assert_eq!(tokens, &[placeholder]);
    }

    #[test]
    fn collect_placeholders_finds_multiple_distinct_tokens() {
        let placeholder1 = SecretPlaceholder::new();
        let placeholder2 = SecretPlaceholder::new();
        let body = format!("{{\"a\":\"{placeholder1}\",\"b\":\"{placeholder2}\"}}");
        let tokens = collect_placeholders(body.as_bytes());
        assert_eq!(tokens, &[placeholder1, placeholder2]);
    }

    #[test]
    fn collect_placeholders_returns_empty_when_none_present() {
        let body = b"no placeholders here";
        assert!(collect_placeholders(body).is_empty());
    }

    #[test]
    fn collect_placeholders_stops_at_quote() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("\"{placeholder}\"");
        let tokens = collect_placeholders(body.as_bytes());
        assert_eq!(tokens, &[placeholder]);
    }

    #[test]
    fn collect_placeholders_finds_both_when_adjacent_with_no_separator() {
        // Regression test: the first placeholder's greedy alphanumeric scan
        // used to swallow the second placeholder's `fsp_` prefix (its
        // letters are alphanumeric, only the underscore stops the run),
        // fail to parse the resulting oversized token, and then resume
        // scanning past the underscore — never re-aligning with the second
        // prefix. Both placeholders were silently dropped from the result,
        // which meant `rehydrate_request` saw an empty placeholder list and
        // dispatched the request with both tokens still literal in the
        // body instead of failing closed.
        let p1 = SecretPlaceholder::new();
        let p2 = SecretPlaceholder::new();
        let body = format!("{p1}{p2}");
        let tokens = collect_placeholders(body.as_bytes());
        assert_eq!(tokens, &[p1, p2]);
    }

    #[test]
    fn collect_placeholders_skips_long_invalid_run_without_quadratic_scan() {
        // Regression: a body of `fsp_` plus a long alphanumeric run that
        // never forms a valid token used to shrink the candidate span one
        // byte at a time across the entire run, running `from_utf8` over an
        // O(n)-long slice per candidate — a quadratic CPU DoS on the
        // enforcement hot path. The shrink window is now bounded to the
        // fixed placeholder length, so the trailing valid token is still
        // found and the run is skipped in linear time.
        let placeholder = SecretPlaceholder::new();
        let mut body = format!("fsp_{}", "a".repeat(1 << 16));
        body.push_str(&placeholder.to_string());
        let tokens = collect_placeholders(body.as_bytes());
        assert_eq!(tokens, &[placeholder]);
    }
}
