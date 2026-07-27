//! Generic HTTP connector used as the registry default and as the
//! provider for every host without a specialized override.
//!
//! Translates an [`ExecutionEnvelope`] whose params are
//! [`ActionParams::Http`] into a [`reqwest::Request`], applies the
//! configured per-host technical constraints (rate limit, timeout),
//! merges credentials from the [`TransportView`], and returns the raw
//! response to the caller.
//!
//! This connector is scope-bounded by FEP §6.2: it does not make
//! authorization decisions, does not modify intent fields, and reads
//! credentials exclusively from the view.

use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use firma_core::{
    ActionParams, Connector, ConnectorError, ConnectorResponse, ExecutionIntent, HttpMethod,
    HttpParams, TransportView,
};
use firma_http::HeaderMap;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};

type DirectRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Default dispatch timeout applied when no per-host value is set.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Build-time configuration for a [`GenericHttpConnector`] instance.
///
/// Built from sidecar host connector configuration entries
/// at startup. Per-host instances carry a rate limiter; the registry
/// default built via
/// [`GenericHttpConnector::default_for_unconfigured`] does not.
#[derive(Debug, Clone)]
pub struct HttpConnectorConfig {
    /// Dispatch timeout for both the rate-limiter wait and the
    /// upstream call. Required.
    pub timeout: Duration,
    /// Optional token-bucket rate limiter parameters.
    pub rate_limit: Option<RateLimitConfig>,
}

/// Token-bucket rate-limit parameters.
///
/// `rps` is the sustained refill rate (tokens per second); `burst` is
/// the bucket capacity (maximum instantaneous burst).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Tokens produced per second.
    pub(crate) rps: NonZeroU32,
    /// Bucket capacity.
    pub(crate) burst: NonZeroU32,
}

/// Errors raised while constructing a [`GenericHttpConnector`].
///
/// Kept separate from [`ConnectorError`] because these failures are
/// startup-time configuration bugs, not hot-path dispatch outcomes.
#[derive(Debug, thiserror::Error)]
pub enum HttpConnectorBuildError {
    /// The underlying [`reqwest::Client`] could not be constructed.
    #[error("failed to build reqwest client: {0}")]
    Client(String),
}

/// HTTP connector built on [`reqwest::Client`].
///
/// One instance per configured host plus one registry default.
/// Connection pooling and HTTP/2 multiplexing are inherited from the
/// underlying client; the `Arc<Client>` is cheap to clone into the
/// registry.
///
/// The workspace `reqwest` dependency does not enable the `gzip`/`brotli`/
/// `deflate`/`zstd` features, so this client never automatically decodes a
/// compressed response body: a `Content-Encoding`-compressed upstream
/// response is forwarded with its compressed bytes intact. Secret-gateway
/// response masking and HTTP secret provider interception both scan the raw
/// body for plaintext content-type structure (JSON/XML/form), so neither
/// sees anything to redact or extract in a compressed body — a real, if
/// narrow, sharp edge for any secret-provider host that returns compressed
/// responses.
pub struct GenericHttpConnector {
    client: Arc<reqwest::Client>,
    rate_limiter: Option<Arc<DirectRateLimiter>>,
    timeout: Duration,
}

impl GenericHttpConnector {
    /// Builds a connector with the given [`HttpConnectorConfig`].
    ///
    /// # Errors
    ///
    /// Returns `HttpConnectorBuildError::Client` when the underlying
    /// [`reqwest::Client`] cannot be constructed (TLS setup failure,
    /// invalid runtime defaults).
    pub fn new(config: &HttpConnectorConfig) -> Result<Self, HttpConnectorBuildError> {
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(build_reqwest_tls_config()?)
            .build()
            .map_err(|e| HttpConnectorBuildError::Client(e.to_string()))?;
        let rate_limiter = config.rate_limit.map(|rl| {
            let quota = Quota::per_second(rl.rps).allow_burst(rl.burst);
            Arc::new(RateLimiter::direct(quota))
        });
        Ok(Self {
            client: Arc::new(client),
            rate_limiter,
            timeout: config.timeout,
        })
    }

    /// Builds the registry default connector: 30s timeout, no rate
    /// limit.
    ///
    /// Used for every host that does not have an explicit override —
    /// typically passthrough hosts and protected hosts without a
    /// configured entry.
    ///
    /// # Errors
    ///
    /// Returns `HttpConnectorBuildError::Client` when the underlying
    /// [`reqwest::Client`] cannot be constructed.
    pub(crate) fn default_for_unconfigured() -> Result<Self, HttpConnectorBuildError> {
        Self::new(&HttpConnectorConfig {
            timeout: DEFAULT_TIMEOUT,
            rate_limit: None,
        })
    }

    /// Waits for the next rate-limit permit when configured.
    async fn acquire_permit(&self) {
        if let Some(limiter) = self.rate_limiter.as_ref() {
            limiter.until_ready().await;
        }
    }

    async fn dispatch_inner(
        &self,
        view: &TransportView,
        intent: &ExecutionIntent,
        http: &HttpParams,
    ) -> Result<ConnectorResponse, ConnectorError> {
        self.acquire_permit().await;

        let method = to_reqwest_method(http.method);
        let scheme = if intent.raw_transport == "https" {
            "https"
        } else {
            "http"
        };
        let resource_display = intent.resource_display();
        let outbound_resource = if http.query.is_empty() {
            resource_display.as_str()
        } else {
            resource_display
                .split_once('?')
                .map_or(resource_display.as_str(), |(resource, _)| resource)
        };
        let url = format!("{scheme}://{outbound_resource}");
        let mut builder = self.client.request(method, url);

        if !http.query.is_empty() {
            let query: Vec<(&str, &str)> = http
                .query
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            builder = builder.query(&query);
        }

        for (name, value) in http.headers.iter() {
            builder = builder.header(name, value);
        }
        for (name, value) in view.credentials().headers() {
            builder = builder.header(name, value);
        }

        if let Some(body) = http.body.as_ref() {
            builder = builder.body(body.clone());
        }

        let request = builder
            .build()
            .map_err(|err| map_reqwest_error(&err, self.timeout))?;

        let response = self
            .client
            .execute(request)
            .await
            .map_err(|err| map_reqwest_error(&err, self.timeout))?;

        let status = response.status().as_u16();
        let headers = HeaderMap(response.headers().clone());
        let body = response
            .bytes()
            .await
            .map_err(|err| map_reqwest_error(&err, self.timeout))?
            .to_vec();
        let response_size = body.len();

        Ok(ConnectorResponse {
            status,
            headers,
            body,
            dispatch_latency: Duration::ZERO,
            response_size,
        })
    }
}

fn build_reqwest_tls_config() -> Result<rustls::ClientConfig, HttpConnectorBuildError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| HttpConnectorBuildError::Client(e.to_string()))?
    .with_platform_verifier()
    .map_err(|e| HttpConnectorBuildError::Client(e.to_string()))?;
    Ok(builder.with_no_client_auth())
}

#[async_trait]
impl Connector for GenericHttpConnector {
    async fn dispatch(&self, view: &TransportView) -> Result<ConnectorResponse, ConnectorError> {
        let envelope = view.envelope();
        let intent = envelope.intent();
        let ActionParams::Http(http) = &intent.params else {
            return Err(ConnectorError::InvalidRequest(
                "non-HTTP params cannot be dispatched by GenericHttpConnector".to_string(),
            ));
        };

        let host = intent.resource.get("host").map_or("", String::as_str);
        let path = intent.resource.get("path").map_or("", String::as_str);
        let method_label = http.method.as_str();

        tracing::debug!(
            target_host = %host,
            method = method_label,
            path = %path,
            "dispatching",
        );

        let started = Instant::now();
        let inner = self.dispatch_inner(view, intent, http);
        let result = tokio::time::timeout(self.timeout, inner)
            .await
            .unwrap_or(Err(ConnectorError::Timeout(self.timeout)));
        let elapsed = started.elapsed();
        let elapsed_micros = duration_to_u64_micros(elapsed);

        match result {
            Ok(mut response) => {
                response.dispatch_latency = elapsed;
                tracing::debug!(
                    target_host = %host,
                    method = method_label,
                    path = %path,
                    status = response.status,
                    latency_us = elapsed_micros,
                    "dispatched",
                );
                Ok(response)
            }
            Err(err) => {
                tracing::error!(
                    target_host = %host,
                    method = method_label,
                    path = %path,
                    kind = ?err,
                    elapsed_us = elapsed_micros,
                    "dispatch failed",
                );
                Err(err)
            }
        }
    }
}

fn to_reqwest_method(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::GET => reqwest::Method::GET,
        HttpMethod::POST => reqwest::Method::POST,
        HttpMethod::PUT => reqwest::Method::PUT,
        HttpMethod::DELETE => reqwest::Method::DELETE,
        HttpMethod::PATCH => reqwest::Method::PATCH,
        HttpMethod::HEAD => reqwest::Method::HEAD,
        HttpMethod::OPTIONS => reqwest::Method::OPTIONS,
        HttpMethod::CONNECT => reqwest::Method::CONNECT,
    }
}

/// Flag projection of a [`reqwest::Error`] sufficient to choose a
/// [`ConnectorError`] variant.
///
/// Kept as a pure data struct so the mapping decision is unit-testable
/// without synthesizing opaque `reqwest::Error` values. Populated by
/// [`reqwest_error_flags`] from a real error in the dispatch path.
#[expect(
    clippy::struct_excessive_bools,
    reason = "This mirrors reqwest's classifier surface for pure unit testing."
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReqwestErrorFlags {
    is_timeout: bool,
    is_connect: bool,
    is_request: bool,
    is_body: bool,
    is_decode: bool,
    is_builder: bool,
}

/// Classified outcome carrying just the [`ConnectorError`] variant kind.
///
/// Returned by [`classify_reqwest_error`]; the dispatch site rehydrates
/// it into a full [`ConnectorError`] with the configured timeout and a
/// short stable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectorErrorKind {
    Timeout,
    Network,
    InvalidRequest,
}

fn reqwest_error_flags(err: &reqwest::Error) -> ReqwestErrorFlags {
    ReqwestErrorFlags {
        is_timeout: err.is_timeout(),
        is_connect: err.is_connect(),
        is_request: err.is_request(),
        is_body: err.is_body(),
        is_decode: err.is_decode(),
        is_builder: err.is_builder(),
    }
}

/// Maps a [`ReqwestErrorFlags`] projection onto the
/// [`ConnectorError`] variant the dispatch path should surface.
///
/// Order matters: `is_timeout` and `is_builder` are checked before the
/// transport family so that a builder error masquerading as a request
/// error does not get smeared into `Network`.
///
/// Unknown / all-false combinations fall through to [`Network`] since
/// the runtime maps `Network` to DENY.
fn classify_reqwest_error(flags: ReqwestErrorFlags) -> ConnectorErrorKind {
    if flags.is_timeout {
        ConnectorErrorKind::Timeout
    } else if flags.is_builder {
        ConnectorErrorKind::InvalidRequest
    } else {
        ConnectorErrorKind::Network
    }
}

/// Translates a [`reqwest::Error`] into a [`ConnectorError`].
///
/// Logs any unknown / all-false flag combination so an operator sees a
/// fail-closed `Network` mapping that did not match a known reqwest
/// classifier.
fn map_reqwest_error(err: &reqwest::Error, configured: Duration) -> ConnectorError {
    let flags = reqwest_error_flags(err);
    let kind = classify_reqwest_error(flags);
    if !flags.is_timeout
        && !flags.is_builder
        && !flags.is_connect
        && !flags.is_request
        && !flags.is_body
        && !flags.is_decode
    {
        tracing::warn!(
            error = %err,
            "reqwest error matched no known classifier; mapping to Network",
        );
    }

    match kind {
        ConnectorErrorKind::Timeout => ConnectorError::Timeout(configured),
        ConnectorErrorKind::Network => ConnectorError::Network(reqwest_error_message(err, flags)),
        ConnectorErrorKind::InvalidRequest => ConnectorError::InvalidRequest(err.to_string()),
    }
}

fn reqwest_error_message(err: &reqwest::Error, flags: ReqwestErrorFlags) -> String {
    let prefix = if flags.is_connect {
        "connect"
    } else if flags.is_body {
        "body"
    } else if flags.is_decode {
        "decode"
    } else if flags.is_request {
        "request"
    } else {
        "transport"
    };
    format!("{prefix}: {err}")
}

fn duration_to_u64_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex, MutexGuard};

    use firma_core::{
        ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
        HttpParams, InjectedCredentials,
    };
    use firma_http::{HeaderMap, HeaderName};
    use tracing_subscriber::fmt::MakeWriter;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[derive(Clone, Default)]
    struct CapturingWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturingWriter {
        fn snapshot(&self) -> String {
            let guard: MutexGuard<'_, Vec<u8>> = self
                .buf
                .lock()
                .expect("capture mutex must not be poisoned in tests");
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl Write for CapturingWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let mut guard = self
                .buf
                .lock()
                .expect("capture mutex must not be poisoned in tests");
            guard.extend_from_slice(data);
            drop(guard);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturingWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture_subscriber(writer: CapturingWriter) -> impl tracing::Subscriber + Send + Sync {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish()
    }

    /// Force re-evaluation of every registered tracing callsite.
    ///
    /// Tracing caches each callsite's `Interest` the first time the event
    /// fires. If that first hit happens on a thread that has no subscriber
    /// installed (e.g. another test running in parallel), the callsite
    /// caches `Interest::never()` and stays silent on every later thread —
    /// even one that has a thread-local subscriber set. Calling this
    /// after `set_default` makes the callsite re-ask each registered
    /// dispatcher and unblocks capture.
    fn rebuild_interest() {
        tracing::callsite::rebuild_interest_cache();
    }

    fn view_for(intent: ExecutionIntent, creds: InjectedCredentials) -> TransportView {
        let envelope = ExecutionEnvelope::new(
            intent,
            "v4.public.eyJ0...".to_string(),
            ExecutionMetadata {
                session_id: "sess".parse().expect("literal session id"),
                agent_id: "agt_01j0000000e008000000000001"
                    .parse()
                    .expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        );
        TransportView::new(envelope, creds)
    }

    fn get_intent(resource: &str) -> ExecutionIntent {
        ExecutionIntent {
            action_class: "filesystem.read".to_string(),
            resource: firma_core::ExecutionIntent::resource_map_from(resource),
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::GET,
                headers: HeaderMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "http".to_string(),
            raw_action_ref: "GET /".to_string(),
        }
    }

    #[test]
    fn classify_timeout_flag_yields_timeout() {
        let flags = ReqwestErrorFlags {
            is_timeout: true,
            is_connect: false,
            is_request: false,
            is_body: false,
            is_decode: false,
            is_builder: false,
        };

        assert_eq!(classify_reqwest_error(flags), ConnectorErrorKind::Timeout);
    }

    #[test]
    fn classify_connect_flag_yields_network() {
        let flags = ReqwestErrorFlags {
            is_timeout: false,
            is_connect: true,
            is_request: false,
            is_body: false,
            is_decode: false,
            is_builder: false,
        };

        assert_eq!(classify_reqwest_error(flags), ConnectorErrorKind::Network);
    }

    #[test]
    fn classify_builder_flag_yields_invalid_request() {
        let flags = ReqwestErrorFlags {
            is_timeout: false,
            is_connect: false,
            is_request: false,
            is_body: false,
            is_decode: false,
            is_builder: true,
        };

        assert_eq!(
            classify_reqwest_error(flags),
            ConnectorErrorKind::InvalidRequest
        );
    }

    #[test]
    fn classify_body_flag_yields_network() {
        let flags = ReqwestErrorFlags {
            is_timeout: false,
            is_connect: false,
            is_request: false,
            is_body: true,
            is_decode: false,
            is_builder: false,
        };

        assert_eq!(classify_reqwest_error(flags), ConnectorErrorKind::Network);
    }

    #[test]
    fn classify_decode_flag_yields_network() {
        let flags = ReqwestErrorFlags {
            is_timeout: false,
            is_connect: false,
            is_request: false,
            is_body: false,
            is_decode: true,
            is_builder: false,
        };

        assert_eq!(classify_reqwest_error(flags), ConnectorErrorKind::Network);
    }

    #[test]
    fn classify_no_flags_falls_back_to_network() {
        let flags = ReqwestErrorFlags {
            is_timeout: false,
            is_connect: false,
            is_request: false,
            is_body: false,
            is_decode: false,
            is_builder: false,
        };

        assert_eq!(classify_reqwest_error(flags), ConnectorErrorKind::Network);
    }

    #[test]
    fn classify_timeout_dominates_connect() {
        let flags = ReqwestErrorFlags {
            is_timeout: true,
            is_connect: true,
            is_request: true,
            is_body: false,
            is_decode: false,
            is_builder: false,
        };

        assert_eq!(classify_reqwest_error(flags), ConnectorErrorKind::Timeout);
    }

    #[tokio::test]
    async fn test_dispatch_forwards_request_and_returns_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
            .mount(&server)
            .await;

        let connector = GenericHttpConnector::default_for_unconfigured()
            .expect("connector build should succeed");
        let view = view_for(
            get_intent(&format!("{}/data", server.address())),
            InjectedCredentials::empty(),
        );

        let response = connector
            .dispatch(&view)
            .await
            .expect("dispatch should succeed");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello".to_vec());
        assert_eq!(response.response_size, 5);
    }

    #[tokio::test]
    async fn test_dispatch_merges_injected_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secure"))
            .and(header("Authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let connector = GenericHttpConnector::default_for_unconfigured()
            .expect("connector build should succeed");
        let creds = InjectedCredentials::new(HashMap::from([(
            HeaderName::from_static("authorization"),
            "Bearer secret".to_string(),
        )]));
        let view = view_for(get_intent(&format!("{}/secure", server.address())), creds);

        let response = connector
            .dispatch(&view)
            .await
            .expect("dispatch should succeed");
        assert_eq!(response.status, 204);
    }

    #[tokio::test]
    async fn test_dispatch_relays_upstream_5xx_as_ok() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/boom"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;

        let connector = GenericHttpConnector::default_for_unconfigured()
            .expect("connector build should succeed");
        let view = view_for(
            get_intent(&format!("{}/boom", server.address())),
            InjectedCredentials::empty(),
        );

        let response = connector
            .dispatch(&view)
            .await
            .expect("5xx should be relayed, not error");
        assert_eq!(response.status, 503);
        assert_eq!(response.body, b"down".to_vec());
    }

    #[tokio::test]
    async fn test_dispatch_times_out_on_slow_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;

        let connector = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: Duration::from_millis(100),
            rate_limit: None,
        })
        .expect("connector build should succeed");
        let view = view_for(
            get_intent(&format!("{}/slow", server.address())),
            InjectedCredentials::empty(),
        );

        let err = connector
            .dispatch(&view)
            .await
            .expect_err("slow upstream should time out");
        assert!(matches!(err, ConnectorError::Timeout(_)));
    }

    #[tokio::test]
    async fn test_dispatch_network_error_when_target_unreachable() {
        let connector = GenericHttpConnector::default_for_unconfigured()
            .expect("connector build should succeed");
        // Port 1 is reserved; a connect attempt reliably fails.
        let view = view_for(
            get_intent("http://127.0.0.1:1/"),
            InjectedCredentials::empty(),
        );

        let err = connector
            .dispatch(&view)
            .await
            .expect_err("unreachable target should error");
        assert!(matches!(
            err,
            ConnectorError::Network(_) | ConnectorError::Timeout(_)
        ));
    }

    #[tokio::test]
    async fn test_dispatch_rejects_non_http_params() {
        use firma_core::ToolUseParams;

        let intent = ExecutionIntent {
            action_class: "tool.invoke".to_string(),
            resource: firma_core::ExecutionIntent::resource_map_from("calculator"),
            params: ActionParams::ToolUse(ToolUseParams {
                tool_name: "calc".to_string(),
                input: HashMap::new(),
            }),
            raw_transport: "http".to_string(),
            raw_action_ref: "tool".to_string(),
        };
        let connector = GenericHttpConnector::default_for_unconfigured()
            .expect("connector build should succeed");
        let view = view_for(intent, InjectedCredentials::empty());

        let err = connector
            .dispatch(&view)
            .await
            .expect_err("non-HTTP params must be rejected");
        assert!(matches!(err, ConnectorError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn test_dispatch_applies_rate_limiter() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/quick"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let connector = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: Duration::from_secs(5),
            rate_limit: Some(RateLimitConfig {
                rps: NonZeroU32::new(2).expect("rps must be non-zero"),
                burst: NonZeroU32::new(1).expect("burst must be non-zero"),
            }),
        })
        .expect("connector build should succeed");
        let url = format!("{}/quick", server.address());

        // First call consumes the burst.
        let first_view = view_for(get_intent(&url), InjectedCredentials::empty());
        let first = connector
            .dispatch(&first_view)
            .await
            .expect("first call succeeds");
        assert_eq!(first.status, 200);

        // Second call must wait for the limiter to refill. Measure the
        // wall-clock gap to confirm the limiter actually throttled.
        let second_view = view_for(get_intent(&url), InjectedCredentials::empty());
        let started = Instant::now();
        let second = connector
            .dispatch(&second_view)
            .await
            .expect("second call succeeds after waiting");
        let elapsed = started.elapsed();
        assert_eq!(second.status, 200);
        assert!(
            elapsed >= Duration::from_millis(200),
            "second call should have waited for the limiter (elapsed {elapsed:?})"
        );
    }

    #[tokio::test]
    async fn test_dispatch_query_parameters_are_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .and(wiremock::matchers::query_param("q", "rust"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let intent = ExecutionIntent {
            action_class: "filesystem.read".to_string(),
            resource: firma_core::ExecutionIntent::resource_map_from(&format!(
                "{}/search",
                server.address()
            )),
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::GET,
                headers: HeaderMap::new(),
                body: None,
                query: HashMap::from([("q".to_string(), "rust".to_string())]),
            }),
            raw_transport: "http".to_string(),
            raw_action_ref: "GET /search".to_string(),
        };
        let connector = GenericHttpConnector::default_for_unconfigured()
            .expect("connector build should succeed");
        let view = view_for(intent, InjectedCredentials::empty());

        let response = connector
            .dispatch(&view)
            .await
            .expect("dispatch should succeed");
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_dispatch_rate_limit_wait_exhausts_timeout_budget() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/quick"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let connector = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: Duration::from_millis(100),
            rate_limit: Some(RateLimitConfig {
                rps: NonZeroU32::new(1).expect("rps must be non-zero"),
                burst: NonZeroU32::new(1).expect("burst must be non-zero"),
            }),
        })
        .expect("connector build should succeed");
        let url = format!("{}/quick", server.address());

        let view_a = view_for(get_intent(&url), InjectedCredentials::empty());
        let _first = connector.dispatch(&view_a).await;

        let view_b = view_for(get_intent(&url), InjectedCredentials::empty());
        let _second = connector.dispatch(&view_b).await;

        let view_c = view_for(get_intent(&url), InjectedCredentials::empty());
        let err = connector
            .dispatch(&view_c)
            .await
            .expect_err("trailing call must time out on rate-limit wait alone");
        match err {
            ConnectorError::Timeout(duration) => {
                assert_eq!(duration, Duration::from_millis(100));
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_logs_entry_and_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/log-ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let writer = CapturingWriter::default();
        let snapshot = {
            let subscriber = capture_subscriber(writer.clone());
            let _guard = tracing::subscriber::set_default(subscriber);
            rebuild_interest();

            let connector = GenericHttpConnector::default_for_unconfigured()
                .expect("connector build should succeed");
            let view = view_for(
                get_intent(&format!("{}/log-ok", server.address())),
                InjectedCredentials::empty(),
            );
            connector
                .dispatch(&view)
                .await
                .expect("dispatch should succeed");
            writer.snapshot()
        };

        assert!(
            snapshot.contains("dispatching"),
            "expected entry log; got: {snapshot}",
        );
        assert!(
            snapshot.contains("dispatched"),
            "expected success log; got: {snapshot}",
        );
        assert!(
            snapshot.contains("status=200"),
            "expected status field; got: {snapshot}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "flaky: tracing callsite Interest cache races with parallel tests"]
    async fn test_dispatch_logs_error_on_failure() {
        let writer = CapturingWriter::default();
        let snapshot = {
            let subscriber = capture_subscriber(writer.clone());
            let _guard = tracing::subscriber::set_default(subscriber);
            rebuild_interest();

            let connector = GenericHttpConnector::default_for_unconfigured()
                .expect("connector build should succeed");
            let view = view_for(
                get_intent("http://127.0.0.1:1/"),
                InjectedCredentials::empty(),
            );
            let err = connector
                .dispatch(&view)
                .await
                .expect_err("connect refused must fail");
            assert!(matches!(
                err,
                ConnectorError::Network(_) | ConnectorError::Timeout(_)
            ));
            writer.snapshot()
        };

        assert!(
            snapshot.contains("dispatching"),
            "expected entry log; got: {snapshot}",
        );
        assert!(
            snapshot.contains("dispatch failed"),
            "expected error log; got: {snapshot}",
        );
        assert!(
            snapshot.contains("kind="),
            "expected kind= field; got: {snapshot}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_does_not_log_credential_values() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secret"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let secret_value = "Bearer hunter2-must-not-leak";
        let writer = CapturingWriter::default();
        let snapshot = {
            let subscriber = capture_subscriber(writer.clone());
            let _guard = tracing::subscriber::set_default(subscriber);
            rebuild_interest();

            let connector = GenericHttpConnector::default_for_unconfigured()
                .expect("connector build should succeed");
            let creds = InjectedCredentials::new(HashMap::from([(
                HeaderName::from_static("authorization"),
                secret_value.to_string(),
            )]));
            let view = view_for(get_intent(&format!("{}/secret", server.address())), creds);
            connector
                .dispatch(&view)
                .await
                .expect("dispatch should succeed");
            writer.snapshot()
        };

        assert!(
            !snapshot.contains("hunter2-must-not-leak"),
            "credential value must not appear in logs; got: {snapshot}",
        );
        assert!(
            !snapshot.contains("Bearer hunter2"),
            "credential prefix must not appear in logs; got: {snapshot}",
        );
    }
}
