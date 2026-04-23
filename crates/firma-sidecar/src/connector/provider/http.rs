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

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use firma_core::{
    ActionParams, Connector, ConnectorError, ConnectorResponse, HttpMethod, TransportView,
};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

type DirectRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Default dispatch timeout applied when no per-host value is set.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Build-time configuration for a [`GenericHttpConnector`] instance.
///
/// Built from the sidecar [`HostConnectorConfig`](crate::config::HostConnectorConfig)
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
    pub rps: NonZeroU32,
    /// Bucket capacity.
    pub burst: NonZeroU32,
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
    /// Returns [`HttpConnectorBuildError::Client`] when the underlying
    /// [`reqwest::Client`] cannot be constructed (TLS setup failure,
    /// invalid runtime defaults).
    pub fn new(config: &HttpConnectorConfig) -> Result<Self, HttpConnectorBuildError> {
        let client = reqwest::Client::builder()
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
    /// Returns [`HttpConnectorBuildError::Client`] when the underlying
    /// [`reqwest::Client`] cannot be constructed.
    pub fn default_for_unconfigured() -> Result<Self, HttpConnectorBuildError> {
        Self::new(&HttpConnectorConfig {
            timeout: DEFAULT_TIMEOUT,
            rate_limit: None,
        })
    }

    /// Runs the rate limiter wait, bounded by the dispatch timeout.
    async fn acquire_permit(&self, deadline: Instant) -> Result<(), ConnectorError> {
        let Some(limiter) = self.rate_limiter.as_ref() else {
            return Ok(());
        };
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err(ConnectorError::Timeout(self.timeout));
        }
        match tokio::time::timeout(remaining, limiter.until_ready()).await {
            Ok(()) => Ok(()),
            Err(_) => Err(ConnectorError::Timeout(self.timeout)),
        }
    }
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

        let deadline = Instant::now() + self.timeout;
        self.acquire_permit(deadline).await?;

        let method = to_reqwest_method(http.method);
        let scheme = if intent.raw_transport == "https" {
            "https"
        } else {
            "http"
        };
        let url = format!("{scheme}://{}", intent.resource_display());
        let mut builder = self.client.request(method, url);

        if !http.query.is_empty() {
            let query: Vec<(&str, &str)> = http
                .query
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            builder = builder.query(&query);
        }

        for (name, value) in &http.headers {
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
            .map_err(|e| ConnectorError::InvalidRequest(e.to_string()))?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ConnectorError::Timeout(self.timeout));
        }

        let started = Instant::now();
        let response = match tokio::time::timeout(remaining, self.client.execute(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                if err.is_timeout() {
                    return Err(ConnectorError::Timeout(self.timeout));
                }
                return Err(ConnectorError::Network(err.to_string()));
            }
            Err(_) => return Err(ConnectorError::Timeout(self.timeout)),
        };

        let status = response.status().as_u16();
        let headers = extract_headers(response.headers());

        let remaining = deadline.saturating_duration_since(Instant::now());
        let body_fut = response.bytes();
        let body = match tokio::time::timeout(remaining, body_fut).await {
            Ok(Ok(bytes)) => bytes.to_vec(),
            Ok(Err(err)) => return Err(ConnectorError::Network(err.to_string())),
            Err(_) => return Err(ConnectorError::Timeout(self.timeout)),
        };

        let dispatch_latency = started.elapsed();
        let response_size = body.len();
        Ok(ConnectorResponse {
            status,
            headers,
            body,
            dispatch_latency,
            response_size,
        })
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
    }
}

fn extract_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;

    use firma_core::{
        ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
        HttpParams, InjectedCredentials,
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn view_for(intent: ExecutionIntent, creds: InjectedCredentials) -> TransportView {
        let envelope = ExecutionEnvelope::new(
            intent,
            "v4.public.eyJ0...".to_string(),
            ExecutionMetadata {
                session_id: "sess".parse().expect("literal session id"),
                agent_id: "agent".parse().expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        );
        TransportView::new(envelope, creds)
    }

    fn get_intent(resource: String) -> ExecutionIntent {
        ExecutionIntent {
            action_class: "filesystem.read".to_string(),
            resource: firma_core::ExecutionIntent::resource_map_from(&resource),
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::GET,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "http".to_string(),
            raw_action_ref: "GET /".to_string(),
        }
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
            get_intent(format!("{}/data", server.address())),
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
            "Authorization".to_string(),
            "Bearer secret".to_string(),
        )]));
        let view = view_for(get_intent(format!("{}/secure", server.address())), creds);

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
            get_intent(format!("{}/boom", server.address())),
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
            get_intent(format!("{}/slow", server.address())),
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
            get_intent("http://127.0.0.1:1/".to_string()),
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
        let first_view = view_for(get_intent(url.clone()), InjectedCredentials::empty());
        let first = connector
            .dispatch(&first_view)
            .await
            .expect("first call succeeds");
        assert_eq!(first.status, 200);

        // Second call must wait for the limiter to refill. Measure the
        // wall-clock gap to confirm the limiter actually throttled.
        let second_view = view_for(get_intent(url), InjectedCredentials::empty());
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
                headers: HashMap::new(),
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
}
