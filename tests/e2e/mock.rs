use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::sync::oneshot;

// ── Mock response builder ─────────────────────────────────────────────────────

/// Configures the HTTP response returned by the capture server for a mock route.
pub struct MockResponseBuilder {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponseBuilder {
    pub(crate) fn new() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }
}

// ── Mock spec ─────────────────────────────────────────────────────────────────

pub struct MockSpec {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

// ── HttpMock short-lived handle ───────────────────────────────────────────────

/// Short-lived handle returned by [`crate::setup::ScenarioSetup::http_mock`].
pub struct HttpMock<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) mock_specs: &'a mut Vec<MockSpec>,
}

impl HttpMock<'_> {
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    #[must_use]
    pub fn url_for(&self, path: &str) -> String {
        format!("{}{}", self.url(), path)
    }

    #[must_use]
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    #[must_use]
    pub fn host(&self) -> &str {
        self.host
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Register an HTTP mock route. The `configure` closure receives a
    /// [`MockResponseBuilder`] and should chain `.with_status()`, `.with_body()`,
    /// etc. Routes are activated in the capture server after the baseline phase.
    pub fn serve(
        &mut self,
        method: impl Into<String>,
        path: impl Into<String>,
        configure: impl FnOnce(MockResponseBuilder) -> MockResponseBuilder,
    ) {
        let response = configure(MockResponseBuilder::new());
        self.mock_specs.push(MockSpec {
            method: method.into(),
            path: path.into(),
            status: response.status,
            headers: response.headers,
            body: response.body,
        });
    }
}

// ── Capture server ────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct CaptureState {
    pub(crate) mocks: Vec<MockSpec>,
    pub(crate) received: Vec<ReceivedRequest>,
}

/// An HTTP request captured by the mock server during the enforcement phase.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ReceivedRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

impl ReceivedRequest {
    #[must_use]
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or_default()
    }

    #[must_use]
    pub fn body_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

pub async fn run_capture_server(
    listener: tokio::net::TcpListener,
    state: Arc<Mutex<CaptureState>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accept = listener.accept() => {
                let Ok((stream, _)) = accept else { break; };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req: Request<Incoming>| {
                            let s = Arc::clone(&state);
                            handle_capture_request(req, s)
                        }))
                        .await;
                });
            }
        }
    }
}

async fn handle_capture_request(
    req: Request<Incoming>,
    state: Arc<Mutex<CaptureState>>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("body read: {e}"))?
        .to_bytes()
        .to_vec();

    let (status, headers, body) = {
        let mut locked = state
            .lock()
            .map_err(|e| anyhow::anyhow!("capture lock poisoned: {e}"))?;
        locked.received.push(ReceivedRequest {
            method: method.clone(),
            path: path.clone(),
            body: body_bytes,
        });
        locked
            .mocks
            .iter()
            .find(|m| m.method.eq_ignore_ascii_case(&method) && m.path == path)
            .map_or_else(
                || (404_u16, Vec::new(), b"no mock registered".to_vec()),
                |m| (m.status, m.headers.clone(), m.body.clone()),
            )
    };

    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let response = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| anyhow::anyhow!("response build: {e}"))?;
    Ok(response)
}

// ── HttpCaptures ──────────────────────────────────────────────────────────────

/// HTTP requests captured by the mock server during a scenario phase.
pub struct HttpCaptures {
    pub(crate) requests: Vec<ReceivedRequest>,
}

impl HttpCaptures {
    /// All captured HTTP requests.
    #[must_use]
    pub fn all(&self) -> &[ReceivedRequest] {
        &self.requests
    }

    /// Captured requests whose path exactly matches `path`.
    #[must_use]
    pub fn for_path(&self, path: &str) -> Vec<&ReceivedRequest> {
        self.requests.iter().filter(|r| r.path == path).collect()
    }

    /// True when at least one request reached the mock server.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.requests.is_empty()
    }
}
