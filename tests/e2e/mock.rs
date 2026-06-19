// ── Mock response builder ─────────────────────────────────────────────────────

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

// ── ReceivedRequest ───────────────────────────────────────────────────────────

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
