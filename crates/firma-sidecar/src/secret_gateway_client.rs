//! Client for the firma-run secret resolution gateway.
//!
//! When the Sidecar MITM pipeline processes an outbound request body containing
//! placeholder tokens, it calls [`resolve_batch`] with all tokens at once to
//! obtain the raw secret bytes from firma-run in a single round-trip. firma-run
//! remains the single source of truth; the Sidecar never caches secrets across
//! requests.
//!
//! The gateway address is advertised via the [`GATEWAY_ADDR_ENV`] environment
//! variable, set by the orchestrator after firma-run binds the socket. The
//! address uses a `unix:<path>` or `tcp:<host>:<port>` scheme (no `//`):
//!
//! ```text
//! unix:/run/firma/secret-shims/gateway.sock   (Linux/macOS)
//! tcp:127.0.0.1:51234                          (Windows)
//! ```
//!
//! Parse it with [`GatewayEndpoint::parse`] and pass it to [`resolve_batch`].

use std::{fmt::Display, net::SocketAddr};

use firma_http::Str;
use firma_secret_provider::{
    GatewayRequest, PlaceholderResult, PushRequest, PushResponse, ResolveRequest,
};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net,
};

/// Environment variable the Sidecar reads to locate the firma-run secret
/// gateway (`unix:<path>` or `tcp:<host>:<port>` format).
pub const GATEWAY_ADDR_ENV: &str = "FIRMA_SECRET_GATEWAY_ADDR";

/// Transport address for the firma-run secret resolution gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEndpoint {
    /// TCP loopback socket (Windows, and any platform when configured).
    Tcp(SocketAddr),
    /// Unix domain socket (Linux/macOS).
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl GatewayEndpoint {
    /// Parse a `unix:<path>` or `tcp:<host>:<port>` address string.
    ///
    /// # Errors
    ///
    /// Returns an error string if the scheme is unrecognized, the TCP address
    /// is malformed, or a `unix:` address is used on a non-Unix platform.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(addr_str) = s.strip_prefix("tcp:") {
            let addr = addr_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("invalid TCP gateway address '{addr_str}': {e}"))?;
            return Ok(Self::Tcp(addr));
        }

        if let Some(path_str) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(Self::Unix(std::path::PathBuf::from(path_str)));

            #[cfg(not(unix))]
            {
                let _ = path_str;
                return Err(format!(
                    "unix gateway address '{s}' is not supported on this platform"
                ));
            }
        }

        Err(format!(
            "unrecognized gateway address '{s}'; expected 'tcp:<host>:<port>' or 'unix:<path>'"
        ))
    }
}

impl Display for GatewayEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp:{addr}"),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayClientError {
    #[error("failed to serialize gateway request: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("failed to decode gateway response: {0}")]
    Deserialize(#[source] serde_json::Error),
    #[error("failed to serialize gateway push request: {0}")]
    PushSerialize(#[source] serde_json::Error),
    #[error("failed to decode gateway push response: {0}")]
    PushDeserialize(#[source] serde_json::Error),
    #[error("secret gateway unreachable ({endpoint}): {error}")]
    Unreachable {
        endpoint: GatewayEndpoint,
        #[source]
        error: io::Error,
    },
    #[error("gateway returned {results} results for {placeholders} placeholders")]
    Mismatch { results: usize, placeholders: usize },
    #[error("gateway error: {0}")]
    GatewayError(String),
    #[error("gateway write failed: {0}")]
    Write(#[source] io::Error),
    #[error("gateway flush failed: {0}")]
    Flush(#[source] io::Error),
    #[error("gateway read failed: {0}")]
    Read(#[source] io::Error),
    #[error("gateway returned an empty response")]
    Empty,
}

/// Resolve a batch of placeholder tokens to their raw secret bytes via the
/// firma-run secret gateway.
///
/// All tokens are sent in a single request; the response is a positionally-
/// aligned array of per-token results. `domain` is the target host of the
/// outbound request; secrets stored for a different domain will not resolve.
///
/// The outer `Result` represents a connection or protocol failure that affects
/// the entire batch. The inner `Result` per position represents whether that
/// specific placeholder was known to firma-run for this domain.
///
/// # Errors
///
/// The outer error is returned when the gateway is unreachable or the response
/// cannot be decoded. The inner per-token error is returned when a placeholder
/// is unknown or scoped to a different domain. Treat both error variants as
/// fail-open for that placeholder (leave the literal token in the request body).
pub async fn resolve_batch<'a, I, S>(
    endpoint: &GatewayEndpoint,
    placeholders: I,
    domain: &str,
) -> Result<Vec<Result<Vec<u8>, String>>, GatewayClientError>
where
    I: IntoIterator<Item = S> + 'a,
    Str<'a>: From<S>,
{
    use base64::Engine as _;

    let placeholders = placeholders.into_iter().map(Str::from).collect::<Vec<_>>();
    if placeholders.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders_len = placeholders.len();

    let request = GatewayRequest::Resolve(ResolveRequest {
        placeholders,
        domain: domain.into(),
    });
    let payload = serde_json::to_string(&request).map_err(GatewayClientError::Serialize)?;

    let response_line = match endpoint {
        GatewayEndpoint::Tcp(addr) => {
            let stream = net::TcpStream::connect(addr).await.map_err(|error| {
                GatewayClientError::Unreachable {
                    endpoint: endpoint.clone(),
                    error,
                }
            })?;
            send_and_receive(stream, &payload).await?
        }
        #[cfg(unix)]
        GatewayEndpoint::Unix(path) => {
            let stream = net::UnixStream::connect(path).await.map_err(|error| {
                GatewayClientError::Unreachable {
                    endpoint: endpoint.clone(),
                    error,
                }
            })?;
            send_and_receive(stream, &payload).await?
        }
    };

    let results = serde_json::from_str::<Vec<PlaceholderResult>>(&response_line)
        .map_err(GatewayClientError::Deserialize)?;

    if results.len() != placeholders_len {
        return Err(GatewayClientError::Mismatch {
            results: results.len(),
            placeholders: placeholders_len,
        });
    }

    Ok(results
        .into_iter()
        .map(|r| match r {
            PlaceholderResult::Ok { secret_b64 } => base64::engine::general_purpose::STANDARD
                .decode(&*secret_b64)
                .map_err(|e| format!("gateway returned invalid base64: {e}")),
            PlaceholderResult::Err { error } => Err(format!("gateway error: {error}")),
        })
        .collect())
}

/// Push a secret newly extracted from an intercepted HTTP vault response.
///
/// `placeholder` must already be minted by the caller (via
/// `firma_secret_provider::mint_placeholder`, from the same
/// `placeholder_template` firma-run resolved and mirrored into the Sidecar's
/// config) — the Sidecar mints locally so it can substitute the placeholder
/// synchronously into the response body during extraction, and the gateway
/// stores it as-is rather than re-deriving it, so the stored key can never
/// diverge from what the agent actually sees. The counterpart of
/// [`resolve_batch`] for the write direction: extraction happens in the
/// Sidecar (via `firma_secret_provider::CompiledMatcher`), but firma-run's
/// broker remains the single owner of the secret dictionary, so the
/// extracted value is pushed there rather than cached locally.
///
/// `domain` scopes the pushed secret to that request host, mirroring a CLI
/// intercept's `domain_path`-derived scope; pass `None` to store it unscoped
/// (resolves for any request host) — the common case for HTTP vaults, whose
/// response carries a credential meant for later use against some other
/// downstream host, not the vault itself.
///
/// # Errors
///
/// Returns an error string if the gateway is unreachable, the response
/// cannot be decoded, or the gateway rejects the push (e.g. malformed
/// placeholder). Callers should treat any error as fail-closed: do not
/// substitute the placeholder into the response the agent sees.
pub async fn push_secret(
    endpoint: &GatewayEndpoint,
    placeholder: &str,
    value: &[u8],
    domain: Option<&str>,
) -> Result<String, GatewayClientError> {
    use base64::Engine as _;

    let request = GatewayRequest::Push(PushRequest {
        placeholder: Str::from(placeholder),
        value_b64: Str::from(base64::engine::general_purpose::STANDARD.encode(value)),
        domain: domain.map(Str::from),
    });
    let payload = serde_json::to_string(&request).map_err(GatewayClientError::PushSerialize)?;

    let response_line = match endpoint {
        GatewayEndpoint::Tcp(addr) => {
            let stream = net::TcpStream::connect(addr).await.map_err(|error| {
                GatewayClientError::Unreachable {
                    endpoint: endpoint.clone(),
                    error,
                }
            })?;
            send_and_receive(stream, &payload).await?
        }
        #[cfg(unix)]
        GatewayEndpoint::Unix(path) => {
            let stream = net::UnixStream::connect(path).await.map_err(|error| {
                GatewayClientError::Unreachable {
                    endpoint: endpoint.clone(),
                    error,
                }
            })?;
            send_and_receive(stream, &payload).await?
        }
    };

    match serde_json::from_str::<PushResponse>(&response_line) {
        Ok(PushResponse::Ok { placeholder }) => Ok(placeholder.to_string()),
        Ok(PushResponse::Err { error }) => Err(GatewayClientError::GatewayError(error.to_string())),
        Err(e) => Err(GatewayClientError::PushDeserialize(e)),
    }
}

async fn send_and_receive<S>(stream: S, payload: &str) -> Result<String, GatewayClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = stream;
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(GatewayClientError::Write)?;
    stream
        .write_all(b"\n")
        .await
        .map_err(GatewayClientError::Write)?;
    stream.flush().await.map_err(GatewayClientError::Flush)?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(GatewayClientError::Read)?;

    let trimmed = line.trim().to_owned();
    if trimmed.is_empty() {
        return Err(GatewayClientError::Empty);
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use firma_secret_provider::SecretPlaceholder;
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn parse_tcp_address() {
        let ep = GatewayEndpoint::parse("tcp:127.0.0.1:1234").expect("parse");
        assert_eq!(ep, GatewayEndpoint::Tcp("127.0.0.1:1234".parse().unwrap()));
    }

    #[test]
    fn parse_rejects_invalid_tcp_addr() {
        let err = GatewayEndpoint::parse("tcp:not-an-addr").expect_err("invalid");
        assert!(err.contains("invalid TCP gateway address"));
    }

    #[test]
    fn parse_rejects_unknown_scheme() {
        let err = GatewayEndpoint::parse("vsock://3:1234").expect_err("unknown scheme");
        assert!(err.contains("unrecognized gateway address"));
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_path() {
        let ep = GatewayEndpoint::parse("unix:/run/firma/gateway.sock").expect("parse");
        assert_eq!(
            ep,
            GatewayEndpoint::Unix(std::path::PathBuf::from("/run/firma/gateway.sock"))
        );
    }

    /// Binds an ephemeral TCP listener that accepts a single connection,
    /// reads its request line, and (if `response` is non-empty) writes back
    /// `response` followed by a newline before closing. An empty `response`
    /// closes the connection without writing anything, to exercise the
    /// empty-response error path.
    async fn mock_gateway(response: &str) -> GatewayEndpoint {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("local addr");
        let response = response.to_owned();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                let _ = reader.read_line(&mut line).await;
                if !response.is_empty() {
                    let _ = writer.write_all(response.as_bytes()).await;
                    let _ = writer.write_all(b"\n").await;
                }
                let _ = writer.shutdown().await;
            }
        });
        GatewayEndpoint::Tcp(addr)
    }

    /// Binds an ephemeral TCP listener and immediately drops it, yielding an
    /// address nothing is listening on, to exercise the connect-failure path.
    async fn unreachable_endpoint() -> GatewayEndpoint {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        GatewayEndpoint::Tcp(addr)
    }

    #[tokio::test]
    async fn resolve_batch_returns_empty_without_io_for_empty_placeholders() {
        // Deliberately unreachable: an empty batch must short-circuit before
        // any connection is attempted.
        let endpoint = unreachable_endpoint().await;
        let result = resolve_batch(&endpoint, Vec::<String>::new(), "example.com")
            .await
            .expect("empty batch needs no io");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn resolve_batch_maps_per_placeholder_results() {
        let endpoint = mock_gateway(
            r#"[{"secret_b64":"aGVsbG8="},{"secret_b64":"not-base64!!"},{"error":"unknown placeholder"}]"#,
        )
        .await;

        let results = resolve_batch(
            &endpoint,
            vec!["ph-ok", "ph-bad-base64", "ph-unknown"],
            "example.com",
        )
        .await
        .expect("outer call succeeds");

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_deref(), Ok(b"hello".as_slice()));
        assert!(
            results[1]
                .as_ref()
                .is_err_and(|e| e.contains("invalid base64"))
        );
        assert_eq!(
            results[2].as_deref().unwrap_err(),
            "gateway error: unknown placeholder"
        );
    }

    #[tokio::test]
    async fn resolve_batch_rejects_mismatched_result_count() {
        let endpoint = mock_gateway(r#"[{"secret_b64":"aGVsbG8="}]"#).await;

        let err = resolve_batch(&endpoint, vec!["ph-a", "ph-b"], "example.com")
            .await
            .expect_err("count mismatch");
        std::assert_matches!(err, GatewayClientError::Mismatch { results, placeholders } if results == 1 && placeholders == 2);
    }

    #[tokio::test]
    async fn resolve_batch_rejects_malformed_response() {
        let endpoint = mock_gateway("not json").await;

        let err = resolve_batch(&endpoint, vec!["ph-a"], "example.com")
            .await
            .expect_err("malformed response");
        std::assert_matches!(err, GatewayClientError::Deserialize(_));
    }

    #[tokio::test]
    async fn resolve_batch_reports_empty_response_line() {
        let endpoint = mock_gateway("").await;

        let err = resolve_batch(&endpoint, vec!["ph-a"], "example.com")
            .await
            .expect_err("empty response");
        std::assert_matches!(err, GatewayClientError::Empty);
    }

    #[tokio::test]
    async fn resolve_batch_reports_unreachable_gateway() {
        let endpoint = unreachable_endpoint().await;

        let err = resolve_batch(&endpoint, vec!["ph-a"], "example.com")
            .await
            .expect_err("unreachable");
        std::assert_matches!(err, GatewayClientError::Unreachable { .. });
    }

    #[tokio::test]
    async fn push_secret_returns_placeholder_on_success() {
        let placeholder = SecretPlaceholder::new().to_string();
        let endpoint = mock_gateway(&format!(r#"{{"placeholder":"{placeholder}"}}"#)).await;

        let returned = push_secret(&endpoint, &placeholder, b"s3cr3t", None)
            .await
            .expect("push succeeds");
        assert_eq!(returned, placeholder);
    }

    #[tokio::test]
    async fn push_secret_reports_gateway_rejection() {
        let placeholder = SecretPlaceholder::new().to_string();
        let endpoint = mock_gateway(r#"{"error":"malformed placeholder"}"#).await;

        let err = push_secret(&endpoint, &placeholder, b"s3cr3t", None)
            .await
            .expect_err("rejected");
        std::assert_matches!(err, GatewayClientError::GatewayError(err) if err == "malformed placeholder");
    }

    #[tokio::test]
    async fn push_secret_rejects_malformed_response() {
        let placeholder = SecretPlaceholder::new().to_string();
        let endpoint = mock_gateway("not json").await;

        let err = push_secret(&endpoint, &placeholder, b"s3cr3t", None)
            .await
            .expect_err("malformed response");
        std::assert_matches!(err, GatewayClientError::PushDeserialize(_));
    }

    #[tokio::test]
    async fn push_secret_reports_unreachable_gateway() {
        let placeholder = SecretPlaceholder::new().to_string();
        let endpoint = unreachable_endpoint().await;

        let err = push_secret(&endpoint, &placeholder, b"s3cr3t", None)
            .await
            .expect_err("unreachable");
        std::assert_matches!(err, GatewayClientError::Unreachable { .. });
    }
}
