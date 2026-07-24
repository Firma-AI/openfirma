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

use std::net::SocketAddr;

use firma_http::Str;
use firma_secret_provider::{
    GatewayRequest, PlaceholderResult, PushRequest, PushResponse, ResolveRequest,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

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
) -> Result<Vec<Result<Vec<u8>, String>>, String>
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
    let payload = serde_json::to_string(&request)
        .map_err(|e| format!("failed to serialize gateway request: {e}"))?;

    let response_line = match endpoint {
        GatewayEndpoint::Tcp(addr) => {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("secret gateway unreachable (tcp:{addr}): {e}"))?;
            send_and_receive(stream, &payload).await?
        }
        #[cfg(unix)]
        GatewayEndpoint::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| {
                format!("secret gateway unreachable (unix:{}): {e}", path.display())
            })?;
            send_and_receive(stream, &payload).await?
        }
    };

    let results = serde_json::from_str::<Vec<PlaceholderResult>>(&response_line)
        .map_err(|e| format!("failed to decode gateway response: {e}"))?;

    if results.len() != placeholders_len {
        return Err(format!(
            "gateway returned {} results for {placeholders_len} placeholders",
            results.len()
        ));
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
    domain: &str,
) -> Result<String, String> {
    use base64::Engine as _;

    let request = GatewayRequest::Push(PushRequest {
        placeholder: Str::from(placeholder),
        value_b64: Str::from(base64::engine::general_purpose::STANDARD.encode(value)),
        domain: Str::from(domain),
    });
    let payload = serde_json::to_string(&request)
        .map_err(|e| format!("failed to serialize gateway push request: {e}"))?;

    let response_line = match endpoint {
        GatewayEndpoint::Tcp(addr) => {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("secret gateway unreachable (tcp:{addr}): {e}"))?;
            send_and_receive(stream, &payload).await?
        }
        #[cfg(unix)]
        GatewayEndpoint::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| {
                format!("secret gateway unreachable (unix:{}): {e}", path.display())
            })?;
            send_and_receive(stream, &payload).await?
        }
    };

    match serde_json::from_str::<PushResponse>(&response_line) {
        Ok(PushResponse::Ok { placeholder }) => Ok(placeholder.to_string()),
        Ok(PushResponse::Err { error }) => Err(format!("gateway error: {error}")),
        Err(e) => Err(format!("failed to decode gateway push response: {e}")),
    }
}

async fn send_and_receive<S>(stream: S, payload: &str) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = stream;
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("gateway write failed: {e}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| format!("gateway write failed: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("gateway flush failed: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("gateway read failed: {e}"))?;

    let trimmed = line.trim().to_owned();
    if trimmed.is_empty() {
        return Err("gateway returned an empty response".to_owned());
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
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
}
