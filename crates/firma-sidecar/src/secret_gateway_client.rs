//! Client for the firma-run secret resolution gateway.
//!
//! When the Sidecar MITM pipeline processes an outbound request body containing
//! placeholder tokens, it calls [`resolve`] for each token to obtain the raw
//! secret bytes from firma-run. firma-run remains the single source of truth;
//! the Sidecar never caches secrets across requests.
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
//! Parse it with [`GatewayEndpoint::parse`] and pass it to [`resolve`].

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
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
            return Err(format!(
                "unix gateway address '{s}' is not supported on this platform"
            ));
        }

        Err(format!(
            "unrecognized gateway address '{s}'; expected 'tcp:<host>:<port>' or 'unix:<path>'"
        ))
    }
}

#[derive(Serialize)]
struct ResolveRequest<'a> {
    placeholder: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ResolveResponse {
    Ok { secret_b64: String },
    Err { error: String },
}

/// Resolve one placeholder token to its raw secret bytes via the firma-run
/// secret gateway.
///
/// `domain` is the target host of the outbound request. It is forwarded to
/// firma-run for future domain-based access control; pass `None` to omit.
///
/// # Errors
///
/// Returns an error string when the gateway is unreachable, returns an error
/// response, or the response cannot be decoded. Treat errors as fail-closed:
/// do not forward the request with unresolved placeholders.
pub async fn resolve(
    endpoint: &GatewayEndpoint,
    placeholder: &str,
    domain: Option<&str>,
) -> Result<Vec<u8>, String> {
    use base64::Engine as _;

    let request = ResolveRequest {
        placeholder,
        domain,
    };
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

    match serde_json::from_str::<ResolveResponse>(&response_line)
        .map_err(|e| format!("failed to decode gateway response: {e}"))?
    {
        ResolveResponse::Ok { secret_b64 } => base64::engine::general_purpose::STANDARD
            .decode(&secret_b64)
            .map_err(|e| format!("gateway returned invalid base64: {e}")),
        ResolveResponse::Err { error } => Err(format!("gateway error: {error}")),
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
