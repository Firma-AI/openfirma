//! Client for the firma-run secret resolution gateway.
//!
//! When the Sidecar MITM pipeline processes an outbound request body containing
//! placeholder tokens, it calls [`GatewayClient::resolve_batch`] with all tokens at once to
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
//! Parse it with [`GatewayEndpoint::parse`] and pass it to [`GatewayClient::resolve_batch`].

use std::collections::HashSet;

use firma_http::{Authority, Str};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net,
    time::timeout,
};

use crate::{
    ExposeSecret, GatewayRequest, PlaceholderResult, PushRequest, PushResponse, ResolveRequest,
    SecretPlaceholder, SecretString,
    gateway::{
        client::{
            config::GatewayClientConfig,
            error::{GatewayClientError, ProtocolViolation, TransportError},
        },
        endpoint::{GatewayEndpoint, GatewayEndpointInner},
    },
};

pub mod config;
pub mod error;

/// Environment variable the Sidecar reads to locate the firma-run secret
/// gateway (`unix:<path>` or `tcp:<host>:<port>` format).
pub const GATEWAY_ADDR_ENV: &str = "FIRMA_SECRET_GATEWAY_ADDR";

/// Client for the firma-run secret resolution gateway, bound to one [`GatewayEndpoint`].
///
/// Opens a fresh connection per call rather than pooling, since gateway
/// calls are infrequent relative to request traffic.
#[derive(Debug)]
pub struct GatewayClient {
    endpoint: GatewayEndpoint,
    config: GatewayClientConfig,
}

impl GatewayClient {
    #[must_use]
    pub fn new(endpoint: GatewayEndpoint, config: GatewayClientConfig) -> Self {
        Self { endpoint, config }
    }

    /// Resolve a batch of placeholder tokens to their raw secret bytes via the
    /// firma-run secret gateway.
    ///
    /// All tokens are sent in a single request; the wire response is a
    /// positionally-aligned array of per-token results, but resolution here is
    /// all-or-nothing: the first unresolved placeholder fails the whole batch.
    /// `domain` is the target host of the outbound request; secrets stored for
    /// a different domain will not resolve.
    ///
    /// The outer `Result` represents a connection or protocol failure that affects
    /// the entire batch. The inner `Result` represents whether every placeholder in
    /// the batch was known to firma-run for this domain; one unknown placeholder
    /// fails the whole batch, not just that placeholder.
    ///
    /// # Errors
    ///
    /// The outer error is returned when the gateway is unreachable or the response
    /// cannot be decoded. The inner error is returned when any placeholder in the
    /// batch is unknown or scoped to a different domain, which fails the whole
    /// batch. Treat both error variants as fail-closed for the whole batch: do not
    /// substitute any literal token into the request body, and deny the outbound
    /// request instead.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn resolve_batch(
        &self,
        placeholders: &[SecretPlaceholder],
        domain: Authority,
    ) -> Result<Result<Vec<SecretString>, ResolveError>, GatewayClientError> {
        use base64::Engine as _;

        if placeholders.is_empty() {
            return Ok(Ok(Vec::new()));
        }

        let request = GatewayRequest::Resolve(ResolveRequest {
            placeholders: placeholders
                .iter()
                .map(ToString::to_string)
                .map(Str::from)
                .collect(),
            domain,
        });
        let payload = serde_json::to_string(&request).map_err(GatewayClientError::Bug)?;

        let response_line = match self.endpoint.as_inner() {
            GatewayEndpointInner::Tcp(addr) => {
                let stream = timeout(
                    self.config.connection_timeout,
                    net::TcpStream::connect(addr),
                )
                .await
                .map_err(|_| self.transport_error(TransportError::ConnectionTimeout))?
                .map_err(|error| self.transport_error(TransportError::Connect(error)))?;
                self.send_and_receive(stream, &payload).await?
            }
            #[cfg(unix)]
            GatewayEndpointInner::Unix(path) => {
                let stream = timeout(
                    self.config.connection_timeout,
                    net::UnixStream::connect(path),
                )
                .await
                .map_err(|_| self.transport_error(TransportError::ConnectionTimeout))?
                .map_err(|error| self.transport_error(TransportError::Connect(error)))?;
                self.send_and_receive(stream, &payload).await?
            }
        };

        let results =
            serde_json::from_str::<Vec<PlaceholderResult>>(&response_line).map_err(|error| {
                GatewayClientError::ProtocolViolation(ProtocolViolation::Deserialize(error))
            })?;

        if results.len() != placeholders.len() {
            return Err(GatewayClientError::ProtocolViolation(
                ProtocolViolation::Mismatch {
                    results: results.len(),
                    placeholders: placeholders.len(),
                },
            ));
        }

        Ok(results
            .into_iter()
            .map(|r| match r {
                PlaceholderResult::Ok { secret_b64 } => {
                    let buffer = base64::engine::general_purpose::STANDARD
                        .decode(&*secret_b64)
                        .map_err(ResolveError::Base64)?;
                    String::from_utf8(buffer)
                        .map(SecretString::from)
                        .map_err(|_| ResolveError::Utf8)
                }
                PlaceholderResult::Err { error } => Err(ResolveError::Gateway(error.to_string())),
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
    /// [`GatewayClient::resolve_batch`] for the write direction: extraction happens in the
    /// Sidecar (via `firma_secret_provider::CompiledMatcher`), but firma-run's
    /// broker remains the single owner of the secret dictionary, so the
    /// extracted value is pushed there rather than cached locally.
    ///
    /// `domain` scopes the pushed secret to that request hosts, mirroring a CLI
    /// intercept's `domain_selector`-derived scope; an empty set means it's
    /// unscoped (resolves for any request host) — the common case for HTTP
    /// vaults, whose response carries a credential meant for later use against
    /// some other downstream host, not the vault itself.
    ///
    /// # Errors
    ///
    /// Returns an error string if the gateway is unreachable, the response
    /// cannot be decoded, or the gateway rejects the push (e.g. malformed
    /// placeholder). Callers should treat any error as fail-closed: do not
    /// substitute the placeholder into the response the agent sees.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn push_secret(
        &self,
        placeholder: SecretPlaceholder,
        value: SecretString,
        domain: HashSet<Authority>,
    ) -> Result<SecretPlaceholder, GatewayClientError> {
        use base64::Engine as _;

        let request = GatewayRequest::Push(PushRequest {
            placeholder: Str::from(placeholder.to_string()),
            value_b64: Str::from(
                base64::engine::general_purpose::STANDARD.encode(value.expose_secret()),
            ),
            domain,
        });
        let payload = serde_json::to_string(&request).map_err(GatewayClientError::Bug)?;

        let response_line = match self.endpoint.as_inner() {
            GatewayEndpointInner::Tcp(addr) => {
                let stream = timeout(
                    self.config.connection_timeout,
                    net::TcpStream::connect(addr),
                )
                .await
                .map_err(|_| self.transport_error(TransportError::ConnectionTimeout))?
                .map_err(|error| self.transport_error(TransportError::Connect(error)))?;
                self.send_and_receive(stream, &payload).await?
            }
            #[cfg(unix)]
            GatewayEndpointInner::Unix(path) => {
                let stream = timeout(
                    self.config.connection_timeout,
                    net::UnixStream::connect(path),
                )
                .await
                .map_err(|_| self.transport_error(TransportError::ConnectionTimeout))?
                .map_err(|error| self.transport_error(TransportError::Connect(error)))?;
                self.send_and_receive(stream, &payload).await?
            }
        };

        match serde_json::from_str::<PushResponse>(&response_line) {
            Ok(PushResponse::Ok {
                placeholder: returned,
            }) if returned == placeholder => Ok(returned),
            Ok(PushResponse::Ok {
                placeholder: returned,
            }) => Err(GatewayClientError::ProtocolViolation(
                ProtocolViolation::PushPlaceholderMismatch {
                    expected: placeholder.clone(),
                    actual: returned,
                },
            )),
            Ok(PushResponse::Err { error }) => Err(GatewayClientError::Rejected(error.to_string())),
            Err(error) => Err(GatewayClientError::ProtocolViolation(
                ProtocolViolation::Deserialize(error),
            )),
        }
    }

    /// Wrap a [`TransportError`] with this client's endpoint.
    fn transport_error(&self, source: TransportError) -> GatewayClientError {
        GatewayClientError::Transport {
            endpoint: self.endpoint.clone(),
            source,
        }
    }

    async fn send_and_receive<S>(
        &self,
        stream: S,
        payload: &str,
    ) -> Result<String, GatewayClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(self.config.operation_timeout, async {
            let mut stream = stream;
            stream
                .write_all(payload.as_bytes())
                .await
                .map_err(|error| self.transport_error(TransportError::Write(error)))?;
            stream
                .write_all(b"\n")
                .await
                .map_err(|error| self.transport_error(TransportError::Write(error)))?;
            stream
                .flush()
                .await
                .map_err(|error| self.transport_error(TransportError::Flush(error)))?;

            let reader = BufReader::new(stream);
            // Cap the underlying reads at max_buffer_size + 1 so a response line
            // without a trailing newline cannot grow `line` without bound; the
            // `+ 1` lets an over-limit line still trip the length check below
            // instead of being silently truncated to exactly the limit.
            let mut limited = reader.take(self.config.max_buffer_size.as_u64().saturating_add(1));
            let mut line = String::new();
            limited
                .read_line(&mut line)
                .await
                .map_err(|error| self.transport_error(TransportError::Read(error)))?;

            if line.len() > self.max_buffer_size() {
                return Err(GatewayClientError::ProtocolViolation(
                    ProtocolViolation::MaxBufferSizeExceeded,
                ));
            }

            let trimmed = line.trim().to_owned();
            if trimmed.is_empty() {
                return Err(self.transport_error(TransportError::Empty));
            }
            Ok(trimmed)
        })
        .await
        .map_err(|_| self.transport_error(TransportError::OperationTimeout))?
    }

    #[inline]
    fn max_buffer_size(&self) -> usize {
        // the only way this conversion can fail is that we're running on a 32bit system
        // and we're using a max_buffer_size > u32::MAX (or, even worse, on a 16bit system)
        usize::try_from(self.config.max_buffer_size.as_u64()).unwrap_or(usize::MAX)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("gateway returned invalid base64: {0}")]
    Base64(#[source] base64::DecodeError),
    #[error("gateway returned invalid utf8")]
    Utf8,
    #[error("gateway error: {0}")]
    Gateway(String),
}
