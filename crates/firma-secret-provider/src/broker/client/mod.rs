//! Client for the out-of-sandbox secret broker.
//!
//! The shim binary runs inside the sandbox and uses [`BrokerClient`] to ask
//! the broker (running out of the sandbox, inside firma-run) to run the real
//! CLI tool and return its stdout. Whether the tool is authorized to run is
//! decided downstream by the broker's handler (config matching and
//! authorization), which reports a refused or failed launch back as an error.
//! [`BrokerClient`] opens a fresh connection per call rather than pooling,
//! since broker calls are infrequent relative to tool launches, and applies
//! the timeouts and buffer limits from [`BrokerClientConfig`] to every
//! operation.
//!
//! All operations are fail-closed: any connect, timeout, protocol, or
//! rejected error means the wrapped tool produced no usable output, and the
//! caller must treat the invocation as failed rather than substituting a
//! partial or synthetic result.

use firma_http::Str;

use crate::{
    broker::{
        BinaryName, BrokerOutput, BrokerRequest, BrokerResponse, DecodedBrokerResponse,
        read_bounded_line, stream::BrokerStream, write_all,
    },
    endpoint::{EndpointInner, client::ClientEndpoint},
};

pub mod config;
pub mod error;

use config::BrokerClientConfig;
#[cfg(unix)]
use error::PeerAuthenticationError;
use error::{BrokerClientError, OutcomeUnknownError, ProtocolViolation, UnavailableError};

/// Client for the out-of-sandbox secret broker, bound to one
/// [`ClientEndpoint`].
///
/// Construction validates address-level invariants; transport-level checks
/// (Unix socket presence, peer credentials) run at connect time.
#[derive(Debug)]
pub struct BrokerClient {
    endpoint: ClientEndpoint,
    config: BrokerClientConfig,
}

impl BrokerClient {
    /// Build a client for `endpoint`
    #[must_use]
    pub fn new(endpoint: ClientEndpoint, config: BrokerClientConfig) -> Self {
        Self { endpoint, config }
    }

    /// Run one wrapped tool via the broker and return its output and status.
    ///
    /// The broker's handler applies config matching and authorization before
    /// executing the tool, so a request the handler refuses fails closed here.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerClientError::Rejected`] when the broker's handler
    /// refused the request or failed to launch the tool,
    /// [`BrokerClientError::Unavailable`] when no request reached the broker,
    /// [`BrokerClientError::OutcomeUnknown`] when execution may have occurred
    /// without a valid response,
    /// and [`BrokerClientError::ProtocolViolation`] when the response broke
    /// the wire contract. All errors are fail-closed from the caller's
    /// perspective: no usable output is returned, though an
    /// [`BrokerClientError::OutcomeUnknown`] means the tool may have executed.
    pub async fn run(&self, bin: &str, args: &[&str]) -> Result<BrokerOutput, BrokerClientError> {
        let request = BrokerRequest {
            bin: BinaryName::new(bin)?,
            args: args.iter().map(Str::from).collect(),
        };
        self.request(&request, |response| match response.decode() {
            Ok(DecodedBrokerResponse::Executed(output)) => Ok(output),
            Ok(DecodedBrokerResponse::Rejected(error)) => Err(BrokerClientError::Rejected(error)),
            Err(error) => Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::Output(error),
            )),
        })
        .await
    }

    /// Send one request and read the broker's response.
    ///
    /// # Errors
    ///
    /// See [`Self::run`].
    pub async fn request<T>(
        &self,
        request: &BrokerRequest<'_>,
        exec: impl Fn(BrokerResponse<'_>) -> Result<T, BrokerClientError>,
    ) -> Result<T, BrokerClientError> {
        let payload = serde_json::to_string(request).map_err(BrokerClientError::Bug)?;
        if payload.len() > self.max_buffer_size() {
            return Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::MaxBufferSizeExceeded,
            ));
        }
        let stream = self.connect().await?;
        self.send_and_receive(stream, &payload, exec).await
    }

    async fn connect(&self) -> Result<BrokerStream, BrokerClientError> {
        let timeout = self.config.connection_timeout;
        let stream: BrokerStream = match self.endpoint.as_inner() {
            EndpointInner::Tcp(addr) => {
                let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
                    .await
                    .map_err(|_| self.unavailable(UnavailableError::ConnectionTimeout))?
                    .map_err(|error| self.unavailable(UnavailableError::Connect(error)))?;
                BrokerStream::Tcp { stream }
            }
            #[cfg(unix)]
            EndpointInner::Unix(path) => {
                let stream = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path))
                    .await
                    .map_err(|_| self.unavailable(UnavailableError::ConnectionTimeout))?
                    .map_err(|error| self.unavailable(UnavailableError::Connect(error)))?;
                validate_broker_peer_credentials(&stream, &self.endpoint)?;
                BrokerStream::Unix { stream }
            }
        };
        Ok(stream)
    }

    async fn send_and_receive<T>(
        &self,
        mut stream: BrokerStream,
        payload: &str,
        exec: impl Fn(BrokerResponse<'_>) -> Result<T, BrokerClientError>,
    ) -> Result<T, BrokerClientError> {
        // The whole write-then-read exchange runs under one deadline, so a
        // peer that stalls mid-exchange cannot hold the connection past
        // `operation_timeout`.
        let line = tokio::time::timeout(self.config.operation_timeout, async {
            write_all(&mut stream, payload.as_bytes())
                .await
                .map_err(|error| self.outcome_unknown(OutcomeUnknownError::Write(error)))?;
            write_all(&mut stream, b"\n")
                .await
                .map_err(|error| self.outcome_unknown(OutcomeUnknownError::Write(error)))?;

            // Cap the underlying reads at max_buffer_size + 1 (see
            // [`read_bounded_line`]) and reject any response whose newline-stripped
            // line exceeds the limit. Padding an over-limit response with boundary
            // whitespace must not let it pass, so the check measures the raw line,
            // not the trimmed content.
            read_bounded_line(&mut stream, self.max_buffer_size() as u64)
                .await
                .map_err(|error| self.outcome_unknown(OutcomeUnknownError::Read(error)))
        })
        .await
        .map_err(|_| self.outcome_unknown(OutcomeUnknownError::OperationTimeout))??;

        // Size-check the raw line before UTF-8 decoding so an over-limit
        // response that truncates mid-character is reported as an oversized
        // payload rather than a decode failure.
        if line.len() > self.max_buffer_size() {
            return Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::MaxBufferSizeExceeded,
            ));
        }
        let line = String::from_utf8(line).map_err(|error| {
            BrokerClientError::ProtocolViolation(ProtocolViolation::InvalidUtf8(error))
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(self.outcome_unknown(OutcomeUnknownError::Empty));
        }
        exec(serde_json::from_str(trimmed).map_err(|error| {
            BrokerClientError::ProtocolViolation(ProtocolViolation::Deserialize(error))
        })?)
    }

    /// Wrap a pre-dispatch failure with this client's endpoint.
    fn unavailable(&self, source: UnavailableError) -> BrokerClientError {
        BrokerClientError::Unavailable {
            endpoint: self.endpoint.clone(),
            source,
        }
    }

    /// Wrap an indeterminate post-connect failure with this client's endpoint.
    fn outcome_unknown(&self, source: OutcomeUnknownError) -> BrokerClientError {
        BrokerClientError::OutcomeUnknown {
            endpoint: self.endpoint.clone(),
            source,
        }
    }

    #[inline]
    fn max_buffer_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_buffer_size larger than usize::MAX.
        usize::try_from(self.config.max_buffer_size.as_u64()).unwrap_or(usize::MAX)
    }
}

/// Confirm the broker socket's peer belongs to the current user.
///
/// The broker returns secret material, so the client must not talk to a
/// socket planted by a different user. Matches the same-uid check the local
/// exec mediator applies on its side of the same boundary.
#[cfg(unix)]
fn validate_broker_peer_credentials(
    stream: &tokio::net::UnixStream,
    endpoint: &ClientEndpoint,
) -> Result<(), BrokerClientError> {
    let actual_uid =
        super::peer_uid(stream).map_err(|error| BrokerClientError::PeerAuthentication {
            endpoint: endpoint.clone(),
            source: PeerAuthenticationError::Credential(error),
        })?;
    let expected_uid = super::current_uid();
    if actual_uid != expected_uid {
        return Err(BrokerClientError::PeerAuthentication {
            endpoint: endpoint.clone(),
            source: PeerAuthenticationError::UidMismatch {
                expected_uid,
                actual_uid,
            },
        });
    }
    Ok(())
}
