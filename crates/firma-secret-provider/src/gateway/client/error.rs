use std::io;

use crate::gateway::endpoint::GatewayEndpoint;

/// Whole-request failures from talking to the firma-run secret gateway,
/// returned by [`super::GatewayClient::resolve_batch`] and [`super::GatewayClient::push_secret`].
///
/// This is the *outer* failure mode: connection, framing, and transport
/// errors that abort the entire call. It is distinct from batch resolution
/// failure, which [`super::GatewayClient::resolve_batch`] instead reports in its inner
/// `Result<Vec<SecretString>, ResolveError>` — a single unknown placeholder still
/// fails the whole batch, but as a resolution error rather than a transport
/// or protocol one. See each function's `# Errors` section for the
/// fail-closed handling callers must apply.
///
/// Variants are grouped by what the caller should *do*, not by which
/// internal step failed:
///
/// - [`GatewayClientError::Transport`] — the round-trip to `endpoint` did not
///   complete (connect/read/write failure, a timeout, or the connection
///   closing without a response). Transient; safe to retry.
/// - [`GatewayClientError::ProtocolViolation`] — the gateway responded but
///   broke the wire contract. Not a caller bug, but retrying the same
///   request is unlikely to help.
/// - [`GatewayClientError::Rejected`] — the gateway understood the request
///   and explicitly refused it (e.g. a malformed placeholder). Retrying
///   without changing the input is pointless.
/// - [`GatewayClientError::Bug`] — encoding our own outbound request failed.
///   Should never happen given internally-constructed request data.
#[derive(Debug, thiserror::Error)]
pub enum GatewayClientError {
    /// The round-trip to the gateway did not complete. Retryable.
    #[error("secret gateway ({endpoint}): {source}")]
    Transport {
        endpoint: GatewayEndpoint,
        #[source]
        source: TransportError,
    },
    /// The gateway responded but violated the wire protocol. Not retryable
    /// without a code or protocol fix.
    #[error("secret gateway protocol violation: {0}")]
    ProtocolViolation(#[source] ProtocolViolation),
    /// The gateway explicitly rejected the request (via [`super::PushResponse::Err`]).
    /// Retrying with the same input is pointless.
    #[error("gateway rejected the request: {0}")]
    Rejected(String),
    /// Encoding our own outbound request as JSON failed. Should never happen
    /// given internally-constructed request data; indicates a bug.
    #[error("bug: failed to serialize gateway request: {0}")]
    Bug(#[source] serde_json::Error),
}

/// Round-trip failure to the gateway: connect, write, read, or timeout at
/// any stage. Grouped under [`GatewayClientError::Transport`] because a
/// caller handles all of them the same way (retry).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Connecting to the gateway timed out.
    #[error("connection timeout")]
    ConnectionTimeout,
    /// The request/response round-trip timed out after connecting.
    #[error("operation timeout")]
    OperationTimeout,
    /// Connecting to the gateway failed.
    #[error("connect failed: {0}")]
    Connect(#[source] io::Error),
    /// Writing the request line to the gateway socket failed.
    #[error("write failed: {0}")]
    Write(#[source] io::Error),
    /// Flushing the gateway socket after writing the request failed.
    #[error("flush failed: {0}")]
    Flush(#[source] io::Error),
    /// Reading the response line from the gateway socket failed.
    #[error("read failed: {0}")]
    Read(#[source] io::Error),
    /// The gateway closed the connection without writing a response line.
    #[error("connection closed without a response")]
    Empty,
}

/// The gateway responded, but the response broke the wire contract. Grouped
/// under [`GatewayClientError::ProtocolViolation`] because neither is a
/// caller bug, but neither is safe to blindly retry either.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolViolation {
    /// The gateway's response line did not decode as the expected response
    /// shape ([`Vec<PlaceholderResult>`] for [`super::GatewayClient::resolve_batch`],
    /// [`super::PushResponse`] for [`super::GatewayClient::push_secret`]).
    #[error("failed to decode gateway response: {0}")]
    Deserialize(#[source] serde_json::Error),
    /// [`super::GatewayClient::resolve_batch`]'s response array length did not match the number of
    /// placeholders sent, violating the positional-alignment contract of the
    /// wire protocol; the whole batch is treated as failed since results
    /// cannot be reliably matched to placeholders.
    #[error("gateway returned {results} results for {placeholders} placeholders")]
    Mismatch { results: usize, placeholders: usize },
    #[error("gateway max buffer size exceeded")]
    MaxBufferSizeExceeded,
}
