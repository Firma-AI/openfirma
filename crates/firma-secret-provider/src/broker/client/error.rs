use std::io;

use crate::{
    broker::{BinaryNameError, BrokerResponseDecodeError},
    endpoint::client::ClientEndpoint,
};

/// Whole-request failures from talking to the out-of-sandbox secret broker.
///
/// Returned by [`super::BrokerClient`]. Variants are grouped by what the
/// caller should *do*, not by which internal step failed:
///
/// - [`BrokerClientError::Unavailable`] — no request reached the broker, so a
///   retry cannot duplicate tool execution.
/// - [`BrokerClientError::OutcomeUnknown`] — the request may have reached the
///   broker and executed, but no valid response arrived. Retrying can duplicate
///   execution and requires caller-level idempotency or deduplication.
/// - `PeerAuthentication` — the connected Unix peer could
///   not be authenticated as the current user. Not retryable without fixing
///   the endpoint or its ownership.
/// - [`BrokerClientError::ProtocolViolation`] — the broker responded but
///   broke the wire contract. Not a caller bug, but retrying the same
///   request is unlikely to help.
/// - [`BrokerClientError::Rejected`] — the broker understood the request and
///   explicitly refused it: the handler's config matching or authorization did
///   not allow the tool to run, or the tool could not be launched. Retrying
///   without changing the input is unlikely to help.
/// - [`BrokerClientError::InvalidEndpoint`] — the endpoint fails an
///   address-level invariant (non-loopback TCP, relative Unix path). A
///   configuration error; not retryable.
/// - [`BrokerClientError::InvalidBinaryName`] and
///   [`BrokerClientError::RequestTooLarge`] — the request cannot be sent as
///   configured. Caller or configuration errors; not retryable unchanged.
/// - [`BrokerClientError::Bug`] — encoding our own outbound request failed.
///   Should never happen given internally-constructed request data.
#[derive(Debug, thiserror::Error)]
pub enum BrokerClientError {
    /// The broker could not be reached, and the request was not dispatched.
    #[error("secret broker unavailable ({endpoint}): {source}")]
    Unavailable {
        endpoint: ClientEndpoint,
        #[source]
        source: UnavailableError,
    },
    /// The request may have executed, but no valid response arrived.
    #[error("secret broker outcome unknown ({endpoint}): {source}")]
    OutcomeUnknown {
        endpoint: ClientEndpoint,
        #[source]
        source: OutcomeUnknownError,
    },
    /// The connected Unix peer failed same-user authentication.
    #[cfg(unix)]
    #[error("secret broker peer authentication failed ({endpoint}): {source}")]
    PeerAuthentication {
        endpoint: ClientEndpoint,
        #[source]
        source: PeerAuthenticationError,
    },
    /// The broker responded but violated the wire protocol. Not retryable
    /// without a code or protocol fix.
    #[error("secret broker protocol violation: {0}")]
    ProtocolViolation(#[source] ProtocolViolation),
    /// The broker explicitly rejected the request (via
    /// [`super::super::BrokerResponse::Rejected`]).
    /// Retrying with the same input is pointless.
    #[error("secret broker rejected the request: {0}")]
    Rejected(String),
    /// The endpoint fails an address-level invariant. Configuration error.
    #[error("invalid secret broker endpoint: {0}")]
    InvalidEndpoint(String),
    /// The executable is not a portable basename.
    #[error("invalid secret broker binary: {0}")]
    InvalidBinaryName(#[from] BinaryNameError),
    /// The encoded request exceeds the configured outbound limit.
    #[error("secret broker request is {size} bytes, exceeding the {max} byte limit")]
    RequestTooLarge { size: usize, max: usize },
    /// Encoding our own outbound request as JSON failed. Should never happen
    /// given internally-constructed request data; indicates a bug.
    #[error("bug: failed to serialize broker request: {0}")]
    Bug(#[source] serde_json::Error),
}

/// A pre-dispatch connection failure. Retrying cannot duplicate execution.
#[derive(Debug, thiserror::Error)]
pub enum UnavailableError {
    /// Connecting to the broker timed out.
    #[error("connection timed out")]
    ConnectionTimeout,
    /// Connecting to the broker failed.
    #[error("connect failed: {0}")]
    Connect(#[source] io::Error),
}

/// A post-connect failure for which tool execution may already have occurred.
#[derive(Debug, thiserror::Error)]
pub enum OutcomeUnknownError {
    /// The write-then-read round-trip exceeded the operation timeout.
    #[error("operation timed out")]
    OperationTimeout,
    /// Writing the request line failed, possibly after a complete request
    /// reached the broker.
    #[error("write failed: {0}")]
    Write(#[source] io::Error),
    /// Reading the response failed after the request was dispatched.
    #[error("read failed: {0}")]
    Read(#[source] io::Error),
    /// The broker closed the connection without a response after dispatch.
    #[error("broker closed the connection without a response")]
    Empty,
    /// The broker closed the response without its newline frame delimiter.
    #[error("broker response is not newline-terminated")]
    UnterminatedResponse,
}

/// Unix peer-authentication failures.
#[cfg(unix)]
#[derive(Debug, thiserror::Error)]
pub enum PeerAuthenticationError {
    /// Reading the broker's peer credentials failed.
    #[error("failed to read broker peer credentials: {0}")]
    Credential(#[source] io::Error),
    /// The broker's Unix peer did not match the expected user id.
    #[error("broker unix peer uid mismatch: expected {expected_uid}, got {actual_uid}")]
    UidMismatch { expected_uid: u32, actual_uid: u32 },
}

/// The broker responded, but the response broke the wire contract.
///
/// Grouped under [`BrokerClientError::ProtocolViolation`] because neither is
/// a caller bug, but neither is safe to blindly retry either.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolViolation {
    /// The broker's response line did not decode as the expected response
    /// shape ([`super::super::BrokerResponse`]).
    #[error("failed to decode broker response: {0}")]
    Deserialize(#[source] serde_json::Error),
    /// An execution response carried malformed process output.
    #[error("failed to decode broker process output: {0}")]
    Output(#[source] BrokerResponseDecodeError),
    /// The response line is not valid UTF-8.
    #[error("broker response is not valid UTF-8: {0}")]
    InvalidUtf8(#[source] std::string::FromUtf8Error),
    /// The response line exceeded
    /// [`super::super::config::BrokerConfig::max_response_size`].
    #[error("broker response exceeds the configured size limit")]
    ResponseTooLarge,
}
