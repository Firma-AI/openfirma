use std::io;

use crate::endpoint::client::ClientEndpoint;

/// Whole-request failures from talking to the out-of-sandbox secret broker.
///
/// Returned by [`super::BrokerClient`]. Variants are grouped by what the
/// caller should *do*, not by which internal step failed:
///
/// - [`BrokerClientError::Transport`] — the round-trip to `endpoint` did not
///   complete (connect/read/write failure, a timeout, a peer-credential
///   mismatch, or the connection closing without a response). Transient;
///   safe to retry.
/// - [`BrokerClientError::ProtocolViolation`] — the broker responded but
///   broke the wire contract. Not a caller bug, but retrying the same
///   request is unlikely to help.
/// - [`BrokerClientError::Rejected`] — the broker understood the request and
///   explicitly refused it: the handler's config matching or authorization did
///   not allow the tool to run, or the tool ran and exited non-zero. Retrying
///   without changing the input is pointless.
/// - [`BrokerClientError::InvalidEndpoint`] — the endpoint fails an
///   address-level invariant (non-loopback TCP, relative Unix path). A
///   configuration error; not retryable.
/// - [`BrokerClientError::Bug`] — encoding our own outbound request failed.
///   Should never happen given internally-constructed request data.
#[derive(Debug, thiserror::Error)]
pub enum BrokerClientError {
    /// The round-trip to the broker did not complete. Retryable.
    #[error("secret broker ({endpoint}): {source}")]
    Transport {
        endpoint: ClientEndpoint,
        #[source]
        source: TransportError,
    },
    /// The broker responded but violated the wire protocol. Not retryable
    /// without a code or protocol fix.
    #[error("secret broker protocol violation: {0}")]
    ProtocolViolation(#[source] ProtocolViolation),
    /// The broker explicitly rejected the request (via [`super::super::BrokerResponse::Err`]).
    /// Retrying with the same input is pointless.
    #[error("secret broker rejected the request: {0}")]
    Rejected(String),
    /// The endpoint fails an address-level invariant. Configuration error.
    #[error("invalid secret broker endpoint: {0}")]
    InvalidEndpoint(String),
    /// Encoding our own outbound request as JSON failed. Should never happen
    /// given internally-constructed request data; indicates a bug.
    #[error("bug: failed to serialize broker request: {0}")]
    Bug(#[source] serde_json::Error),
}

/// Round-trip failure to the broker.
///
/// Covers connect, write, read, timeout, and peer-credential mismatch at any
/// stage. Grouped under [`BrokerClientError::Transport`] because a caller
/// handles all of them the same way (retry).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Connecting to the broker timed out.
    #[error("connection timed out")]
    ConnectionTimeout,
    /// The write-then-read round-trip exceeded the operation timeout.
    #[error("operation timed out")]
    OperationTimeout,
    /// Connecting to the broker failed.
    #[error("connect failed: {0}")]
    Connect(#[source] io::Error),
    /// Writing the request line to the broker socket failed.
    #[error("write failed: {0}")]
    Write(#[source] io::Error),
    /// Reading the response line from the broker socket failed.
    #[error("read failed: {0}")]
    Read(#[source] io::Error),
    /// The broker closed the connection without writing a response line.
    #[error("broker closed the connection without a response")]
    Empty,
    /// The broker's Unix peer did not match the expected user id.
    #[cfg(unix)]
    #[error("broker unix peer uid mismatch: expected {expected_uid}, got {actual_uid}")]
    PeerUidMismatch { expected_uid: u32, actual_uid: u32 },
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
    /// A success response carried a stdout payload that is not valid base64.
    #[error("broker returned invalid base64: {0}")]
    Base64(#[source] base64::DecodeError),
    /// The response line is not valid UTF-8.
    #[error("broker response is not valid UTF-8: {0}")]
    InvalidUtf8(#[source] std::string::FromUtf8Error),
    /// The request or response line exceeded [`super::config::BrokerClientConfig::max_buffer_size`].
    #[error("broker max buffer size exceeded")]
    MaxBufferSizeExceeded,
}
