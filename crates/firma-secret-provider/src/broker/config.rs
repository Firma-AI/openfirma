use std::time::Duration;

use bytesize::ByteSize;
use serde::Deserialize;

/// Tunable timeouts and limits for [`super::client::BrokerClient`], deserialized from
/// the shim's `firma.toml`.
#[derive(Debug, Copy, Clone, Deserialize)]
pub struct BrokerConfig {
    /// Deadline for establishing the connection to the broker endpoint.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_connection_timeout"
    )]
    pub connection_timeout: Duration,
    /// Deadline for a single write-then-read round-trip once connected.
    ///
    /// The broker runs a real CLI tool out of the sandbox, whose latency is
    /// not fully under our control, so this is deliberately more generous
    /// than [`Self::connection_timeout`].
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_operation_timeout"
    )]
    pub operation_timeout: Duration,
    /// Cap on the outbound request line size, enforced before connecting.
    #[serde(default = "default_max_request_size")]
    pub max_request_size: ByteSize,
    /// Cap on the inbound response line size.
    ///
    /// Responses can include encoded process output, so this is deliberately
    /// larger than [`Self::max_request_size`].
    #[serde(default = "default_max_response_size")]
    pub max_response_size: ByteSize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            connection_timeout: default_connection_timeout(),
            operation_timeout: default_operation_timeout(),
            max_request_size: default_max_request_size(),
            max_response_size: default_max_response_size(),
        }
    }
}

impl BrokerConfig {
    /// Byte size of the request-line cap, as a `usize` the reader can bound with.
    #[inline]
    pub(crate) fn max_request_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_request_size larger than usize::MAX.
        usize::try_from(self.max_request_size.as_u64()).unwrap_or(usize::MAX)
    }

    /// Byte size of the response-line cap, as a `usize` the reader can bound with.
    #[inline]
    pub(crate) fn max_response_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_response_size larger than usize::MAX.
        usize::try_from(self.max_response_size.as_u64()).unwrap_or(usize::MAX)
    }
}

fn default_connection_timeout() -> Duration {
    Duration::from_secs(1)
}

fn default_operation_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_max_request_size() -> ByteSize {
    ByteSize::kib(64)
}

fn default_max_response_size() -> ByteSize {
    ByteSize::mb(10)
}
