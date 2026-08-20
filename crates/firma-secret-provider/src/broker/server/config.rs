use std::time::Duration;

use bytesize::ByteSize;
use serde::Deserialize;

/// Tunable timeouts and limits for [`super::BrokerListener`], deserialized from
/// firma-run's `firma.toml`.
#[derive(Debug, Copy, Clone, Deserialize)]
pub struct BrokerListenerConfig {
    /// Deadline for each read, write, or drain operation on an accepted
    /// connection.
    ///
    /// This does not bound handler execution. A handler that launches a
    /// subprocess must own its execution deadline, termination, and reaping.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_io_timeout"
    )]
    pub io_timeout: Duration,
    /// Cap on the inbound request line size.
    #[serde(default = "default_max_request_size")]
    pub max_request_size: ByteSize,
    /// Cap on the outbound response line size.
    ///
    /// Responses can include encoded process output, so this is deliberately
    /// larger than [`Self::max_request_size`].
    #[serde(default = "default_max_response_size")]
    pub max_response_size: ByteSize,
}

impl BrokerListenerConfig {
    /// Byte size of the request-line cap, as a `usize` the reader can bound with.
    pub(crate) fn max_request_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_request_size larger than usize::MAX.
        usize::try_from(self.max_request_size.as_u64()).unwrap_or(usize::MAX)
    }

    /// Byte size of the response-line cap.
    pub(crate) fn max_response_size(&self) -> usize {
        usize::try_from(self.max_response_size.as_u64()).unwrap_or(usize::MAX)
    }
}

impl Default for BrokerListenerConfig {
    fn default() -> Self {
        Self {
            io_timeout: default_io_timeout(),
            max_request_size: default_max_request_size(),
            max_response_size: default_max_response_size(),
        }
    }
}

fn default_io_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_max_request_size() -> ByteSize {
    ByteSize::kib(64)
}

fn default_max_response_size() -> ByteSize {
    ByteSize::mb(10)
}
