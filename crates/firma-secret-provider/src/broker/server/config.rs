use std::time::Duration;

use bytesize::ByteSize;
use serde::Deserialize;

/// Tunable timeouts and limits for [`super::BrokerListener`], deserialized from
/// firma-run's `firma.toml`.
#[derive(Debug, Copy, Clone, Deserialize)]
pub struct BrokerListenerConfig {
    /// Deadline for reading one request line and writing the response on an
    /// accepted connection.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_operation_timeout"
    )]
    pub operation_timeout: Duration,
    /// Cap on the inbound request line and outbound response line size,
    /// enforced by [`super::BrokerListener`].
    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: ByteSize,
}

impl BrokerListenerConfig {
    /// Byte size of the request-line cap, as a `usize` the reader can bound with.
    pub(crate) fn max_buffer_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_buffer_size larger than usize::MAX.
        usize::try_from(self.max_buffer_size.as_u64()).unwrap_or(usize::MAX)
    }
}

impl Default for BrokerListenerConfig {
    fn default() -> Self {
        Self {
            operation_timeout: default_operation_timeout(),
            max_buffer_size: default_max_buffer_size(),
        }
    }
}

fn default_operation_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_max_buffer_size() -> ByteSize {
    ByteSize::mb(10)
}
