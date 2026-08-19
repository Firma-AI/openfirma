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
    /// Cap on the request line size from a shim, enforced before the line is
    /// fully buffered.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: ByteSize,
}

impl Default for BrokerListenerConfig {
    fn default() -> Self {
        Self {
            operation_timeout: default_operation_timeout(),
            max_request_bytes: default_max_request_bytes(),
        }
    }
}

fn default_operation_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_max_request_bytes() -> ByteSize {
    ByteSize::kib(64)
}
