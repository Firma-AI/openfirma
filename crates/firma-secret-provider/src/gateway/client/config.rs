use std::time::Duration;

use bytesize::ByteSize;
use serde::Deserialize;

/// Tunable timeouts and limits for [`super::GatewayClient`], deserialized
/// from the Sidecar's `firma.toml`.
#[derive(Debug, Deserialize)]
pub struct GatewayClientConfig {
    /// Deadline for establishing the connection to the gateway endpoint.
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub connection_timeout: Duration,
    /// Deadline for a single write-then-read round-trip once connected.
    #[serde(with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required")]
    pub operation_timeout: Duration,
    /// Cap on the outbound payload and inbound response line size, enforced
    /// by [`super::GatewayClient`].
    pub max_buffer_size: ByteSize,
}

impl Default for GatewayClientConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_secs(1),
            max_buffer_size: ByteSize::mb(10),
        }
    }
}
