use std::time::Duration;

use bytesize::ByteSize;
use serde::Deserialize;

/// Tunable timeouts and limits for [`super::client::GatewayClient`], deserialized
/// from the Sidecar's `firma.toml`.
#[derive(Debug, Copy, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Deadline for establishing the connection to the gateway endpoint.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_connection_timeout"
    )]
    pub connection_timeout: Duration,
    /// Deadline for a single write-then-read round-trip once connected.
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::required",
        default = "default_operation_timeout"
    )]
    pub operation_timeout: Duration,
    /// Cap on the outbound payload and inbound response line size, enforced
    /// by [`super::client::GatewayClient`].
    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: ByteSize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            connection_timeout: default_connection_timeout(),
            operation_timeout: default_operation_timeout(),
            max_buffer_size: default_max_buffer_size(),
        }
    }
}

impl GatewayConfig {
    /// Byte size of the request-line cap, as a `usize` the reader can bound with.
    #[inline]
    pub(crate) fn max_buffer_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_buffer_size larger than usize::MAX.
        usize::try_from(self.max_buffer_size.as_u64()).unwrap_or(usize::MAX)
    }
}

fn default_connection_timeout() -> Duration {
    Duration::from_secs(1)
}

fn default_operation_timeout() -> Duration {
    Duration::from_secs(1)
}

fn default_max_buffer_size() -> ByteSize {
    ByteSize::mb(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_uses_all_defaults() {
        let config: GatewayConfig = toml::from_str("").expect("empty table parses");
        assert_eq!(config.connection_timeout, Duration::from_secs(1));
        assert_eq!(config.operation_timeout, Duration::from_secs(1));
        assert_eq!(config.max_buffer_size, ByteSize::mb(10));
    }

    #[test]
    fn partial_table_defaults_missing_fields() {
        let config: GatewayConfig =
            toml::from_str("connection_timeout = \"5s\"").expect("partial table parses");
        assert_eq!(config.connection_timeout, Duration::from_secs(5));
        assert_eq!(config.operation_timeout, Duration::from_secs(1));
        assert_eq!(config.max_buffer_size, ByteSize::mb(10));
    }

    #[test]
    fn full_table_uses_every_given_value() {
        let config: GatewayConfig = toml::from_str(
            "connection_timeout = \"2s\"\noperation_timeout = \"3s\"\nmax_buffer_size = \"1MB\"",
        )
        .expect("full table parses");
        assert_eq!(config.connection_timeout, Duration::from_secs(2));
        assert_eq!(config.operation_timeout, Duration::from_secs(3));
        assert_eq!(config.max_buffer_size, ByteSize::mb(1));
    }
}
