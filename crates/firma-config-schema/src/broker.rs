//! Schema for firma-run `[sidecar.secret_gateway]` client tuning.
//!
//! `firma-secret-provider`'s `GatewayClient` consumes these values directly.
//! Schema value types enforce their intrinsic invariants before the client sees
//! them.

use std::time::Duration;

use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

use crate::utils::NonZeroDuration;

const DEFAULT_CONNECTION_TIMEOUT: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(1));
const DEFAULT_OPERATION_TIMEOUT: NonZeroDuration =
    NonZeroDuration::from_static(Duration::from_secs(5));

/// Tunable timeouts and limits for firma-run shim broker, deserialized from
/// the shim's `firma.toml`.
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    /// Deadline for establishing the connection to the gateway endpoint.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: NonZeroDuration,
    /// Deadline for a single write-then-read round-trip once connected.
    #[serde(default = "default_operation_timeout")]
    pub operation_timeout: NonZeroDuration,
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
    #[must_use]
    pub fn max_request_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_request_size larger than usize::MAX.
        usize::try_from(self.max_request_size.as_u64()).unwrap_or(usize::MAX)
    }

    /// Byte size of the response-line cap, as a `usize` the reader can bound with.
    #[inline]
    #[must_use]
    pub fn max_response_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_response_size larger than usize::MAX.
        usize::try_from(self.max_response_size.as_u64()).unwrap_or(usize::MAX)
    }
}

fn default_connection_timeout() -> NonZeroDuration {
    DEFAULT_CONNECTION_TIMEOUT
}

fn default_operation_timeout() -> NonZeroDuration {
    DEFAULT_OPERATION_TIMEOUT
}

fn default_max_request_size() -> ByteSize {
    ByteSize::kib(64)
}

fn default_max_response_size() -> ByteSize {
    ByteSize::mb(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_uses_all_defaults() {
        let config: BrokerConfig = toml::from_str("").expect("empty table parses");
        assert_eq!(config.connection_timeout.duration(), Duration::from_secs(1));
        assert_eq!(config.operation_timeout.duration(), Duration::from_secs(5));
        assert_eq!(config.max_request_size, ByteSize::kib(64));
        assert_eq!(config.max_response_size, ByteSize::mb(10));
    }

    #[test]
    fn partial_table_defaults_missing_fields() {
        let config: BrokerConfig =
            toml::from_str("connection_timeout = \"5s\"").expect("partial table parses");
        assert_eq!(config.connection_timeout.duration(), Duration::from_secs(5));
        assert_eq!(config.operation_timeout.duration(), Duration::from_secs(5));
        assert_eq!(config.max_request_size, ByteSize::kib(64));
        assert_eq!(config.max_response_size, ByteSize::mb(10));
    }

    #[test]
    fn full_table_uses_every_given_value() {
        let config: BrokerConfig = toml::from_str(
            "connection_timeout = \"2s\"\noperation_timeout = \"3s\"\nmax_request_size = \"1MB\"\nmax_response_size = \"2MB\"",
        )
        .expect("full table parses");
        assert_eq!(config.connection_timeout.duration(), Duration::from_secs(2));
        assert_eq!(config.operation_timeout.duration(), Duration::from_secs(3));
        assert_eq!(config.max_request_size, ByteSize::mb(1));
        assert_eq!(config.max_response_size, ByteSize::mb(2));
    }
}
