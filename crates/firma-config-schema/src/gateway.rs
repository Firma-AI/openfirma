//! Schema for the sidecar's `[sidecar.secret_gateway]` client tuning.
//!
//! Representation only. `firma-secret-provider`'s `GatewayClient` consumes
//! these values directly; the type carries no behavior of its own.

use std::time::Duration;

use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

/// Tunable timeouts and limits for the secret-gateway client, deserialized
/// from the Sidecar's `firma.toml`.
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayClientConfig {
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
    /// Cap on the outbound payload and inbound response line size.
    #[serde(
        deserialize_with = "crate::utils::byte_size::deserialize",
        default = "default_max_buffer_size"
    )]
    pub max_buffer_size: ByteSize,
}

impl Default for GatewayClientConfig {
    fn default() -> Self {
        Self {
            connection_timeout: default_connection_timeout(),
            operation_timeout: default_operation_timeout(),
            max_buffer_size: default_max_buffer_size(),
        }
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
        let config: GatewayClientConfig = toml::from_str("").expect("empty table parses");
        assert_eq!(config.connection_timeout, Duration::from_secs(1));
        assert_eq!(config.operation_timeout, Duration::from_secs(1));
        assert_eq!(config.max_buffer_size, ByteSize::mb(10));
    }

    #[test]
    fn partial_table_defaults_missing_fields() {
        let config: GatewayClientConfig =
            toml::from_str("connection_timeout = \"5s\"").expect("partial table parses");
        assert_eq!(config.connection_timeout, Duration::from_secs(5));
        assert_eq!(config.operation_timeout, Duration::from_secs(1));
        assert_eq!(config.max_buffer_size, ByteSize::mb(10));
    }

    #[test]
    fn full_table_uses_every_given_value() {
        let config: GatewayClientConfig = toml::from_str(
            "connection_timeout = \"2s\"\noperation_timeout = \"3s\"\nmax_buffer_size = \"1MB\"",
        )
        .expect("full table parses");
        assert_eq!(config.connection_timeout, Duration::from_secs(2));
        assert_eq!(config.operation_timeout, Duration::from_secs(3));
        assert_eq!(config.max_buffer_size, ByteSize::mb(1));
    }
}
