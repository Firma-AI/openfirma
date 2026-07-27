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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_uses_all_defaults() {
        let config: BrokerListenerConfig = toml::from_str("").expect("empty table parses");
        assert_eq!(config.operation_timeout, Duration::from_secs(5));
        assert_eq!(config.max_request_bytes, ByteSize::kib(64));
    }

    #[test]
    fn partial_table_defaults_missing_fields() {
        let config: BrokerListenerConfig =
            toml::from_str("operation_timeout = \"2s\"").expect("partial table parses");
        assert_eq!(config.operation_timeout, Duration::from_secs(2));
        assert_eq!(config.max_request_bytes, ByteSize::kib(64));
    }

    #[test]
    fn full_table_uses_every_given_value() {
        let config: BrokerListenerConfig =
            toml::from_str("operation_timeout = \"3s\"\nmax_request_bytes = \"1MB\"")
                .expect("full table parses");
        assert_eq!(config.operation_timeout, Duration::from_secs(3));
        assert_eq!(config.max_request_bytes, ByteSize::mb(1));
    }
}
