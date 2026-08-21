use std::time::Duration;

use bytesize::ByteSize;
use firma_secret_provider::broker::client::config::BrokerClientConfig;

#[test]
fn empty_table_uses_all_defaults() {
    let config: BrokerClientConfig = toml::from_str("").expect("empty table parses");
    assert_eq!(config.connection_timeout, Duration::from_secs(1));
    assert_eq!(config.operation_timeout, Duration::from_secs(5));
    assert_eq!(config.max_request_size, ByteSize::kib(64));
    assert_eq!(config.max_response_size, ByteSize::mb(10));
}

#[test]
fn partial_table_defaults_missing_fields() {
    let config: BrokerClientConfig =
        toml::from_str("operation_timeout = \"2s\"").expect("partial table parses");
    assert_eq!(config.connection_timeout, Duration::from_secs(1));
    assert_eq!(config.operation_timeout, Duration::from_secs(2));
    assert_eq!(config.max_request_size, ByteSize::kib(64));
    assert_eq!(config.max_response_size, ByteSize::mb(10));
}

#[test]
fn full_table_uses_every_given_value() {
    let config: BrokerClientConfig = toml::from_str(
        "connection_timeout = \"2s\"\noperation_timeout = \"3s\"\nmax_request_size = \"1MB\"\nmax_response_size = \"2MB\"",
    )
    .expect("full table parses");
    assert_eq!(config.connection_timeout, Duration::from_secs(2));
    assert_eq!(config.operation_timeout, Duration::from_secs(3));
    assert_eq!(config.max_request_size, ByteSize::mb(1));
    assert_eq!(config.max_response_size, ByteSize::mb(2));
}
