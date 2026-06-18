//! Authority gRPC channel builder (delegates to `firma_proto::client`).

use std::time::Duration;

use anyhow::Result;
use tonic::transport::Channel;

/// Build a lazily connecting tonic channel to the Authority.
///
/// # Errors
///
/// See [`firma_proto::client::build_channel`].
pub fn build_channel(
    url: &str,
    connect_timeout: Duration,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Channel> {
    firma_proto::client::build_channel(
        url,
        connect_timeout,
        ca_cert_pem,
        client_cert_pem,
        client_key_pem,
    )
    .map_err(anyhow::Error::from)
}
