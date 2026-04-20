//! Authority gRPC channel builder.

use std::time::Duration;

use tonic::transport::{Channel, Endpoint, Error};

/// Build a lazily connecting tonic channel to the Authority.
///
/// # Errors
///
/// Returns a tonic transport error if the URL cannot be parsed.
pub fn build_channel(url: &str, connect_timeout: Duration) -> Result<Channel, Error> {
    Ok(Endpoint::from_shared(url.to_string())?
        .connect_timeout(connect_timeout)
        .keep_alive_timeout(Duration::from_secs(30))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .connect_lazy())
}
