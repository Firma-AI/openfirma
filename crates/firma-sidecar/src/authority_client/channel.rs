//! Authority gRPC channel builder shared by the sidecar and `firma run`.

use std::time::Duration;

use firma_config_utils::NonZeroDuration;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use crate::authority_tls::{TlsTrust, client_tls_config};
use crate::config::AuthorityEndpoint;

/// Error building the Authority channel.
#[derive(Debug, thiserror::Error)]
pub enum BuildChannelError {
    /// The validated URI could not be represented as a tonic endpoint.
    #[error("invalid Authority URL: {0}")]
    InvalidUrl(String),
    /// TLS configuration was rejected by tonic, for instance because no trusted
    /// roots could be loaded.
    #[error("invalid TLS configuration")]
    Tls(#[source] tonic::transport::Error),
}

/// Build a lazily connecting tonic channel to the Authority.
///
/// * `trust` — what the Authority's server TLS cert is verified against when
///   `url` uses `https://`: the configured CAs alone, or the platform's
///   trusted roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` override them).
/// * `client_identity` — PEM client cert and key for mTLS.
///
/// # Errors
///
/// Returns [`BuildChannelError`] when tonic rejects the validated origin, or
/// TLS config is bad (including an `https://` origin with no CA cert on a host
/// with no trusted roots).
pub fn build_channel(
    authority: &AuthorityEndpoint,
    connect_timeout: NonZeroDuration,
    trust: TlsTrust<'_>,
    client_identity: Option<(&[u8], &[u8])>,
) -> Result<Channel, BuildChannelError> {
    let mut endpoint = Endpoint::from_shared(authority.origin().to_string())
        .map_err(|e| BuildChannelError::InvalidUrl(e.to_string()))?
        .connect_timeout(connect_timeout.duration())
        .keep_alive_timeout(Duration::from_secs(30))
        .http2_keep_alive_interval(Duration::from_secs(30));

    if authority.is_https() {
        endpoint = endpoint
            .tls_config(client_tls_config(trust, client_identity))
            .map_err(BuildChannelError::Tls)?;
    }

    Ok(if let Some(connect_addr) = authority.connect_addr() {
        // Endpoint TCP options configure tonic's internal HTTP connector, not
        // caller-provided streams. Tokio exposes TCP_NODELAY portably, so set
        // it explicitly; retaining OS keepalive parity would require adding a
        // socket-level dependency solely for this advanced override.
        endpoint.connect_with_connector_lazy(service_fn(move |_| async move {
            let stream = TcpStream::connect(connect_addr).await?;
            stream.set_nodelay(true)?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }))
    } else {
        endpoint
            .tcp_keepalive(Some(Duration::from_mins(1)))
            .connect_lazy()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_url_builds() {
        let endpoint =
            AuthorityEndpoint::new("http://127.0.0.1:50051", None).expect("valid test endpoint");
        let ch = build_channel(
            &endpoint,
            NonZeroDuration::from_static(Duration::from_secs(5)),
            TlsTrust::PlatformStore,
            None,
        );
        assert!(ch.is_ok());
    }
}
