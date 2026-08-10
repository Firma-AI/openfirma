//! Authority gRPC channel builder shared by the sidecar and `firma run`.

use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tower::service_fn;

use crate::config::AuthorityEndpoint;

/// Error building the Authority channel.
#[derive(Debug, thiserror::Error)]
pub enum BuildChannelError {
    /// The validated URI could not be represented as a tonic endpoint.
    #[error("invalid Authority URL: {0}")]
    InvalidUrl(String),
    /// An `https://` URL was given without a CA certificate.
    #[error("authority_url uses https:// but no CA certificate was provided")]
    MissingCaCert,
    /// Exactly one of client cert / client key was provided.
    #[error("tls_client_cert and tls_client_key must both be set or both unset")]
    PartialClientIdentity,
    /// TLS configuration was rejected by tonic.
    #[error("invalid TLS configuration: {0}")]
    Tls(String),
}

/// Build a lazily connecting tonic channel to the Authority.
///
/// * `ca_cert_pem` — PEM CA cert to verify the Authority's server TLS cert;
///   required when `url` uses `https://`.
/// * `client_cert_pem` / `client_key_pem` — PEM client cert + key for mTLS;
///   both `Some` or both `None`.
///
/// # Errors
///
/// Returns [`BuildChannelError`] when tonic rejects the validated origin, an
/// `https://` origin has no CA cert, the client identity is partial, or TLS
/// config is bad.
pub fn build_channel(
    authority: &AuthorityEndpoint,
    connect_timeout: Duration,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Channel, BuildChannelError> {
    if client_cert_pem.is_some() != client_key_pem.is_some() {
        return Err(BuildChannelError::PartialClientIdentity);
    }

    let mut endpoint = Endpoint::from_shared(authority.origin().to_string())
        .map_err(|e| BuildChannelError::InvalidUrl(e.to_string()))?
        .connect_timeout(connect_timeout)
        .keep_alive_timeout(Duration::from_secs(30))
        .http2_keep_alive_interval(Duration::from_secs(30));

    if authority.is_https() {
        let pem = ca_cert_pem.ok_or(BuildChannelError::MissingCaCert)?;
        let ca_cert = Certificate::from_pem(pem);
        let mut tls = ClientTlsConfig::new().ca_certificate(ca_cert);
        if let (Some(cert), Some(key)) = (client_cert_pem, client_key_pem) {
            tls = tls.identity(Identity::from_pem(cert, key));
        }
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| BuildChannelError::Tls(e.to_string()))?;
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
        let ch = build_channel(&endpoint, Duration::from_secs(5), None, None, None);
        assert!(ch.is_ok());
    }

    #[test]
    fn https_without_ca_fails() {
        let endpoint = AuthorityEndpoint::new("https://authority.example:9443", None)
            .expect("valid test endpoint");
        let err = build_channel(&endpoint, Duration::from_secs(5), None, None, None).unwrap_err();
        assert!(matches!(err, BuildChannelError::MissingCaCert));
    }

    #[test]
    fn partial_client_identity_fails() {
        let endpoint = AuthorityEndpoint::new("http://x:1", None).expect("valid test endpoint");
        let err = build_channel(&endpoint, Duration::from_secs(5), None, Some(b"cert"), None)
            .unwrap_err();
        assert!(matches!(err, BuildChannelError::PartialClientIdentity));
    }
}
