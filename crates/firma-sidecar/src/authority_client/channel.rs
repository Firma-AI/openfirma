//! Authority gRPC channel builder shared by the sidecar and `firma run`.

use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Error building the Authority channel.
#[derive(Debug, thiserror::Error)]
pub enum BuildChannelError {
    /// The URL could not be parsed as a tonic endpoint.
    #[error("invalid Authority URL: {0}")]
    InvalidUrl(String),
    /// An `https://` URL was given without a CA certificate.
    #[error("authority_url uses https:// but no CA certificate was provided")]
    MissingCaCert,
    /// Exactly one of client cert / client key was provided.
    #[error("tls_client_cert and tls_client_key must both be set or both unset")]
    PartialClientIdentity,
    /// The URL scheme is neither http nor https.
    #[error("unsupported authority_url scheme: {0}")]
    UnsupportedScheme(String),
    /// The URL had no scheme.
    #[error("authority_url must include a scheme")]
    MissingScheme,
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
/// Returns [`BuildChannelError`] when the URL/scheme is invalid, an `https://`
/// URL has no CA cert, the client identity is partial, or TLS config is bad.
pub fn build_channel(
    url: &str,
    connect_timeout: Duration,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Channel, BuildChannelError> {
    if client_cert_pem.is_some() != client_key_pem.is_some() {
        return Err(BuildChannelError::PartialClientIdentity);
    }

    let scheme = url
        .split_once("://")
        .map(|(s, _)| s.to_string())
        .ok_or(BuildChannelError::MissingScheme)?;

    let mut endpoint = Endpoint::from_shared(url.to_string())
        .map_err(|e| BuildChannelError::InvalidUrl(e.to_string()))?
        .connect_timeout(connect_timeout)
        .keep_alive_timeout(Duration::from_secs(30))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .tcp_keepalive(Some(Duration::from_mins(1)));

    match scheme.as_str() {
        "https" => {
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
        "http" => {}
        other => return Err(BuildChannelError::UnsupportedScheme(other.to_string())),
    }

    Ok(endpoint.connect_lazy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_url_builds() {
        let ch = build_channel(
            "http://127.0.0.1:50051",
            Duration::from_secs(5),
            None,
            None,
            None,
        );
        assert!(ch.is_ok());
    }

    #[test]
    fn https_without_ca_fails() {
        let err = build_channel(
            "https://authority.example:9443",
            Duration::from_secs(5),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, BuildChannelError::MissingCaCert));
    }

    #[test]
    fn partial_client_identity_fails() {
        let err = build_channel(
            "http://x:1",
            Duration::from_secs(5),
            None,
            Some(b"cert"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, BuildChannelError::PartialClientIdentity));
    }

    #[test]
    fn missing_scheme_fails() {
        let err =
            build_channel("127.0.0.1:50051", Duration::from_secs(5), None, None, None).unwrap_err();
        assert!(matches!(err, BuildChannelError::MissingScheme));
    }
}
