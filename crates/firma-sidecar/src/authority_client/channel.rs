//! Authority gRPC channel builder.

use std::time::Duration;

use anyhow::{Context as _, Result};
use hyper::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Build a lazily connecting tonic channel to the Authority.
///
/// * `ca_cert_pem` — PEM CA cert to verify the Authority's server TLS cert.
///   Required when `url` uses `https://`.
/// * `client_cert_pem` / `client_key_pem` — PEM client cert + key for mTLS.
///   Both must be `Some` or both `None`. Used when the Authority requires
///   client certificates (`mtls_client_ca_cert_path` is set on the Authority).
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed, TLS configuration is
/// invalid, or an `https://` URL is provided without a CA certificate.
pub fn build_channel(
    url: &str,
    connect_timeout: Duration,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Channel> {
    if client_cert_pem.is_some() != client_key_pem.is_some() {
        anyhow::bail!(
            "tls_client_cert_path and tls_client_key_path must both be set or both be unset"
        );
    }

    let parsed_uri: Uri = url
        .parse()
        .context("invalid Authority URL: failed to parse URI")?;
    let mut endpoint = Endpoint::from_shared(url.to_string())
        .context("invalid Authority URL")?
        .connect_timeout(connect_timeout)
        .keep_alive_timeout(Duration::from_secs(30))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .tcp_keepalive(Some(Duration::from_secs(60)));

    match parsed_uri.scheme_str() {
        Some("https") => {
            let pem = ca_cert_pem.context(
                "authority_url uses https:// but authority.ca_cert_path is not configured",
            )?;
            let ca_cert = Certificate::from_pem(pem);
            let mut tls = ClientTlsConfig::new().ca_certificate(ca_cert);

            // Attach mTLS client identity when both cert and key are provided.
            if let (Some(cert), Some(key)) = (client_cert_pem, client_key_pem) {
                let identity = Identity::from_pem(cert, key);
                tls = tls.identity(identity);
                tracing::debug!("mTLS client identity attached to Authority channel");
            }

            endpoint = endpoint
                .tls_config(tls)
                .context("invalid TLS configuration")?;
        }
        Some("http") => {}
        Some(other) => anyhow::bail!("unsupported authority_url scheme: {other}"),
        None => anyhow::bail!("authority_url must include a scheme"),
    }

    Ok(endpoint.connect_lazy())
}
