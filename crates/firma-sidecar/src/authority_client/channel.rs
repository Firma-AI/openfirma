//! Authority gRPC channel builder.

use std::time::Duration;

use anyhow::{Context as _, Result};
use hyper::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

/// Build a lazily connecting tonic channel to the Authority.
///
/// `ca_cert_pem` must be set when `url` uses `https://`. The bytes are the
/// PEM-encoded CA certificate used to verify the Authority's TLS certificate.
/// `http://` URLs use plain gRPC (loopback / local dev only).
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed, TLS configuration is invalid,
/// or an `https://` URL is provided without a CA certificate.
pub fn build_channel(
    url: &str,
    connect_timeout: Duration,
    ca_cert_pem: Option<&[u8]>,
) -> Result<Channel> {
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
            let tls = ClientTlsConfig::new().ca_certificate(ca_cert);
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
