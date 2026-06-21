use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use firma_core::token::paseto::PasetoV4Signer;
use firma_protobuf::v1::authority_service_server::AuthorityServiceServer;
use tonic::transport::{Identity, Server as TonicServer, ServerTlsConfig};
use tonic_health::server::HealthReporter;

use crate::authorized_clients::AuthorizedClientSet;
use crate::cedar_loader::CedarPolicyStore;
use crate::config::AuthorityConfig;
use crate::revocation::RevocationStore;
use crate::service::AuthorityServiceImpl;
use crate::tls_verifier::AllowListClientVerifier;

type ServerFuture = Pin<Box<dyn Future<Output = Result<(), tonic::transport::Error>> + Send>>;

/// The Mini Authority Server.
///
/// Can be instantiated with port 0 to bind to a random available port,
/// which is useful for integration testing without race conditions.
pub struct Server {
    port: u16,
    listen_addr: SocketAddr,
    policy_dir: std::path::PathBuf,
    configured_listen_addr: String,
    policy_count: usize,
    health_reporter: HealthReporter,
    future: ServerFuture,
}

impl Server {
    /// Create a new Server instance from the provided configuration.
    ///
    /// This will bind to the configured address immediately, allowing the
    /// caller to retrieve the actual port (useful if port 0 was requested).
    ///
    /// # Errors
    ///
    /// Returns an error if the policy store cannot be loaded, the
    /// TCP listener cannot bind to the configured address, or the file watcher
    /// cannot be initialised.
    pub async fn try_new<F>(config: AuthorityConfig, shutdown_signal: F) -> Result<Self>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tracing::info!(
            listen_addr = %config.listen_addr,
            policy_dir = %config.policy_dir.display(),
            "firma-authority starting"
        );
        tracing::warn!(
            "NOT FOR PRODUCTION USE: This is the Mini Authority (Firma OSS v1) intended for local development and testing only."
        );

        validate_tls_config(&config)?;

        let authority_service = load_authority_service(&config)?;
        let (listener, port) = bind_listener(&config.listen_addr).await?;
        let local_addr = listener
            .local_addr()
            .context("failed to get local address")?;
        let policy_count = std::fs::read_dir(&config.policy_dir).map_or(0, |rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "cedar"))
                .count()
        });
        let (health_reporter, health_service) = tonic_health::server::health_reporter();

        let future = build_server_future(
            &config,
            authority_service,
            health_service,
            listener,
            shutdown_signal,
        )
        .await?;

        Ok(Self {
            port,
            listen_addr: local_addr,
            policy_dir: config.policy_dir.clone(),
            configured_listen_addr: config.listen_addr.clone(),
            policy_count,
            health_reporter,
            future,
        })
    }

    /// Run the server until the provided shutdown signal is received.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying gRPC transport fails.
    pub async fn run(self) -> Result<()> {
        self.health_reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        crate::startup::log_ready_sequence(&crate::startup::StartupReport {
            policy_dir: &self.policy_dir,
            configured_listen_addr: &self.configured_listen_addr,
            policy_count: self.policy_count,
            effective_listen_addr: self.listen_addr.to_string(),
        });
        self.future.await.context("gRPC transport server failed")
    }

    /// Get the port the server is bound to.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

fn validate_tls_config(config: &AuthorityConfig) -> Result<()> {
    if config.tls.tls_cert_path.is_some() != config.tls.tls_key_path.is_some() {
        anyhow::bail!("tls_cert_path and tls_key_path must both be set or both be unset");
    }
    if config.tls.mtls_client_ca_cert_path.is_some() != config.tls.authorized_clients_path.is_some()
    {
        anyhow::bail!(
            "mtls_client_ca_cert_path and authorized_clients_path must both be set or both be unset"
        );
    }
    if config.tls.mtls_client_ca_cert_path.is_some()
        && (config.tls.tls_cert_path.is_none() || config.tls.tls_key_path.is_none())
    {
        anyhow::bail!(
            "mTLS (mtls_client_ca_cert_path) requires tls_cert_path and tls_key_path to also be configured"
        );
    }
    Ok(())
}

fn load_authority_service(config: &AuthorityConfig) -> Result<AuthorityServiceImpl> {
    let key_bytes = std::fs::read(&config.key_file)
        .with_context(|| format!("failed to read key file {}", config.key_file.display()))?;
    let signer = Arc::new(PasetoV4Signer::try_new(&key_bytes).context("invalid signing key")?);

    tracing::info!(policy_dir = %config.policy_dir.display(), "loading enforcement policy store");
    let policy_store = CedarPolicyStore::load(
        &config.policy_dir,
        config.schema_path.clone(),
        config.bundle_ttl_seconds,
    )?;

    tracing::info!(issuance_policy_dir = %config.issuance_policy_dir.display(), "loading issuance policy store");
    let issuance_policy_store = CedarPolicyStore::load(
        &config.issuance_policy_dir,
        config.schema_path.clone(),
        config.bundle_ttl_seconds,
    )?;

    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let revocation_store = RevocationStore::try_new(&config.revocation_file, token_ttl)?;

    AuthorityServiceImpl::try_new(
        issuance_policy_store,
        policy_store,
        revocation_store,
        signer,
        config.max_ttl_seconds,
    )
}

async fn bind_listener(listen_addr: &str) -> Result<(tokio::net::TcpListener, u16)> {
    let addr: SocketAddr = listen_addr
        .parse()
        .with_context(|| format!("invalid listen address {listen_addr}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;
    let port = listener
        .local_addr()
        .context("failed to get local address")?
        .port();
    Ok((listener, port))
}

async fn build_server_future<F, H>(
    config: &AuthorityConfig,
    authority_service: AuthorityServiceImpl,
    health_service: tonic_health::pb::health_server::HealthServer<H>,
    listener: tokio::net::TcpListener,
    shutdown_signal: F,
) -> Result<ServerFuture>
where
    F: Future<Output = ()> + Send + 'static,
    H: tonic_health::pb::health_server::Health + Send + Sync + 'static,
{
    match (
        &config.tls.tls_cert_path,
        &config.tls.tls_key_path,
        &config.tls.mtls_client_ca_cert_path,
        &config.tls.authorized_clients_path,
    ) {
        (Some(cert_path), Some(key_path), Some(ca_cert_path), Some(clients_path)) => {
            build_mtls_future(
                cert_path,
                key_path,
                ca_cert_path,
                clients_path,
                authority_service,
                health_service,
                listener,
                shutdown_signal,
            )
            .await
        }
        (Some(cert_path), Some(key_path), None, None) => {
            build_tls_future(
                cert_path,
                key_path,
                authority_service,
                health_service,
                listener,
                shutdown_signal,
            )
            .await
        }
        _ => Ok(build_plain_future(
            authority_service,
            health_service,
            listener,
            shutdown_signal,
        )),
    }
}

// ---------------------------------------------------------------------------
// Per-mode server future builders
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_arguments,
    reason = "mTLS server construction needs explicit TLS paths, services, listener, and shutdown signal"
)]
async fn build_mtls_future<F, H>(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
    clients_path: &Path,
    authority_service: AuthorityServiceImpl,
    health_service: tonic_health::pb::health_server::HealthServer<H>,
    listener: tokio::net::TcpListener,
    shutdown_signal: F,
) -> Result<ServerFuture>
where
    F: Future<Output = ()> + Send + 'static,
    H: tonic_health::pb::health_server::Health + Send + Sync + 'static,
{
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("failed to read TLS cert {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("failed to read TLS key {}", key_path.display()))?;
    let ca_cert_pem = tokio::fs::read(ca_cert_path).await.with_context(|| {
        format!(
            "failed to read mTLS client CA cert {}",
            ca_cert_path.display()
        )
    })?;

    let allow_list = Arc::new(AuthorizedClientSet::load(clients_path).with_context(|| {
        format!(
            "failed to load authorized-clients list {}",
            clients_path.display()
        )
    })?);
    tracing::info!(
        entries = allow_list.len(),
        path = %clients_path.display(),
        "loaded authorized-clients allow-list"
    );

    let tls_cfg = build_mtls_server_config(&cert_pem, &key_pem, &ca_cert_pem, allow_list)
        .context("failed to build mTLS server config")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
    tracing::info!("mTLS enabled on gRPC server (client certs required + allow-list enforced)");

    let incoming = mtls_incoming(listener, acceptor);
    let mut builder = TonicServer::builder();
    let svc = builder
        .add_service(health_service)
        .add_service(AuthorityServiceServer::new(authority_service));
    Ok(Box::pin(
        svc.serve_with_incoming_shutdown(incoming, shutdown_signal),
    ))
}

async fn build_tls_future<F, H>(
    cert_path: &Path,
    key_path: &Path,
    authority_service: AuthorityServiceImpl,
    health_service: tonic_health::pb::health_server::HealthServer<H>,
    listener: tokio::net::TcpListener,
    shutdown_signal: F,
) -> Result<ServerFuture>
where
    F: Future<Output = ()> + Send + 'static,
    H: tonic_health::pb::health_server::Health + Send + Sync + 'static,
{
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("failed to read TLS cert {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("failed to read TLS key {}", key_path.display()))?;
    let identity = Identity::from_pem(cert_pem, key_pem);
    let tls_config = ServerTlsConfig::new().identity(identity);
    tracing::info!("TLS enabled on gRPC server (server-only, V1)");

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let mut builder = TonicServer::builder()
        .tls_config(tls_config)
        .context("invalid TLS config")?;
    let svc = builder
        .add_service(health_service)
        .add_service(AuthorityServiceServer::new(authority_service));
    Ok(Box::pin(
        svc.serve_with_incoming_shutdown(incoming, shutdown_signal),
    ))
}

fn build_plain_future<F, H>(
    authority_service: AuthorityServiceImpl,
    health_service: tonic_health::pb::health_server::HealthServer<H>,
    listener: tokio::net::TcpListener,
    shutdown_signal: F,
) -> ServerFuture
where
    F: Future<Output = ()> + Send + 'static,
    H: tonic_health::pb::health_server::Health + Send + Sync + 'static,
{
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let mut builder = TonicServer::builder();
    let svc = builder
        .add_service(health_service)
        .add_service(AuthorityServiceServer::new(authority_service));
    Box::pin(svc.serve_with_incoming_shutdown(incoming, shutdown_signal))
}

// ---------------------------------------------------------------------------
// mTLS rustls helpers
// ---------------------------------------------------------------------------

/// Build a `rustls::ServerConfig` that requires client certificates and
/// enforces the allow-list via [`AllowListClientVerifier`].
///
/// ALPN is set to `["h2", "http/1.1"]` so tonic's HTTP/2 framing works.
fn build_mtls_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_cert_pem: &[u8],
    allow_list: Arc<AuthorizedClientSet>,
) -> Result<rustls::ServerConfig> {
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem))
            .collect::<Result<_, _>>()
            .context("failed to parse server TLS certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("server TLS certificate PEM contains no certificates");
    }

    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem))
        .context("failed to read server TLS private key PEM")?
        .context("server TLS key PEM contains no private key")?;
    let key = match key {
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(k),
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(k),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(k),
        _ => anyhow::bail!("unsupported server TLS private key type"),
    };

    let mut roots = RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(client_ca_cert_pem))
            .collect::<Result<_, _>>()
            .context("failed to parse client CA certificate PEM")?;
    if ca_certs.is_empty() {
        anyhow::bail!("client CA certificate PEM contains no certificates");
    }
    for ca_cert in ca_certs {
        roots
            .add(ca_cert)
            .context("failed to add client CA cert to root store")?;
    }
    let roots = Arc::new(roots);

    let inner_verifier = WebPkiClientVerifier::builder_with_provider(roots, Arc::clone(&provider))
        .build()
        .context("failed to build WebPki client verifier")?;
    let supported_algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(AllowListClientVerifier::new(
        inner_verifier,
        allow_list,
        supported_algs,
    ));

    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to set TLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("failed to build rustls ServerConfig")?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server_config)
}

/// Produce an async stream of `TlsStream<TcpStream>` items for
/// `serve_with_incoming_shutdown`. Failed TLS handshakes (including
/// allow-list rejections) are logged and silently dropped.
fn mtls_incoming(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> impl tokio_stream::Stream<
    Item = Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>,
> {
    async_stream::stream! {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    match acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            let peer_identity = peer_cn(&tls_stream);
                            tracing::debug!(
                                peer = %peer_addr,
                                identity = %peer_identity.as_deref().unwrap_or("<unknown>"),
                                "mTLS client connected"
                            );
                            yield Ok(tls_stream);
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer = %peer_addr,
                                err = %e,
                                "mTLS handshake failed — connection dropped"
                            );
                        }
                    }
                }
                Err(e) => {
                    yield Err(e);
                }
            }
        }
    }
}

/// Extract the peer certificate identity (DNS SAN preferred, then CN) from
/// a successfully established TLS stream.
fn peer_cn(stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, server_conn) = stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    let end_entity = certs.first()?;
    let (_, parsed) = X509Certificate::from_der(end_entity.as_ref()).ok()?;

    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    return Some((*dns).to_string());
                }
            }
        }
    }
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}
