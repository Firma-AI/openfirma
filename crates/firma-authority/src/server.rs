use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use firma_core::token::paseto::PasetoV4Signer;
use firma_proto::firma::v1::authority_service_server::AuthorityServiceServer;
use tonic::transport::{Identity, Server as TonicServer, ServerTlsConfig};
use tonic_health::server::HealthReporter;

use crate::cedar_loader::CedarPolicyStore;
use crate::config::AuthorityConfig;
use crate::revocation::RevocationStore;
use crate::service::AuthorityServiceImpl;

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
    future: Pin<Box<dyn Future<Output = Result<(), tonic::transport::Error>> + Send>>,
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

        // Load Ed25519 signing key
        let key_bytes = std::fs::read(&config.key_file)
            .with_context(|| format!("failed to read key file {}", config.key_file.display()))?;

        let signer = Arc::new(PasetoV4Signer::try_new(&key_bytes).context("invalid signing key")?);

        // Load Cedar policies for streaming to sidecars (enforcement bundle)
        tracing::info!(
            policy_dir = %config.policy_dir.display(),
            "loading enforcement policy store"
        );
        let policy_store = CedarPolicyStore::load(
            &config.policy_dir,
            config.schema_path.clone(),
            config.bundle_ttl_seconds,
        )?;

        let policy_count = std::fs::read_dir(&config.policy_dir).map_or(0, |rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "cedar"))
                .count()
        });

        // Load separate issuance policy store
        tracing::info!(
            issuance_policy_dir = %config.issuance_policy_dir.display(),
            "loading issuance policy store"
        );
        let issuance_policy_store = CedarPolicyStore::load(
            &config.issuance_policy_dir,
            config.schema_path.clone(),
            config.bundle_ttl_seconds,
        )?;

        // Load revocation store
        let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
        let revocation_store = RevocationStore::try_new(&config.revocation_file, token_ttl)?;

        // Build gRPC service (starts all file watchers internally)
        let authority_service = AuthorityServiceImpl::try_new(
            issuance_policy_store,
            policy_store,
            revocation_store,
            signer,
            config.max_ttl_seconds,
        )?;

        let addr: SocketAddr = config
            .listen_addr
            .parse()
            .with_context(|| format!("invalid listen address {}", config.listen_addr))?;

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind to {addr}"))?;

        let local_addr = listener
            .local_addr()
            .context("failed to get local address")?;

        let port = local_addr.port();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        // Validate: both TLS fields must be set or neither.
        if config.tls_cert_path.is_some() != config.tls_key_path.is_some() {
            anyhow::bail!("tls_cert_path and tls_key_path must both be set or both be unset");
        }

        let (health_reporter, health_service) = tonic_health::server::health_reporter();

        let mut tonic_builder = if let (Some(cert_path), Some(key_path)) =
            (&config.tls_cert_path, &config.tls_key_path)
        {
            let cert_pem = tokio::fs::read(cert_path)
                .await
                .with_context(|| format!("failed to read TLS cert {}", cert_path.display()))?;
            let key_pem = tokio::fs::read(key_path)
                .await
                .with_context(|| format!("failed to read TLS key {}", key_path.display()))?;
            let identity = Identity::from_pem(cert_pem, key_pem);
            let tls_config = ServerTlsConfig::new().identity(identity);
            tracing::info!("TLS enabled on gRPC server");
            TonicServer::builder()
                .tls_config(tls_config)
                .context("invalid TLS config")?
        } else {
            TonicServer::builder()
        };

        let server = tonic_builder
            .add_service(health_service)
            .add_service(AuthorityServiceServer::new(authority_service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal);

        Ok(Self {
            port,
            listen_addr: local_addr,
            policy_dir: config.policy_dir.clone(),
            configured_listen_addr: config.listen_addr.clone(),
            policy_count,
            health_reporter,
            future: Box::pin(server),
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
