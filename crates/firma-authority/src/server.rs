use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use firma_core::token::paseto::PasetoV4Signer;
use firma_proto::firma::v1::authority_service_server::AuthorityServiceServer;
use tonic::transport::Server as TonicServer;
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

        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        let server = TonicServer::builder()
            .add_service(health_service)
            .add_service(AuthorityServiceServer::new(authority_service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal);

        Ok(Self {
            port,
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
        tracing::info!(port = %self.port, "gRPC server listening");
        self.health_reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        self.future.await.context("gRPC transport server failed")
    }

    /// Get the port the server is bound to.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}
