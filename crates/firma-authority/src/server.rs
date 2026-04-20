use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use firma_core::token::paseto::PasetoV4Signer;
use firma_proto::firma::v1::authority_service_server::AuthorityServiceServer;
use tonic::transport::Server as TonicServer;
use tonic_health::server::HealthReporter;

use crate::cedar_loader::CedarPolicyStore;
use crate::config::AuthorityConfig;
use crate::error::AuthorityError;
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
    pub async fn try_new<F>(
        config: AuthorityConfig,
        shutdown_signal: F,
    ) -> Result<Self, AuthorityError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tracing::warn!(
            "NOT FOR PRODUCTION USE: This is the Mini Authority (Firma OSS v1) intended for local development and testing only."
        );

        // Load Ed25519 signing key
        let key_bytes = std::fs::read(&config.key_file).map_err(|e| AuthorityError::KeyError {
            reason: format!(
                "failed to read key file {}: {}",
                config.key_file.display(),
                e
            ),
        })?;

        let signer = match PasetoV4Signer::try_new(&key_bytes) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                return Err(AuthorityError::KeyError {
                    reason: format!("invalid signing key: {e}"),
                });
            }
        };

        // Load Cedar policies
        let policy_store = Arc::new(CedarPolicyStore::load(
            &config.policy_dir,
            config.bundle_ttl_seconds,
        )?);

        // Load revocation store
        let revocation_store = Arc::new(RevocationStore::new(&config.revocation_file)?);

        // Start policy directory watcher for hot-reload
        let policy_watcher = Arc::new(policy_store.watch()?);

        // Start revocation file watcher
        let revocation_watcher = Arc::new(revocation_store.watch()?);

        // Build gRPC service
        let authority_service = AuthorityServiceImpl::new(
            Arc::clone(&policy_store),
            policy_watcher,
            Arc::clone(&revocation_store),
            revocation_watcher,
            signer,
            config.max_ttl_seconds,
        );

        let addr: SocketAddr =
            config
                .listen_addr
                .parse()
                .map_err(|e| AuthorityError::ConfigError {
                    reason: format!("invalid listen address {}: {}", config.listen_addr, e),
                })?;

        let listener =
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| AuthorityError::ConfigError {
                    reason: format!("failed to bind to {addr}: {e}"),
                })?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| AuthorityError::ConfigError {
                reason: format!("failed to get local address: {e}"),
            })?;

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
    pub async fn run(mut self) -> Result<(), AuthorityError> {
        tracing::info!(port = %self.port, "gRPC server listening");
        self.health_reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        self.future.await.map_err(|error| AuthorityError::Server {
            reason: error.to_string(),
        })
    }

    /// Get the port the server is bound to.
    #[must_use] 
    pub fn port(&self) -> u16 {
        self.port
    }
}
