mod cedar_loader;
mod config;
mod error;
mod revocation;
mod service;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tonic::transport::Server;

use firma_core::token::paseto::PasetoV4Signer;
use firma_proto::firma::v1::authority_service_server::AuthorityServiceServer;

use crate::cedar_loader::CedarPolicyStore;
use crate::config::AuthorityConfig;
use crate::revocation::RevocationStore;
use crate::service::AuthorityServiceImpl;

#[derive(Parser)]
#[command(
    name = "firma-authority",
    about = "Mini Authority — Firma OSS policy & capability service"
)]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the authority gRPC server (default).
    Serve,
    /// Revoke a capability token by ID.
    Revoke {
        /// The token ID to revoke.
        token_id: String,
    },
    /// Generate a new Ed25519 key pair for token signing.
    GenerateKey {
        /// Output path for the key file (default: firma-authority.key).
        #[arg(short, long, default_value = "firma-authority.key")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load configuration
    let config = match AuthorityConfig::load(cli.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level)),
        )
        .json()
        .init();

    let command = cli.command.unwrap_or(Commands::Serve);

    match command {
        Commands::Serve => run_server(config).await,
        Commands::Revoke { token_id } => run_revoke(&config, &token_id),
        Commands::GenerateKey { output } => run_generate_key(&output),
    }
}

async fn run_server(config: config::AuthorityConfig) {
    tracing::warn!("NOT FOR PRODUCTION USE: This is the Mini Authority (Firma OSS v1) intended for local development and testing only.");

    tracing::info!(listen_addr = %config.listen_addr, "firma-authority starting");

    // FR-9: Load Ed25519 signing key
    let key_bytes = match std::fs::read(&config.key_file) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(
                path = %config.key_file.display(),
                %error,
                "failed to read signing key file — run `firma-authority generate-key` first"
            );
            std::process::exit(1);
        }
    };

    let signer = match PasetoV4Signer::try_new(&key_bytes) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(error = %e, "invalid signing key");
            std::process::exit(1);
        }
    };

    // FR-1: Load Cedar policies
    let policy_store = match CedarPolicyStore::load(&config.policy_dir, config.bundle_ttl_seconds) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            tracing::error!(error = %e, "failed to load Cedar policies");
            std::process::exit(1);
        }
    };

    // Load revocation store
    let revocation_store = match RevocationStore::new(&config.revocation_file) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize revocation store");
            std::process::exit(1);
        }
    };

    // FR-2: Start policy directory watcher for hot-reload
    let policy_watcher = match policy_store.watch() {
        Ok(w) => Arc::new(w),
        Err(e) => {
            tracing::error!(error = %e, "failed to start policy directory watcher");
            std::process::exit(1);
        }
    };

    // Start revocation file watcher
    let revocation_watcher = match revocation_store.watch() {
        Ok(w) => Arc::new(w),
        Err(e) => {
            tracing::error!(error = %e, "failed to start revocation file watcher");
            std::process::exit(1);
        }
    };

    // Build gRPC service
    let authority_service = AuthorityServiceImpl::new(
        Arc::clone(&policy_store),
        policy_watcher,
        Arc::clone(&revocation_store),
        revocation_watcher,
        signer,
        config.max_ttl_seconds,
    );

    let addr = config.listen_addr.parse().unwrap_or_else(|e| {
        tracing::error!(error = %e, addr = %config.listen_addr, "invalid listen address");
        std::process::exit(1);
    });

    tracing::info!(%addr, "gRPC server listening");

    // FR-10: Health check via gRPC reflection / tonic-health.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    if let Err(e) = Server::builder()
        .add_service(health_service)
        .add_service(AuthorityServiceServer::new(authority_service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await
    {
        tracing::error!(error = %e, "gRPC server error");
        std::process::exit(1);
    }

    tracing::info!("firma-authority shut down gracefully");
}

/// FR-7: Revoke a token by appending its ID to the revocation file.
fn run_revoke(config: &config::AuthorityConfig, token_id: &str) {
    use std::io::Write;

    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.revocation_file)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "failed to open revocation file {}: {e}",
                config.revocation_file.display()
            );
            std::process::exit(1);
        }
    };

    if let Err(e) = writeln!(file, "{token_id}") {
        eprintln!("failed to write to revocation file: {e}");
        std::process::exit(1);
    }

    println!("revoked token: {token_id}");
}

/// FR-9: Generate a new Ed25519 key pair and write to file.
fn run_generate_key(output: &PathBuf) {
    let kp = match AsymmetricKeyPair::<V4>::generate() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("failed to generate key pair: {e:?}");
            std::process::exit(1);
        }
    };

    // Write secret key (64 bytes: 32-byte seed + 32-byte public)
    if let Err(e) = std::fs::write(output, kp.secret.as_bytes()) {
        eprintln!("failed to write key file {}: {e}", output.display());
        std::process::exit(1);
    }

    // Set file permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(output, perms) {
            eprintln!("warning: could not set key file permissions: {e}");
        }
    }

    // Write public key alongside (for verification / distribution)
    let pub_path = output.with_extension("pub");
    if let Err(e) = std::fs::write(&pub_path, kp.public.as_bytes()) {
        eprintln!(
            "failed to write public key file {}: {e}",
            pub_path.display()
        );
        std::process::exit(1);
    }

    println!("generated Ed25519 key pair:");
    println!("  secret: {}", output.display());
    println!("  public: {}", pub_path.display());
}

/// Wait for SIGINT or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|e| tracing::error!(error = %e, "failed to install ctrl+c handler"));
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                // Fall through to let ctrl_c handle shutdown alone
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => { tracing::info!("received SIGINT"); },
        () = terminate => { tracing::info!("received SIGTERM"); },
    }
}
