use std::path::PathBuf;

use clap::{Parser, Subcommand};
use firma_core::TokenId;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;

use firma_authority::{AuthorityConfig, RevocationStore, Server};

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
    /// Revocation management.
    Revoke {
        #[command(subcommand)]
        action: RevokeAction,
    },
    /// Generate a new Ed25519 key pair for token signing.
    GenerateKey {
        /// Output path for the key file (default: firma-authority.key).
        #[arg(short, long, default_value = "firma-authority.key")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum RevokeAction {
    /// Revoke a capability token by ID.
    Token {
        /// The token ID to revoke.
        token_id: TokenId,
        /// Human-readable reason for the revocation.
        #[arg(short, long, default_value = "operator-revoked")]
        reason: String,
    },
    /// Remove expired entries from the revocation file.
    Compact,
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
        Commands::Revoke {
            action: RevokeAction::Token { token_id, reason },
        } => {
            run_revoke(&config, token_id, &reason).await;
        }
        Commands::Revoke {
            action: RevokeAction::Compact,
        } => run_compact(&config).await,
        Commands::GenerateKey { output } => run_generate_key(&output),
    }
}

/// Run gRPC server.
async fn run_server(config: AuthorityConfig) {
    let server = match Server::try_new(config, shutdown_signal()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize authority server");
            std::process::exit(1);
        }
    };
    if let Err(error) = server.run().await {
        tracing::error!(%error, "authority failed");
        std::process::exit(1);
    }
}

/// FR-7: Revoke a token by delegating to [`RevocationStore::revoke`].
async fn run_revoke(config: &AuthorityConfig, token_id: TokenId, reason: &str) {
    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let store = match RevocationStore::try_new(&config.revocation_file, token_ttl) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to open revocation store: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = store.revoke(token_id, reason).await {
        eprintln!("failed to revoke token: {e}");
        std::process::exit(1);
    }
    println!("revoked token: {token_id}");
}

async fn run_compact(config: &AuthorityConfig) {
    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let store = match RevocationStore::try_new(&config.revocation_file, token_ttl) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to open revocation store: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = store.compact_file().await {
        eprintln!("failed to compact revocation file: {e}");
        std::process::exit(1);
    }
    println!("compacted: {}", config.revocation_file.display());
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
