use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
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
    /// Manage revocation entries.
    #[command(visible_alias = "revoke", visible_alias = "rev")]
    Revocations {
        #[command(subcommand)]
        action: RevocationsCommand,
    },
    /// Generate a new Ed25519 key pair for token signing.
    GenerateKey {
        /// Output path for the key file (default: firma-authority.key).
        #[arg(short, long, default_value = "firma-authority.key")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum RevocationsCommand {
    /// Add a token ID to the revocation store.
    Add(RevocationsAddArgs),
    /// Remove expired entries from the revocation file.
    Compact,
}

#[derive(Args)]
struct RevocationsAddArgs {
    /// The token ID to revoke.
    token_id: TokenId,
    /// Human-readable reason for the revocation.
    #[arg(short, long, default_value = "operator-revoked")]
    reason: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = AuthorityConfig::load(cli.config.as_ref())
        .context("failed to load authority configuration")?;

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level)),
        )
        .init();

    match cli.command {
        None => run_server(config).await?,
        Some(Commands::Revocations {
            action: RevocationsCommand::Add(args),
        }) => run_revoke(&config, args.token_id, &args.reason).await?,
        Some(Commands::Revocations {
            action: RevocationsCommand::Compact,
        }) => run_compact(&config).await?,
        Some(Commands::GenerateKey { output }) => run_generate_key(&output)?,
    }

    Ok(())
}

/// Run gRPC server.
async fn run_server(config: AuthorityConfig) -> Result<()> {
    let server = Server::try_new(config, shutdown_signal())
        .await
        .context("failed to initialize authority server")?;
    server
        .run()
        .await
        .context("authority server exited with error")
}

/// FR-7: Revoke a token by delegating to [`RevocationStore::revoke`].
async fn run_revoke(config: &AuthorityConfig, token_id: TokenId, reason: &str) -> Result<()> {
    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let store =
        RevocationStore::try_new(&config.revocation_file, token_ttl).with_context(|| {
            format!(
                "failed to open revocation store at {}",
                config.revocation_file.display()
            )
        })?;
    store.revoke(token_id, reason).await.with_context(|| {
        format!(
            "failed to revoke token using store {}",
            config.revocation_file.display()
        )
    })?;
    println!("revoked token: {token_id}");
    Ok(())
}

async fn run_compact(config: &AuthorityConfig) -> Result<()> {
    let token_ttl = chrono::Duration::seconds(i64::from(config.max_ttl_seconds));
    let store =
        RevocationStore::try_new(&config.revocation_file, token_ttl).with_context(|| {
            format!(
                "failed to open revocation store at {}",
                config.revocation_file.display()
            )
        })?;
    store.compact_file().await.with_context(|| {
        format!(
            "failed to compact revocation file {}",
            config.revocation_file.display()
        )
    })?;
    println!("compacted: {}", config.revocation_file.display());
    Ok(())
}

/// FR-9: Generate a new Ed25519 key pair and write to file.
fn run_generate_key(output: &PathBuf) -> Result<()> {
    let kp = AsymmetricKeyPair::<V4>::generate().context("failed to generate key pair")?;

    // Write secret key (64 bytes: 32-byte seed + 32-byte public)
    std::fs::write(output, kp.secret.as_bytes())
        .with_context(|| format!("failed to write key file {}", output.display()))?;

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
    std::fs::write(&pub_path, kp.public.as_bytes())
        .with_context(|| format!("failed to write public key file {}", pub_path.display()))?;

    println!("generated Ed25519 key pair:");
    println!("  secret: {}", output.display());
    println!("  public: {}", pub_path.display());
    Ok(())
}

/// Wait for SIGINT or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|error| tracing::error!(%error, "failed to install ctrl+c handler"));
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
