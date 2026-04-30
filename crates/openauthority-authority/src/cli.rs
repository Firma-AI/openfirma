//! Authority command-line interface.
//!
//! Houses every subcommand the `openauthority-authority` binary exposes:
//! the default `serve` flow, revocation management, key generation,
//! and the [`Commands::Issue`] subcommand used by the demo to
//! pre-issue a capability seed without standing up the gRPC server.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use openauthority_core::TokenId;
use openauthority_core::token::paseto::PasetoV4Signer;
use openauthority_core::{AgentId, SessionId};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;

use crate::{AuthorityConfig, CedarPolicyStore, IssuanceRequest, RevocationStore, Server};

#[derive(Parser)]
#[command(
    name = "openauthority-authority",
    about = "Mini Authority — OpenAuthority OSS policy & capability service"
)]
pub struct Cli {
    /// Path to TOML configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage revocation entries.
    #[command(visible_alias = "revoke", visible_alias = "rev")]
    Revocations {
        #[command(subcommand)]
        action: RevocationsCommand,
    },
    /// Generate a new Ed25519 key pair for token signing.
    GenerateKey {
        /// Output path for the key file (default: openauthority-authority.key).
        #[arg(short, long, default_value = "openauthority-authority.key")]
        output: PathBuf,
    },
    /// Issue a signed capability token to a TOML seed file. Used by the
    /// `make demo` flow until the sidecar `IssueCapability` client lands.
    Issue(IssueArgs),
}

#[derive(Subcommand)]
pub enum RevocationsCommand {
    /// Add a token ID to the revocation store.
    Add(RevocationsAddArgs),
    /// Remove expired entries from the revocation file.
    Compact,
}

#[derive(Args)]
pub struct RevocationsAddArgs {
    /// The token ID to revoke.
    pub token_id: TokenId,
    /// Human-readable reason for the revocation.
    #[arg(short, long, default_value = "operator-revoked")]
    pub reason: String,
}

#[derive(Args, Debug)]
pub struct IssueArgs {
    /// Agent identity for the issued token.
    #[arg(long)]
    pub agent_id: String,
    /// Session identity for the issued token.
    #[arg(long)]
    pub session_id: String,
    /// Action class(es) the token covers. Repeat the flag for multiple.
    #[arg(long = "action", required = true)]
    pub actions: Vec<String>,
    /// Resource scope pattern (e.g. `wttr.in*`).
    #[arg(long, default_value = "*")]
    pub resource_scope: String,
    /// Requested TTL in seconds. Clamped by `max_ttl_seconds` in config.
    #[arg(long, default_value_t = 3600)]
    pub ttl_seconds: i32,
    /// Output TOML path.
    #[arg(short, long)]
    pub output: PathBuf,
}

/// CLI entrypoint. Parses arguments, loads config, and dispatches to the
/// matching subcommand handler. Mirrors the behaviour of the original
/// monolithic `main.rs` body.
///
/// # Errors
///
/// Propagates any error from configuration loading or subcommand
/// execution.
///
/// # Panics
///
/// Panics if `clap` cannot parse `argv` (treated as a fatal usage error)
/// or if a global tracing subscriber has already been installed in the
/// current process.
#[tokio::main]
pub async fn run() -> Result<()> {
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
        .json()
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
        Some(Commands::Issue(args)) => run_issue(&config, &args).await?,
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

/// Issue a signed capability token in-process and write it to a TOML
/// seed file consumable by the sidecar's `[capability_seed]` section.
///
/// Loads the signing key and Cedar policies directly from the on-disk
/// configuration — does **not** require the gRPC server to be running.
async fn run_issue(config: &AuthorityConfig, args: &IssueArgs) -> Result<()> {
    let key_bytes = std::fs::read(&config.key_file)
        .with_context(|| format!("failed to read signing key {}", config.key_file.display()))?;
    let signer = Arc::new(PasetoV4Signer::try_new(&key_bytes).context("invalid signing key")?);
    let policy_store = Arc::new(
        CedarPolicyStore::load(
            &config.policy_dir,
            config.schema_path.clone(),
            config.bundle_ttl_seconds,
        )
        .context("failed to load Cedar policies")?,
    );

    let agent_id: AgentId = args.agent_id.parse().context("invalid agent_id")?;
    let session_id: SessionId = args.session_id.parse().context("invalid session_id")?;
    let req = IssuanceRequest {
        agent_id: &agent_id,
        session_id: &session_id,
        requested_actions: &args.actions,
        resource_scope: &args.resource_scope,
        requested_ttl_seconds: args.ttl_seconds,
    };
    let out = crate::issue_capability(&policy_store, &signer, config.max_ttl_seconds, &req)
        .await
        .map_err(|e| anyhow::anyhow!("issuance failed: {e}"))?;

    let toml_body = SeedFile::from_issuance(&out).to_toml()?;
    std::fs::write(&args.output, toml_body)
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    println!("issued capability to {}", args.output.display());
    Ok(())
}

/// On-disk seed format. Mirrored by the sidecar-side reader at
/// `crates/openauthority-sidecar/src/config/capability_seed.rs::SeedFile`.
/// The two structs intentionally duplicate the schema to avoid an
/// authority → sidecar (or vice versa) crate dependency cycle; keep
/// them in lockstep when adding fields.
#[derive(Debug, serde::Serialize)]
struct SeedFile {
    raw_token: String,
    token_id: String,
    agent_id: String,
    session_id: String,
    action_set: Vec<String>,
    resource_scope: String,
    issued_at: String,
    expiry: String,
    context_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_ceiling: Option<f64>,
}

impl SeedFile {
    fn from_issuance(out: &crate::IssuanceResult) -> Self {
        Self {
            raw_token: out.raw_token.clone(),
            token_id: out.claims.token_id.to_string(),
            agent_id: out.claims.agent_id.to_string(),
            session_id: out.claims.session_id.to_string(),
            action_set: out.claims.action_set.clone(),
            resource_scope: out.claims.resource_scope.clone(),
            issued_at: out.claims.issued_at.to_rfc3339(),
            expiry: out.claims.expiry.to_rfc3339(),
            context_hash: out.claims.context_hash.clone(),
            budget_ceiling: out.claims.budget_ceiling,
        }
    }

    fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("seed serialization failed")
    }
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
