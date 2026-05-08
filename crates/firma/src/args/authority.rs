//! Args for `firma authority` subcommand.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Subcommand};
use firma_core::TokenId;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Path to TOML configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
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
    /// Issue a signed capability token to a TOML seed file.
    Issue(IssueArgs),
}

#[derive(Debug, Subcommand)]
pub enum RevocationsCommand {
    /// Add a token ID to the revocation store.
    Add(RevocationsAddArgs),
    /// Remove expired entries from the revocation file.
    Compact,
}

#[derive(Debug, ClapArgs)]
pub struct RevocationsAddArgs {
    /// The token ID to revoke.
    pub token_id: TokenId,
    /// Human-readable reason for the revocation.
    #[arg(short, long, default_value = "operator-revoked")]
    pub reason: String,
}

#[derive(Debug, ClapArgs)]
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
