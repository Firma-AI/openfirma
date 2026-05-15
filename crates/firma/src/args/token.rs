//! Args for `firma token`.

use clap::{Args, Subcommand};

/// Arguments for `firma token`.
#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Approve a pending local-exec governance token.
    Approve(TokenActionArgs),
    /// Revoke a pending or approved local-exec governance token.
    Revoke(TokenActionArgs),
}

#[derive(Debug, Args)]
pub struct TokenActionArgs {
    /// The token ID returned by the governance endpoint (`approval_token` field).
    pub token_id: String,

    /// Path to the local-exec governance UDS socket.
    ///
    /// Must match `local_exec.socket_path` in the sidecar config.
    /// Accepted forms: a plain filesystem path or `unix:///path/to/sock`.
    #[arg(long, default_value = "/tmp/firma-sidecar-tools.sock")]
    pub socket: String,
}
