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
    /// Approve a pending governance token, releasing the held request so the
    /// Sidecar can let the original call through.
    Approve(TokenActionArgs),
    /// Revoke a pending or already-approved governance token. The held
    /// request — and any future call relying on it — is denied.
    Revoke(TokenActionArgs),
}

#[derive(Debug, Args)]
pub struct TokenActionArgs {
    /// Token ID returned by the governance endpoint (the `approval_token`
    /// field in the held-request notification).
    pub token_id: String,

    /// Path to the Sidecar's local-exec governance UDS socket. Must match
    /// `local_exec.socket_path` in the Sidecar config. Accepts a plain
    /// filesystem path or `unix:///path/to/sock`.
    #[arg(long, default_value = "/tmp/firma-sidecar-tools.sock")]
    pub socket: String,

    /// Path to a file containing the operator management token (must match the
    /// sidecar's `local_exec.management_token_path`). When omitted the token is
    /// read from the `FIRMA_LOCAL_EXEC_MANAGEMENT_TOKEN` environment variable.
    #[arg(long)]
    pub management_token_path: Option<String>,
}
