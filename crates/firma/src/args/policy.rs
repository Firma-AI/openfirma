//! Args for `firma policy`.

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Print all available posture and mapping templates.
    List,
}
