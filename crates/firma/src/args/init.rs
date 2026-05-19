//! Args for `firma init`.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

/// Scaffold a new agent config directory from the CLI.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Agent slug used as the `agent_id` in the generated config (e.g. "my-agent").
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// LLM provider — determines the CONNECT mapping rule in `mapping-rules.toml`.
    #[arg(long, value_enum)]
    pub provider: Option<Provider>,

    /// Comma-separated extra hosts the agent is allowed to reach.
    #[arg(long)]
    pub extra_hosts: Option<String>,

    /// Absolute path the agent may write to (bwrap RW mount).
    /// Defaults to the output directory.
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    /// Directory to write scaffolded files into (default: current directory).
    #[arg(long, short = 'o', default_value = ".")]
    pub output_dir: PathBuf,

    /// Print generated files to stdout without writing to disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Overwrite files that already exist (default: preserve).
    #[arg(long)]
    pub force: bool,
}

/// LLM provider selection for `firma init`.
#[derive(Debug, Clone, ValueEnum)]
pub enum Provider {
    /// Anthropic Claude API (api.anthropic.com).
    Anthropic,
    /// `OpenAI` API (api.openai.com).
    Openai,
    /// Other — a commented placeholder is written; fill in manually.
    Other,
}
