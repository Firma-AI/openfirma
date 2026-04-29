mod agent_bridge;
mod demo_loader;
mod process_manager;
mod runtime;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "firma-demo-tui", about = "Firma policy enforcement demo TUI")]
struct Cli {
    /// Skip menu and run a specific demo directory directly
    #[arg(long, short, value_name = "DIR")]
    demo: Option<PathBuf>,

    /// Directory containing demo subdirectories (shown in menu)
    #[arg(long, default_value = "./examples/demos")]
    demos_dir: PathBuf,

    /// Path to firma-authority binary
    #[arg(long, default_value = "./target/debug/firma-authority")]
    authority_bin: PathBuf,

    /// Path to firma-sidecar binary
    #[arg(long, default_value = "./target/debug/firma-sidecar")]
    sidecar_bin: PathBuf,

    /// Skip cargo build step
    #[arg(long)]
    no_build: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if !cli.no_build {
        runtime::build_binaries()?;
    }

    ui::run(
        &cli.demos_dir,
        cli.demo.as_deref(),
        cli.authority_bin,
        cli.sidecar_bin,
    )
}
