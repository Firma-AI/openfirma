mod agent_bridge;
mod demo_loader;
mod process_manager;
mod runtime;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "openauthority-demo-tui",
    about = "OpenAuthority policy enforcement demo TUI"
)]
struct Cli {
    /// Skip menu and run a specific demo directory directly
    #[arg(long, short, value_name = "DIR")]
    demo: Option<PathBuf>,

    /// Directory containing demo subdirectories (shown in menu)
    #[arg(long, default_value = "./examples/demos")]
    demos_dir: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    ui::run(&cli.demos_dir, cli.demo.as_deref())
}
