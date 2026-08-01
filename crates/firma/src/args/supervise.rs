//! Hidden `__supervise` arg struct.

use std::path::PathBuf;

use clap::Args as ClapArgs;

/// Parsed `firma __supervise` arguments. Hidden internal subcommand spawned
/// by `firma stack start --detach`; not user-facing.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// State directory containing stack pid files.
    #[arg(long)]
    pub state_dir: PathBuf,

    /// Unified stack configuration passed by the detached launcher.
    #[arg(long)]
    pub config: PathBuf,

    /// Optional binary override used to spawn Authority and Sidecar.
    #[arg(long)]
    pub firma_bin: Option<PathBuf>,
}
