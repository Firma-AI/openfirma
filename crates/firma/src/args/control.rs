//! Arguments for `firma control`.

use std::path::PathBuf;

use clap::Args as ClapArgs;

/// Parsed `firma control` command-line arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Override the runtime state directory containing the audit log.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
}
