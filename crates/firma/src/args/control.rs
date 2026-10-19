//! Arguments for `firma control`.

use std::path::PathBuf;

use clap::Args as ClapArgs;

/// Parsed `firma control` command-line arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Override the runtime state directory holding the audit log.
    ///
    /// Policy discovery resolves the same directory: artifact paths the
    /// `[authority]` section leaves unset, including the TLS pair under
    /// `tls/`, are read from here rather than from the ambient default.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
}
