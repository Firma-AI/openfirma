//! Args for `firma sidecar` subcommand.

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The path to the configuration file for the sidecar.
    ///
    /// When unset, `firma.toml` is discovered from platform config
    /// dirs (see docs/cli.md).
    #[clap(long, short = 'c', env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// Health check binding address.
    #[clap(
        long,
        env = "FIRMA_SIDECAR_HEALTH_BIND_ADDR",
        default_value = "127.0.0.1:9000"
    )]
    pub health_bind_addr: SocketAddr,
}
