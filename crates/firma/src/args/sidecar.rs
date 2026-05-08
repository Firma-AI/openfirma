//! Args for `firma sidecar` subcommand.

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The path to the configuration file for the sidecar.
    #[clap(
        long,
        short = 'c',
        env = "FIRMA_SIDECAR_CONFIG_FILE",
        default_value = "firma_sidecar.toml"
    )]
    pub config_file: PathBuf,
    /// Health check binding address.
    #[clap(
        long,
        env = "FIRMA_SIDECAR_HEALTH_BIND_ADDR",
        default_value = "127.0.0.1:9000"
    )]
    pub health_bind_addr: SocketAddr,
}
