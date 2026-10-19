use clap::Args as ClapArgs;

/// Inputs for one `firma login`.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// HTTPS origin of the Firma Team control plane.
    #[arg(long)]
    pub control_plane_origin: url::Url,
    /// Permit HTTP only for a loopback development control plane.
    #[arg(long)]
    pub development_loopback: bool,
    /// Paste the one-time browser code in this terminal instead of receiving
    /// it on a loopback callback.
    #[arg(long)]
    pub terminal_code: bool,
    /// On Unix, permit a private 0600 file when the operating system
    /// credential store is unavailable.
    #[arg(long)]
    pub allow_plaintext_refresh_token: bool,
}
