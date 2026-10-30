use clap::Args as ClapArgs;

/// Origin of the hosted Firma control plane, used when no origin is given.
const DEFAULT_CONTROL_PLANE_ORIGIN: &str = "https://app.firma.ai";

/// Inputs for one `firma login`.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// HTTPS origin of the Firma Team control plane.
    #[arg(long, default_value = DEFAULT_CONTROL_PLANE_ORIGIN)]
    pub control_plane_origin: url::Url,
    /// Permit HTTP only for a loopback development control plane. Requires an
    /// explicit `--control-plane-origin`, so it never applies to the default.
    #[arg(long, requires = "control_plane_origin")]
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
