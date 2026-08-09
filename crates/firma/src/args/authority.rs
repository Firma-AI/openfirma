//! Args for `firma authority` subcommand.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Subcommand};
use firma_core::TokenId;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Path to the Authority TOML config (issuer identity, key paths, bundle dir,
    /// listen address). When unset, falls back to platform discovery.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Internal path for writing the one-shot startup report.
    #[arg(long, hide = true)]
    pub startup_report: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage the Authority's revocation list. Revoked token IDs are streamed
    /// to every Sidecar so capability tokens can be invalidated mid-flight.
    #[command(visible_alias = "revoke", visible_alias = "rev")]
    Revocations {
        #[command(subcommand)]
        action: RevocationsCommand,
    },
    /// Generate a new Ed25519 signing key pair for the Authority. The Authority
    /// uses this key to sign PASETO v4 capability tokens; Sidecars verify with
    /// the public half.
    GenerateKey {
        /// Output path for the generated key file.
        #[arg(short, long, default_value = "firma-authority.key")]
        output: PathBuf,
    },
    /// Bootstrap a local CA plus server/client certificates for the
    /// Authority↔Sidecar gRPC channel. Convenience for development; production
    /// stacks should plug in an existing PKI.
    InitTls {
        /// Output directory for generated PEM files (CA cert/key, server cert/key,
        /// client cert/key).
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Hostname or IP SAN to include in the Authority server certificate.
        /// Repeat the flag for multiple SANs.
        #[arg(long = "host")]
        hosts: Vec<String>,
    },
    /// Sign and emit a capability token to a TOML seed file. Used to mint
    /// fixed-scope tokens offline (CI, demos, tests) instead of going through
    /// the Authority's gRPC issuance API.
    Issue(IssueArgs),
    /// Generate and sign an mTLS client certificate for a Sidecar.
    ///
    /// Requires `mtls_client_ca_cert_path` and `mtls_client_ca_key_path` to
    /// be set in the Authority config. The generated cert and private key are
    /// written as separate PEM files. Add the CN (or the cert's DNS SAN if
    /// you specify `--san`) to `authorized_clients_path` to authorize the
    /// Sidecar.
    #[command(name = "issue-client-cert")]
    IssueClientCert(IssueClientCertArgs),
    /// Generate a new mTLS client CA key pair (CA cert + CA key).
    ///
    /// Use this once per Authority deployment to create the CA that signs
    /// Sidecar client certificates. Keep the CA key offline after signing.
    #[command(name = "generate-client-ca")]
    GenerateClientCa(GenerateClientCaArgs),
}

#[derive(Debug, Subcommand)]
pub enum RevocationsCommand {
    /// Add a token ID to the revocation store. Sidecars will deny any request
    /// presenting that token on the next bundle refresh.
    Add(RevocationsAddArgs),
    /// Remove already-expired entries from the revocation file to keep the
    /// streamed list small.
    Compact,
}

#[derive(Debug, ClapArgs)]
pub struct RevocationsAddArgs {
    /// The token ID to revoke.
    pub token_id: TokenId,
    /// Human-readable reason for the revocation.
    #[arg(short, long, default_value = "operator-revoked")]
    pub reason: String,
}

#[derive(Debug, ClapArgs)]
pub struct IssueClientCertArgs {
    /// Common Name (CN) for the client certificate.
    /// The CN is used as the primary identity in the authorized-clients allow-list.
    #[arg(long)]
    pub cn: String,
    /// Optional DNS Subject Alternative Name. When set, this SAN (not the CN)
    /// is checked against the allow-list on the Authority side.
    #[arg(long)]
    pub san: Option<String>,
    /// Certificate validity in days (default: 365).
    #[arg(long, default_value_t = 365)]
    pub days: u32,
    /// Output path for the client certificate PEM (e.g. sidecar-client.crt).
    #[arg(long)]
    pub cert_out: PathBuf,
    /// Output path for the client private key PEM (e.g. sidecar-client.key).
    #[arg(long)]
    pub key_out: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub struct GenerateClientCaArgs {
    /// Output path for the CA certificate PEM.
    #[arg(long, default_value = "firma-client-ca.crt")]
    pub cert_out: PathBuf,
    /// Output path for the CA private key PEM.
    #[arg(long, default_value = "firma-client-ca.key")]
    pub key_out: PathBuf,
    /// CA validity in days (default: 3650).
    #[arg(long, default_value_t = 3650)]
    pub days: u32,
    /// Common Name for the CA certificate.
    #[arg(long, default_value = "Firma mTLS Client CA")]
    pub cn: String,
}

#[derive(Debug, ClapArgs)]
pub struct IssueArgs {
    /// Agent identity for the issued token.
    #[arg(long)]
    pub agent_id: String,
    /// Session identity for the issued token.
    #[arg(long)]
    pub session_id: String,
    /// Action class(es) the token covers. Repeat the flag for multiple.
    #[arg(long = "action", required = true)]
    pub actions: Vec<String>,
    /// Resource scope pattern (e.g. `wttr.in*`).
    #[arg(long, default_value = "*")]
    pub resource_scope: String,
    /// Requested TTL in seconds. Clamped by `max_ttl_seconds` in config.
    #[arg(long, default_value_t = 3600)]
    pub ttl_seconds: i32,
    /// Output TOML path.
    #[arg(short, long)]
    pub output: PathBuf,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Args;

    #[derive(clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn parses_hidden_startup_report_path() {
        let args = Wrapper::try_parse_from([
            "firma-authority",
            "--startup-report",
            "/private/startup/0.toml",
        ])
        .expect("parse internal startup-report path")
        .args;

        assert_eq!(args.startup_report, Some("/private/startup/0.toml".into()));
        assert!(args.command.is_none());
    }
}
