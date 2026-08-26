//! Schema for the `[authority]` section of `firma.toml`.
//!
//! Representation only. `firma-authority` builds its validated configuration
//! type from this shape, re-bases relative paths against the config
//! directory, and applies `FIRMA_AUTHORITY_`-prefixed environment overrides.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Default `policy_dir` value.
const DEFAULT_POLICY_DIR: &str = "policies/";
/// Default `issuance_policy_dir` value.
const DEFAULT_ISSUANCE_POLICY_DIR: &str = "issuance-policies/";
/// Default `key_file` value.
const DEFAULT_KEY_FILE: &str = "firma-authority.key";

/// Behavior-free representation of the `[authority]` section.
///
/// Every field defaults, so a partial or absent section deserializes into the
/// canonical defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthorityConfig {
    /// gRPC listen address (default: `[::1]:50051`).
    pub listen_addr: String,
    /// Directory containing `.cedar` policy files streamed to sidecars for enforcement.
    pub policy_dir: PathBuf,
    /// Directory containing `.cedar` policy files used to gate capability issuance.
    ///
    /// The Authority evaluates issuance requests against this policy set.
    /// `policy_dir` is still streamed to sidecars for enforcement. This lets
    /// issuance policies differ from enforcement policies (e.g. permit issuance
    /// of `communication.external.send` while the sidecar's enforcement policy
    /// forbids the actual call).
    pub issuance_policy_dir: PathBuf,
    /// Optional path to the Cedar schema file.
    /// Overrides `policy_dir/schema.cedarschema`. When unset, falls back to
    /// the schema found in `policy_dir`, then to the embedded canonical schema.
    pub schema_path: Option<PathBuf>,
    /// Path to the revocation file (one token ID per line).
    pub revocation_file: PathBuf,
    /// Maximum token TTL in seconds (default: 3600).
    pub max_ttl_seconds: i32,
    /// Path to the Ed25519 signing key file (64-byte raw or PEM).
    pub key_file: PathBuf,
    /// Log level filter (default: `info`).
    pub log_level: String,
    /// Policy bundle TTL advertised to sidecars in seconds (default: 30).
    pub bundle_ttl_seconds: u32,
    /// Authority TLS configuration.
    ///
    /// Uses `tls_cert_path` + `tls_key_path` keys in TOML via flattening.
    #[serde(flatten)]
    pub tls: AuthorityTlsConfig,
}

/// Behavior-free representation of the Authority's TLS settings.
///
/// Both `tls_cert_path` and `tls_key_path` are required together to enable
/// TLS; the pairing is validated in `firma-authority`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AuthorityTlsConfig {
    /// Path to the TLS certificate file (PEM). Must be set together with
    /// `tls_key_path`.
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS private key file (PEM). Must be set together with
    /// `tls_cert_path`.
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    /// Path to the PEM CA certificate used to verify Sidecar mTLS client
    /// certificates. When set (together with `authorized_clients_path`),
    /// the server requires client certificates and rejects connections whose
    /// identity is not in the allow-list at the TLS handshake level.
    /// Requires `tls_cert_path` / `tls_key_path` to also be configured.
    pub mtls_client_ca_cert_path: Option<PathBuf>,
    /// Path to the PEM CA private key used by `firma authority issue-client-cert`
    /// to sign new Sidecar client certificates. Not loaded at server startup;
    /// only the `issue-client-cert` subcommand reads this file.
    pub mtls_client_ca_key_path: Option<PathBuf>,
    /// Path to the TOML file listing authorized client identities (CN or DNS
    /// SAN). Required together with `mtls_client_ca_cert_path`.
    pub authorized_clients_path: Option<PathBuf>,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:50051".to_string(),
            policy_dir: PathBuf::from(DEFAULT_POLICY_DIR),
            issuance_policy_dir: PathBuf::from(DEFAULT_ISSUANCE_POLICY_DIR),
            schema_path: None,
            revocation_file: PathBuf::from("revocations.txt"),
            max_ttl_seconds: 3600,
            key_file: PathBuf::from(DEFAULT_KEY_FILE),
            log_level: "info".to_string(),
            bundle_ttl_seconds: 30,
            tls: AuthorityTlsConfig::default(),
        }
    }
}
