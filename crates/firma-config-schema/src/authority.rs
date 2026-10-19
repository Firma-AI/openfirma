//! Schema for the `[authority]` section of `firma.toml`.
//!
//! Representation only. `firma-authority` converts this flat TOML shape into
//! its validated runtime configuration, including the grouped TLS settings.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use firma_config_utils::NonZeroDuration;

/// Sentinel: unset `policy_dir`.
const DEFAULT_POLICY_DIR: &str = "policies/";
/// Sentinel: unset `issuance_policy_dir`.
const DEFAULT_ISSUANCE_POLICY_DIR: &str = "issuance-policies/";
/// Behavior-free representation of `[authority]`.
///
/// TLS fields remain direct members so the public TOML keys stay flat without
/// relying on Serde `flatten`, which is incompatible with reliable unknown-key
/// rejection.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorityConfig {
    /// gRPC listen address (default: `[::1]:50051`).
    pub listen_addr: String,
    /// Directory containing enforcement policy files.
    pub policy_dir: PathBuf,
    /// Directory containing capability-issuance policy files.
    pub issuance_policy_dir: PathBuf,
    /// Optional path to the Cedar schema file.
    pub schema_path: Option<PathBuf>,
    /// Ordered mapping rule files included in enforcement snapshots.
    /// At least one file is required. A file with no rules classifies nothing,
    /// so all traffic is denied.
    pub mapping_rules_paths: Vec<PathBuf>,
    /// Path to the revocation file.
    ///
    /// Unset defaults to `revocations.txt` in the resolved state directory.
    pub revocation_file: Option<PathBuf>,
    /// Strictly non-zero maximum token TTL.
    pub max_ttl: NonZeroDuration,
    /// Path to the Ed25519 signing key file.
    ///
    /// Unset defaults to `authority.key` in the resolved state directory.
    pub key_file: Option<PathBuf>,
    /// Strictly non-zero policy bundle TTL advertised to Sidecars.
    pub bundle_ttl: NonZeroDuration,
    /// Path to the TLS certificate file.
    ///
    /// Unset defaults to `tls/authority.crt` in the resolved state directory, and
    /// TLS stays off when nothing was generated there.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS private key file.
    ///
    /// Unset defaults to `tls/authority.key` in the resolved state directory, and
    /// TLS stays off when nothing was generated there.
    pub tls_key_path: Option<PathBuf>,
    /// Path to the CA certificate used to verify Sidecar mTLS clients.
    pub mtls_client_ca_cert_path: Option<PathBuf>,
    /// Path to the CA key used to issue Sidecar client certificates.
    pub mtls_client_ca_key_path: Option<PathBuf>,
    /// Path to the authorized-client identities file.
    pub authorized_clients_path: Option<PathBuf>,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:50051".to_string(),
            policy_dir: PathBuf::from(DEFAULT_POLICY_DIR),
            issuance_policy_dir: PathBuf::from(DEFAULT_ISSUANCE_POLICY_DIR),
            schema_path: None,
            mapping_rules_paths: Vec::new(),
            revocation_file: None,
            max_ttl: NonZeroDuration::from_static(Duration::from_hours(1)),
            key_file: None,
            bundle_ttl: NonZeroDuration::from_static(Duration::from_secs(30)),
            tls_cert_path: None,
            tls_key_path: None,
            mtls_client_ca_cert_path: None,
            mtls_client_ca_key_path: None,
            authorized_clients_path: None,
        }
    }
}
