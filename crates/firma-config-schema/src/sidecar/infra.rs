//! Schema for the sidecar's top-level infrastructure sections:
//! `mode`, `[policy]`, `[ca]`, and `[credentials.*]`.
//!
//! Representation only. `firma-sidecar` validates these values and parses
//! them into its own configuration types (for example, the credential
//! header parses into an `http::HeaderName`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Enforcement mode for the sidecar.
///
/// `enforce` (default) is normal fail-closed operation; `monitor` is
/// observe-only. The monitor-mode opt-in gating lives in `firma-sidecar`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarMode {
    /// Normal fail-closed enforcement (default).
    #[default]
    Enforce,
    /// Observe-only: classify and log every call, but never block.
    Monitor,
}

/// Policy source settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    /// Directory containing `.cedar` policy files.
    #[serde(default = "default_policy_dir")]
    pub dir: PathBuf,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            dir: default_policy_dir(),
        }
    }
}

/// Certificate authority directory settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaConfig {
    /// Directory containing CA key material.
    #[serde(default = "default_ca_dir")]
    pub dir: PathBuf,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: default_ca_dir(),
        }
    }
}

/// Credential injection mode selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// Static credential read from an environment variable at startup.
    #[default]
    Basic,
    /// Secret file rendered by Vault Agent, read from disk per-call.
    Vault,
}

/// Optional transformation applied to resolved credential material before
/// injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialTransform {
    /// Render a GitHub PAT as the Basic auth value accepted by Git smart HTTP.
    GithubPatBasic,
}

/// Credential injection entry for a single external target.
///
/// The `header` field is a plain string here; `firma-sidecar` parses it into
/// an `http::HeaderName` during validation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialConfig {
    /// Injection mode. Default: `basic`.
    #[serde(default)]
    pub mode: CredentialMode,
    /// Host that this credential applies to.
    pub target_host: String,
    /// HTTP header name to inject (e.g. `Authorization`).
    pub header: String,
    /// Optional prefix prepended to the resolved value (e.g. `"Bearer "`).
    #[serde(default)]
    pub prefix: Option<String>,
    /// Optional transform applied to the resolved secret before injection.
    #[serde(default)]
    pub transform: Option<CredentialTransform>,
    /// Environment variable whose value is injected (basic mode).
    #[serde(default)]
    pub value_from_env: Option<String>,
    /// Filesystem path to the secret file rendered by Vault Agent (vault mode).
    #[serde(default)]
    pub secret_path: Option<PathBuf>,
}

/// Sentinel: unset `policy.dir`.
const DEFAULT_POLICY_DIR: &str = "./policies/";
/// Sentinel: unset `ca.dir` (state-managed; never re-based).
const DEFAULT_CA_DIR: &str = "./firma-ca/";

fn default_policy_dir() -> PathBuf {
    PathBuf::from(DEFAULT_POLICY_DIR)
}

fn default_ca_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CA_DIR)
}
