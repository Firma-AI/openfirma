//! User-level `firma.toml` reader.
//!
//! Path resolution is delegated to the shared `firma-config-loader` crate so
//! every binary discovers the same `firma.toml`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::RunError;
use firma_sidecar::authority_credentials::SidecarCredentialsConfig;

/// Client-side connect coordinates lifted from `[sidecar.authority]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityConnectSection {
    /// Authority gRPC URL (e.g. `https://127.0.0.1:9443`).
    pub(crate) url: Option<String>,
    /// Path to the PEM CA certificate that signed the authority's TLS cert.
    pub(crate) ca_cert_path: Option<PathBuf>,
    /// Path to the authority's Ed25519 public key for PASETO token verification.
    pub(crate) public_key_path: Option<PathBuf>,
    /// Sidecar credentials presented on Authority RPCs.
    pub(crate) credentials: Option<SidecarCredentialsConfig>,
}

/// Snapshot of routing-relevant sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySection {
    /// `true` when `[authority]` is present — the file declares a
    /// co-located Mini Authority that `firma run` should autostart.
    pub(crate) local: bool,
    /// Parsed `[authority].listen_addr`, defaulting to `[::1]:50051`.
    pub(crate) listen_addr: std::net::SocketAddr,
    /// Client-side connect coordinates lifted from `[sidecar.authority]`.
    pub(crate) connect: Option<AuthorityConnectSection>,
}

impl Default for AuthoritySection {
    fn default() -> Self {
        Self {
            local: false,
            listen_addr: default_listen_addr(),
            connect: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SidecarAuthorityOnDisk {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    public_key_path: Option<PathBuf>,
    #[serde(default)]
    credentials: Option<SidecarCredentialsConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SidecarOnDisk {
    #[serde(default)]
    authority: Option<SidecarAuthorityOnDisk>,
}

fn default_listen_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 50051)
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorityOnDisk {
    #[serde(default = "default_listen_addr")]
    listen_addr: std::net::SocketAddr,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct UserConfig {
    #[serde(default)]
    authority: Option<AuthorityOnDisk>,
    #[serde(default)]
    sidecar: Option<SidecarOnDisk>,
}

/// Read the routing snapshot from `firma.toml`.
///
/// Returns `Ok(None)` when the file does not exist or carries neither
/// `[authority]` nor `[sidecar.authority]` connect coordinates.
///
/// # Errors
///
/// Returns an error on I/O failure (other than `NotFound`) or TOML
/// parse failure.
pub(crate) fn read_authority(path: &Path) -> Result<Option<AuthoritySection>, RunError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(RunError::Internal(format!(
                "read user config {}: {e}",
                path.display()
            )));
        }
    };
    let parsed: UserConfig = toml::from_str(&text).map_err(|e| RunError::ConfigParse {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let local = parsed.authority.is_some();
    let listen_addr = parsed
        .authority
        .map_or_else(default_listen_addr, |a| a.listen_addr);
    let connect = parsed
        .sidecar
        .and_then(|s| s.authority)
        .map(|a| AuthorityConnectSection {
            url: a.url,
            ca_cert_path: a.ca_cert_path,
            public_key_path: a.public_key_path,
            credentials: a.credentials,
        })
        .map(validate_connect_section)
        .transpose()?
        .filter(|c| {
            c.url.is_some()
                || c.ca_cert_path.is_some()
                || c.public_key_path.is_some()
                || c.credentials.is_some()
        });
    if !local && connect.is_none() {
        return Ok(None);
    }
    Ok(Some(AuthoritySection {
        local,
        listen_addr,
        connect,
    }))
}

fn validate_connect_section(
    section: AuthorityConnectSection,
) -> Result<AuthorityConnectSection, RunError> {
    if let Some(ref credentials) = section.credentials {
        credentials.validate().map_err(|reason| {
            RunError::ConfigValidation(format!("sidecar.authority.credentials: {reason}"))
        })?;
    }
    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_config_loader::CONFIG_FILE_NAME;
    use tempfile::tempdir;

    #[test]
    fn read_authority_returns_none_when_file_missing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nope/firma.toml");
        assert_eq!(read_authority(&path).unwrap(), None);
    }

    #[test]
    fn read_authority_returns_none_when_neither_section_present() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&path, "[other]\nkeep = true\n").unwrap();
        assert_eq!(read_authority(&path).unwrap(), None);
    }

    #[test]
    fn authority_section_marks_local() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&path, "[authority]\nlisten_addr = \"127.0.0.1:0\"\n").unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert!(section.local);
        assert!(section.connect.is_none());
    }

    #[test]
    fn sidecar_authority_url_is_lifted_into_connect() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&path, "[sidecar.authority]\nurl = \"https://x\"\n").unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert!(!section.local);
        assert_eq!(
            section.connect.as_ref().and_then(|c| c.url.as_deref()),
            Some("https://x")
        );
    }

    #[test]
    fn sidecar_authority_credentials_are_lifted_into_connect() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(
            &path,
            "[sidecar.authority.credentials]\n\
             workspace_id = \"ws\"\n\
             sidecar_id = \"sc\"\n\
             pre_shared_key_env = \"FIRMA_PSK\"\n",
        )
        .unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        let credentials = section
            .connect
            .and_then(|connect| connect.credentials)
            .expect("credentials");
        assert_eq!(credentials.workspace_id, "ws");
        assert_eq!(credentials.sidecar_id, "sc");
    }
}
