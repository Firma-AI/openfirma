//! User-level `firma.toml` reader.
//!
//! Path resolution is delegated to the shared `firma-config-loader` crate so
//! every binary discovers the same `firma.toml`.

use std::path::{Path, PathBuf};

use crate::error::RunError;
use firma_config_schema::sidecar::authority::AuthorityConfig as SidecarAuthorityConfig;
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

fn default_listen_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 50051)
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
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(error) => {
            return Err(RunError::Internal(format!(
                "inspect user config {}: {error}",
                path.display()
            )));
        }
    }
    let parsed =
        firma_config_loader::FirmaConfig::load(path).map_err(|error| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let authority = parsed
        .optional_section::<firma_config_schema::authority::AuthorityConfig>("authority")
        .map_err(|error| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let sidecar = parsed
        .optional_section::<firma_config_schema::sidecar::SidecarConfig>("sidecar")
        .map_err(|error| RunError::ConfigParse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let local = authority.is_some();
    let listen_addr = authority.map_or_else(
        || Ok(default_listen_addr()),
        |config| {
            config
                .listen_addr
                .parse()
                .map_err(|error| RunError::ConfigParse {
                    path: path.to_path_buf(),
                    reason: format!("invalid [authority].listen_addr: {error}"),
                })
        },
    )?;
    let connect = sidecar
        .map(|config| config.authority)
        .map(build_connect_section)
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

fn build_connect_section(
    section: SidecarAuthorityConfig,
) -> Result<AuthorityConnectSection, RunError> {
    let credentials = section
        .credentials
        .map(SidecarCredentialsConfig::try_from)
        .transpose()
        .map_err(|e| RunError::ConfigValidation(format!("sidecar.authority.credentials: {e}")))?;
    Ok(AuthorityConnectSection {
        url: section.url,
        ca_cert_path: section.ca_cert_path,
        public_key_path: section.public_key_path,
        credentials,
    })
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
        std::fs::write(&path, "[run]\nprofile = \"generic\"\n").unwrap();
        assert_eq!(read_authority(&path).unwrap(), None);
    }

    #[test]
    fn read_authority_rejects_invalid_whole_file_shapes() -> anyhow::Result<()> {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);

        for (body, expected_reason) in [
            ("unexpected = true\n", "unknown top-level key `unexpected`"),
            (
                "[authority]\nlisten_addr = \"not-an-address\"\n",
                "invalid [authority].listen_addr",
            ),
            (
                "[authority]\nunexpected = true\n",
                "unknown field `unexpected`",
            ),
            (
                "[sidecar]\nunexpected = true\n",
                "unknown field `unexpected`",
            ),
        ] {
            std::fs::write(&path, body).unwrap();
            let error = match read_authority(&path) {
                Ok(value) => anyhow::bail!("invalid config {body:?} produced {value:?}"),
                Err(error) => error,
            };
            let RunError::ConfigParse {
                path: error_path,
                reason,
            } = error
            else {
                anyhow::bail!("unexpected error for {body:?}: {error}");
            };
            assert_eq!(error_path, path);
            assert!(
                reason.contains(expected_reason),
                "unexpected error for {body:?}: {reason}"
            );
        }

        Ok(())
    }

    #[test]
    fn authority_section_marks_local() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "[authority]\nlisten_addr = \"127.0.0.1:0\"\n").unwrap();
        let section = read_authority(&path).unwrap().unwrap();
        assert!(section.local);
        assert!(section.connect.is_none());
    }

    #[test]
    fn sidecar_authority_url_is_lifted_into_connect() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "[sidecar.authority]\nurl = \"https://x\"\n").unwrap();
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
        std::fs::write(
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
