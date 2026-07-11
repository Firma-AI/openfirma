//! Component readiness probes.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use firma_sidecar::config::SidecarConfig;

use crate::error::{Result, StackError};

pub fn wait_for_tcp(component: &str, addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(StackError::Readiness {
                component: component.to_string(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn wait_for_ca_material(ca_dir: &Path, timeout: Duration) -> Result<()> {
    let cert = ca_dir.join("firma-ca.crt");
    let key = ca_dir.join("firma-ca.key");
    let deadline = Instant::now() + timeout;
    loop {
        if cert.exists() && key.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(StackError::Readiness {
                component: "sidecar (CA material)".into(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A parsed unified `firma.toml`, read once so the probes below share a single
/// read instead of each re-reading the file. Retains the source path for error
/// messages.
pub struct FirmaToml {
    root: toml::Value,
    path: PathBuf,
}

impl FirmaToml {
    /// Resolve `[authority].listen_addr`.
    ///
    /// # Errors
    ///
    /// Returns [`StackError::Platform`] when the key is missing or is not a
    /// valid socket address.
    pub fn authority_listen_addr(&self) -> Result<SocketAddr> {
        let raw = self
            .root
            .get("authority")
            .and_then(|node| node.get("listen_addr"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                StackError::Platform(format!(
                    "no listen_addr under [authority] in '{}'",
                    self.path.display()
                ))
            })?;
        raw.parse::<SocketAddr>().map_err(|e| {
            StackError::Platform(format!("invalid authority listen_addr '{raw}': {e}"))
        })
    }

    /// Deserialize the `[sidecar]` section into firma-sidecar's own
    /// [`SidecarConfig`], so the stack shares the sidecar's schema, defaults,
    /// and `HttpsMitmConfig::is_active` semantics rather than mirroring them.
    ///
    /// Callers read `interceptor.listen_addr` for the TCP readiness probe and
    /// `interceptor.https_mitm.is_active()` to gate the CA-material probe.
    ///
    /// # Errors
    ///
    /// Returns [`StackError::Platform`] when the `[sidecar]` section is missing
    /// or does not deserialize.
    pub fn sidecar_config(&self) -> Result<SidecarConfig> {
        let section = self.root.get("sidecar").cloned().ok_or_else(|| {
            StackError::Platform(format!("no [sidecar] section in '{}'", self.path.display()))
        })?;
        section.try_into().map_err(|e: toml::de::Error| {
            StackError::Platform(format!(
                "invalid [sidecar] config in '{}': {e}",
                self.path.display()
            ))
        })
    }
}

/// Read and parse the unified `firma.toml` once into a [`FirmaToml`].
///
/// # Errors
///
/// Returns [`StackError`] when the file cannot be read, or
/// [`StackError::Platform`] when it is not valid TOML.
pub fn read_config(config_path: &Path) -> Result<FirmaToml> {
    let text = std::fs::read_to_string(config_path)?;
    let root = toml::from_str(&text)
        .map_err(|e: toml::de::Error| StackError::Platform(format!("firma.toml: {e}")))?;
    Ok(FirmaToml {
        root,
        path: config_path.to_path_buf(),
    })
}
