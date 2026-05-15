//! Component readiness probes.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

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

/// Read `[authority].listen_addr` from the unified `firma.toml`.
pub fn read_authority_listen_addr(config_path: &Path) -> Result<SocketAddr> {
    section_listen_addr(config_path, &["authority"], "authority")
}

/// Read `[sidecar.interceptor].listen_addr` from the unified `firma.toml`.
pub fn read_sidecar_listen_addr(config_path: &Path) -> Result<SocketAddr> {
    section_listen_addr(config_path, &["sidecar", "interceptor"], "sidecar")
}

fn section_listen_addr(config_path: &Path, path: &[&str], what: &str) -> Result<SocketAddr> {
    let text = std::fs::read_to_string(config_path)?;
    let mut node: &toml::Value = &toml::from_str::<toml::Value>(&text)
        .map_err(|e: toml::de::Error| StackError::Platform(format!("{what} toml: {e}")))?;
    for key in path {
        node = node.get(key).ok_or_else(|| {
            StackError::Platform(format!(
                "no [{}] section in '{}'",
                path.join("."),
                config_path.display()
            ))
        })?;
    }
    let raw = node
        .get("listen_addr")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            StackError::Platform(format!(
                "no listen_addr under [{}] in '{}'",
                path.join("."),
                config_path.display()
            ))
        })?;
    raw.parse::<SocketAddr>()
        .map_err(|e| StackError::Platform(format!("invalid {what} listen_addr '{raw}': {e}")))
}
