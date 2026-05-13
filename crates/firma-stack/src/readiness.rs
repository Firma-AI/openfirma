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

pub fn read_authority_listen_addr(config_path: &Path) -> Result<SocketAddr> {
    let text = std::fs::read_to_string(config_path)?;
    for line in text.lines() {
        let trimmed = line.split('#').next().unwrap_or_default().trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() == "listen_addr" {
            let value = value.trim().trim_matches('"');
            return value.parse::<SocketAddr>().map_err(|error| {
                StackError::Platform(format!("invalid listen_addr '{value}': {error}"))
            });
        }
    }
    Err(StackError::Platform(format!(
        "no listen_addr in '{}'",
        config_path.display()
    )))
}

pub fn read_sidecar_listen_addr(config_path: &Path) -> Result<SocketAddr> {
    let text = std::fs::read_to_string(config_path)?;
    let value: toml::Value = toml::from_str(&text)
        .map_err(|error: toml::de::Error| StackError::Platform(format!("sidecar toml: {error}")))?;
    let raw = find_listen_addr(&value).ok_or_else(|| {
        StackError::Platform(format!(
            "no listen_addr in sidecar config '{}'",
            config_path.display()
        ))
    })?;
    raw.parse::<SocketAddr>().map_err(|error| {
        StackError::Platform(format!("invalid sidecar listen_addr '{raw}': {error}"))
    })
}

fn find_listen_addr(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::Table(table) => {
            if let Some(toml::Value::String(value)) = table.get("listen_addr") {
                return Some(value.clone());
            }
            table.values().find_map(find_listen_addr)
        }
        _ => None,
    }
}
