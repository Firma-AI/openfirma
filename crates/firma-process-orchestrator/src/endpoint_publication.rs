//! One-shot child-to-parent TCP endpoint publication.
//!
//! The record deliberately carries no process or generation identity. The
//! parent supplies a private generation-scoped path and retains the
//! [`crate::component::OwnedComponent`] that authorizes liveness decisions.

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Endpoint publication protocol understood by this orchestrator version.
const ENDPOINT_PROTOCOL_VERSION: u32 = 1;
/// Bound structured state reads so a faulty child cannot force unbounded allocation.
const MAX_ENDPOINT_RECORD_BYTES: u64 = 4_096;

/// Structured one-shot record published after a child successfully binds TCP.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointRecord {
    protocol_version: u32,
    effective_addr: SocketAddr,
}

/// Atomically publish a successfully bound TCP endpoint without replacing state.
///
/// The destination's parent must already exist. Publication writes and flushes
/// a complete versioned record beside `path`, then atomically installs it with
/// no-clobber semantics. An existing file, including a symlink, causes failure.
///
/// # Errors
///
/// Returns an I/O error when serialization, durable staging, or no-clobber
/// publication fails.
pub fn publish_tcp_endpoint(path: &Path, effective_addr: SocketAddr) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let record = toml::to_string(&EndpointRecord {
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        effective_addr,
    })
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(record.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Read and validate a complete child publication record.
pub fn read_tcp_endpoint(path: &Path) -> std::io::Result<Option<(u32, SocketAddr)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "endpoint publication is not a regular file",
        ));
    }
    if metadata.len() > MAX_ENDPOINT_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "endpoint publication exceeds the size limit",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_ENDPOINT_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ENDPOINT_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "endpoint publication exceeds the size limit",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let record: EndpointRecord = toml::from_str(text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(Some((record.protocol_version, record.effective_addr)))
}

pub const fn endpoint_protocol_version() -> u32 {
    ENDPOINT_PROTOCOL_VERSION
}
