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
    let file = match open_endpoint_record(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
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
    file.take(MAX_ENDPOINT_RECORD_BYTES + 1)
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

/// Open one record handle without following a final symlink or reparse point.
#[cfg(unix)]
fn open_endpoint_record(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}

/// Open one record handle and reject Windows reparse points on that handle.
#[cfg(windows)]
fn open_endpoint_record(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "endpoint publication is a reparse point",
        ));
    }
    Ok(file)
}

pub const fn endpoint_protocol_version() -> u32 {
    ENDPOINT_PROTOCOL_VERSION
}
