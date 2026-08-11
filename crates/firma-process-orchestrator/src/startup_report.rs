//! One-shot child-to-parent startup reporting.
//!
//! The record deliberately carries no process or generation identity. The
//! parent supplies a private generation-scoped path and retains the
//! [`crate::component::OwnedComponent`] that authorizes liveness decisions.

use std::io::{Read as _, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Startup-report protocol understood by this orchestrator version.
const STARTUP_REPORT_PROTOCOL_VERSION: u32 = 2;
/// Bound structured state reads so a faulty child cannot force unbounded allocation.
const MAX_STARTUP_REPORT_BYTES: u64 = 4_096;

/// Structured one-shot report published after a child successfully starts.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupReport {
    protocol_version: u32,
    endpoint: crate::ComponentEndpoint,
}

/// Atomically publish a startup report without replacing state.
///
/// The destination's parent must already exist. Publication writes a complete
/// versioned record beside `path`, then atomically installs it with no-clobber
/// semantics. An existing file, including a symlink, causes failure.
///
/// # Errors
///
/// Returns an I/O error when serialization, staging, or no-clobber publication
/// fails.
pub fn publish_startup_report(
    path: &Path,
    endpoint: &crate::ComponentEndpoint,
) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let record = toml::to_string(&StartupReport {
        protocol_version: STARTUP_REPORT_PROTOCOL_VERSION,
        endpoint: endpoint.clone(),
    })
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(record.as_bytes())?;
    temp.persist_noclobber(path).map_err(|error| error.error)?;
    Ok(())
}

/// Read and validate a complete child startup report.
pub fn read_startup_report(path: &Path) -> std::io::Result<Option<crate::ComponentEndpoint>> {
    let file = match open_startup_report(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "startup report is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_STARTUP_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STARTUP_REPORT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "startup report exceeds the size limit",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let report: StartupReport = toml::from_str(text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if report.protocol_version != STARTUP_REPORT_PROTOCOL_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported protocol version {}", report.protocol_version),
        ));
    }
    Ok(Some(report.endpoint))
}

/// Open one record handle without following a final symlink or reparse point.
#[cfg(unix)]
fn open_startup_report(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}

/// Open one record handle and reject Windows reparse points on that handle.
#[cfg(windows)]
fn open_startup_report(path: &Path) -> std::io::Result<std::fs::File> {
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
            "startup report is a reparse point",
        ));
    }
    Ok(file)
}
