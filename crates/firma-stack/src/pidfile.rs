//! Pid-file read, write, remove, and metadata helpers.

use std::path::Path;

use crate::error::Result;

/// Write a pid file.
///
/// # Errors
///
/// Returns filesystem errors.
pub fn write(path: &Path, pid: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{pid}\n"))?;
    Ok(())
}

/// Read a pid file.
///
/// # Errors
///
/// Returns filesystem errors other than not-found.
pub fn read(path: &Path) -> Result<Option<u32>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.trim().parse().ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Remove a pid file if present.
///
/// # Errors
///
/// Returns filesystem errors other than not-found.
pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Return pidfile modification time if the file exists.
///
/// # Errors
///
/// Returns filesystem metadata errors other than not-found.
pub fn mtime(path: &Path) -> Result<Option<std::time::SystemTime>> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(meta.modified().ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
