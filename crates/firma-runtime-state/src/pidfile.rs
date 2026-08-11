//! Pid-file read, write, remove, and metadata helpers.

use std::io::Write as _;
use std::path::Path;

use crate::error::{Result, RuntimeStateError};
use crate::process_id::UserProcessId;

/// Write a pid file, publishing it by rename.
///
/// The pid is written to a flushed temporary file in the same directory and
/// then renamed over `path`. On Unix the rename is atomic and the parent
/// directory is flushed afterwards, so a concurrent reader observes either the
/// previous file or the complete new one, and the replacement survives a crash.
/// On Windows the rename goes through `MoveFileEx` with replace semantics, which
/// still avoids a truncate/append window but is not guaranteed to be atomic
/// against a reader holding the destination open.
///
/// # Errors
///
/// Returns filesystem errors.
pub fn write(path: &Path, pid: UserProcessId) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(temp, "{pid}")?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    // Flush the directory entry so the rename is durable across a crash.
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Read a pid file.
///
/// # Errors
///
/// Returns filesystem errors other than not-found, or an error when the file
/// does not contain a valid non-zero process ID.
pub fn read(path: &Path) -> Result<Option<UserProcessId>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let value = text.trim();
            let pid = value
                .parse()
                .ok()
                .and_then(UserProcessId::new)
                .ok_or_else(|| RuntimeStateError::PidfileParse {
                    path: path.to_path_buf(),
                    value: value.to_string(),
                })?;
            Ok(Some(pid))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Read a pid file only when it has the exact format emitted by [`write()`].
///
/// # Errors
///
/// Returns filesystem errors other than not-found, or an error unless the file
/// contains one canonical non-zero decimal process ID followed by one newline.
pub fn read_canonical(path: &Path) -> Result<Option<UserProcessId>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let value = text.strip_suffix('\n').unwrap_or(&text);
            let pid = value
                .parse()
                .ok()
                .and_then(UserProcessId::new)
                .filter(|pid| text == format!("{pid}\n"))
                .ok_or_else(|| RuntimeStateError::PidfileParse {
                    path: path.to_path_buf(),
                    value: text.clone(),
                })?;
            Ok(Some(pid))
        }
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
