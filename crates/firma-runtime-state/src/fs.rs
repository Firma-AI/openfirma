//! Filesystem helpers for private runtime state.

use std::io;
use std::path::{Path, PathBuf};

/// Error returned by [`create_private_dir_all`].
#[derive(Debug, thiserror::Error)]
pub enum CreatePrivateDirError {
    /// Directory creation failed.
    #[error("failed to create {path}: {source}")]
    Create {
        /// Path that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Setting mode 0700 on an existing directory failed.
    #[error("failed to set mode 0700 on {path}: {source}")]
    Chmod {
        /// Path whose permissions could not be updated.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Write `contents` to `path` with mode 0600 on Unix (owner read/write only, umask-independent).
///
/// Uses `O_CREAT | O_TRUNC` so the mode is set atomically on creation with no write-then-chmod
/// race. Falls back to [`std::fs::write`] on non-Unix platforms.
///
/// # Errors
///
/// Returns an [`io::Error`] on any I/O failure.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Create `path` and all parents with mode 0700 on Unix (umask-independent).
/// Also enforces 0700 on pre-existing directories.
/// On Windows, falls back to `create_dir_all` without explicit mode.
///
/// # Errors
///
/// Returns [`CreatePrivateDirError::Create`] if the directory cannot be created,
/// or [`CreatePrivateDirError::Chmod`] if its permissions cannot be set to 0700.
pub fn create_private_dir_all(path: &Path) -> Result<(), CreatePrivateDirError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| CreatePrivateDirError::Create {
            path: path.to_path_buf(),
            source: e,
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            CreatePrivateDirError::Chmod {
                path: path.to_path_buf(),
                source: e,
            }
        })?;
    }
    Ok(())
}
