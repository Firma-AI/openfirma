//! Filesystem helpers shared by `OpenFirma` crates.

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

/// Error returned by file write helpers.
#[derive(Debug, thiserror::Error)]
#[error("{op} {path}: {source}")]
pub struct FsError {
    op: &'static str,
    path: PathBuf,
    #[source]
    source: io::Error,
}

impl FsError {
    fn new(op: &'static str, path: &Path, source: io::Error) -> Self {
        Self {
            op,
            path: path.to_path_buf(),
            source,
        }
    }

    /// Return the underlying I/O error kind.
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
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

/// Write `bytes` to `path`, creating or truncating it, with the given Unix mode.
/// On Windows the `mode` argument is ignored.
///
/// # Errors
///
/// Returns [`FsError`] on any I/O failure.
pub fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
        .map_err(|e| FsError::new("open", path, e))?
        .write_all(bytes)
        .map_err(|e| FsError::new("write", path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| FsError::new("chmod", path, e))?;
    }
    Ok(())
}

/// Write `bytes` to a new file at `path` with the given Unix mode.
///
/// Returns [`FsError`] with [`FsError::kind`] equal to
/// [`io::ErrorKind::AlreadyExists`] if the file already exists. Callers decide
/// whether to treat that as an error or ignore it. On Windows the `mode`
/// argument is ignored.
///
/// # Errors
///
/// Returns [`FsError`] on any I/O failure.
pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
        .map_err(|e| FsError::new("create", path, e))?
        .write_all(bytes)
        .map_err(|e| FsError::new("write", path, e))
}
