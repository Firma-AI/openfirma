//! Filesystem helpers shared by `OpenFirma` crates.
//!
//! Choose the helper by contract:
//!
//! - [`create_private_dir_all`] creates a directory tree and, on Unix, ensures
//!   the final directory ends with private permissions.
//! - [`write_private_file`] writes a file that must always end with private
//!   permissions on Unix.
//! - [`write_file`] writes a file whose final Unix mode is chosen by the
//!   caller.
//! - [`write_new_file`] is the create-once variant of [`write_file`]. Pair it
//!   with [`FsError::kind`] when `std::io::ErrorKind::AlreadyExists` is a
//!   non-fatal outcome.
//!
//! The file helpers write only the target file. They do not create parent
//! directories; provision those separately with [`create_private_dir_all`] or
//! another directory-creation step first.
//!
//! On non-Unix platforms, the helpers fall back to the closest stdlib behavior.
//! That means Unix mode arguments and permission-tightening guarantees are
//! ignored where the platform does not expose them.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(not(unix))]
mod not_unix;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
use not_unix as platform;
#[cfg(unix)]
use unix as platform;

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

/// Write `contents` to `path` with private permissions on Unix.
///
/// Uses `O_CREAT | O_TRUNC` so the mode is set atomically on creation, then
/// reapplies mode 0600 after writing to tighten pre-existing files. Falls back
/// to [`std::fs::write`] on non-Unix platforms. See the [module docs](self)
/// for helper-selection guidance and parent-directory requirements.
///
/// # Errors
///
/// Returns an [`io::Error`] on any I/O failure.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    platform::write_private_file(path, contents)
}

/// Create `path` and all parents with mode 0700 on Unix (umask-independent).
///
/// Also enforces 0700 on the final directory when it already exists.
/// On non-Unix platforms, falls back to [`std::fs::create_dir_all`] without
/// explicit mode handling.
///
/// # Errors
///
/// Returns [`CreatePrivateDirError::Create`] if the directory cannot be created,
/// or [`CreatePrivateDirError::Chmod`] if its permissions cannot be set to 0700.
pub fn create_private_dir_all(path: &Path) -> Result<(), CreatePrivateDirError> {
    platform::create_private_dir_all(path)
}

/// Write `bytes` to `path`, creating or truncating it, with the given Unix
/// mode.
///
/// On non-Unix platforms, the `mode` argument is ignored. See the
/// [module docs](self) for when to use this helper instead of
/// [`write_private_file`] or [`write_new_file`].
///
/// # Errors
///
/// Returns [`FsError`] on any I/O failure.
pub fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    platform::write_file(path, bytes, mode)
}

/// Write `bytes` to a new file at `path` with the given Unix mode.
///
/// Returns [`FsError`] with [`FsError::kind`] equal to
/// [`io::ErrorKind::AlreadyExists`] if the file already exists. Callers decide
/// whether to treat that as an error or ignore it.
///
/// On non-Unix platforms, the `mode` argument is ignored. See the
/// [module docs](self) for the shared parent-directory requirement.
///
/// # Errors
///
/// Returns [`FsError`] on any I/O failure.
pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    platform::write_new_file(path, bytes, mode)
}
