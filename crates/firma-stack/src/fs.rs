//! Filesystem helpers shared across the stack and its dependents.

use std::io;
use std::path::{Path, PathBuf};

/// Error returned by [`create_private_dir_all`].
#[derive(Debug, thiserror::Error)]
pub enum CreatePrivateDirError {
    /// Directory creation failed.
    #[error("failed to create {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Setting mode 0700 on an existing directory failed.
    #[error("failed to set mode 0700 on {path}: {source}")]
    Chmod {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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
