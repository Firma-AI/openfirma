//! Filesystem utilities shared across services.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

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
        Self { op, path: path.to_path_buf(), source }
    }

    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}

/// Create `path` and all parents with mode 0700 on Unix (umask-independent).
/// Also enforces 0700 on pre-existing directories.
/// On Windows, falls back to `create_dir_all` without explicit mode.
pub fn create_private_dir_all(path: &Path) -> Result<(), FsError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| FsError::new("create", path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| FsError::new("chmod 0700", path, e))?;
    }
    Ok(())
}

/// Write `bytes` to a new file at `path` with the given Unix mode.
/// Returns `FsError` with `kind() == AlreadyExists` if the file already exists —
/// callers decide whether to treat that as an error or ignore it.
/// On Windows the `mode` argument is ignored.
pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
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
