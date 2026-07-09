#![cfg(unix)]

use std::io;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use crate::{CreatePrivateDirError, FsError};

pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn create_private_dir_all(path: &Path) -> Result<(), CreatePrivateDirError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|e| CreatePrivateDirError::Create {
            path: path.to_path_buf(),
            source: e,
        })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        CreatePrivateDirError::Chmod {
            path: path.to_path_buf(),
            source: e,
        }
    })?;
    Ok(())
}

pub fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true).mode(mode);
    opts.open(path)
        .map_err(|e| FsError::new("open", path, e))?
        .write_all(bytes)
        .map_err(|e| FsError::new("write", path, e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| FsError::new("chmod", path, e))?;
    Ok(())
}

pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true).mode(mode);
    opts.open(path)
        .map_err(|e| FsError::new("create", path, e))?
        .write_all(bytes)
        .map_err(|e| FsError::new("write", path, e))
}
