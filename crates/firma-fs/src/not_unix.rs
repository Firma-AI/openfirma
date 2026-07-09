#![cfg(not(unix))]

use std::io;
use std::io::Write as _;
use std::path::Path;

use crate::{CreatePrivateDirError, FsError};

pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    std::fs::write(path, contents)
}

pub fn create_private_dir_all(path: &Path) -> Result<(), CreatePrivateDirError> {
    std::fs::create_dir_all(path).map_err(|e| CreatePrivateDirError::Create {
        path: path.to_path_buf(),
        source: e,
    })
}

pub fn write_file(path: &Path, bytes: &[u8], _mode: u32) -> Result<(), FsError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    opts.open(path)
        .map_err(|e| FsError::new("open", path, e))?
        .write_all(bytes)
        .map_err(|e| FsError::new("write", path, e))
}

pub fn write_new_file(path: &Path, bytes: &[u8], _mode: u32) -> Result<(), FsError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    opts.open(path)
        .map_err(|e| FsError::new("create", path, e))?
        .write_all(bytes)
        .map_err(|e| FsError::new("write", path, e))
}
