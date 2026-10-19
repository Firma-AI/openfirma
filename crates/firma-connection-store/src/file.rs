//! The private directory and the files in it.
//!
//! On Unix the directory must be a real directory owned by the effective
//! user with no group or other permissions, and so must every file the store
//! opens; nothing is repaired with `chmod`. Existing files are opened
//! without following symlinks and checked through the open handle. A new
//! connection file is written to a temporary file, flushed and checked, then
//! renamed over the old one: the rename is the commit point.
//!
//! Only the last path component is protected against symlinks: the parent
//! of the connection directory must be trusted, as the default location in
//! the user's home is.

use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write as _};
use std::path::Path;

use platform::{
    ensure_private, ensure_private_temporary, flush_dir, open_error, open_existing, open_lock_file,
    private_dir_builder,
};
use zeroize::Zeroizing;

use crate::record::{self, Record};
use crate::{Durability, StoreError};

pub const CONNECTION_FILE: &str = "connection.json";
pub const LOCK_FILE: &str = "connection.lock";

#[derive(Clone, Copy)]
enum Kind {
    Directory,
    File,
}

fn io_error(action: &'static str, path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// Creates the directory when missing and returns the highest directory that
/// must be flushed after a write to make its new entries durable.
pub fn prepare_dir(dir: &Path) -> Result<std::path::PathBuf, StoreError> {
    let sync_up_to = dir
        .ancestors()
        .find_map(|ancestor| match fs::symlink_metadata(ancestor) {
            Ok(_) => Some(Ok(ancestor.to_path_buf())),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => Some(Err(io_error("inspect", ancestor, error))),
        })
        .transpose()?
        .unwrap_or_else(|| dir.to_path_buf());
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => create_dir(dir)?,
        Err(error) => return Err(io_error("inspect", dir, error)),
    }
    check_dir(dir)?;
    Ok(sync_up_to)
}

/// Checks a directory without creating it; `false` means it does not exist.
pub fn existing_dir(dir: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => ensure_private(&metadata, dir, Kind::Directory).map(|()| true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect", dir, error)),
    }
}

fn create_dir(dir: &Path) -> Result<(), StoreError> {
    if let Some(parent) = dir.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|error| io_error("create", parent, error))?;
    }
    match private_dir_builder().create(dir) {
        Err(error) if error.kind() != ErrorKind::AlreadyExists => {
            Err(io_error("create", dir, error))
        }
        _ => Ok(()),
    }
}

/// Checks, again, that the directory is private: it may have changed since
/// the store was opened.
pub fn check_dir(dir: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(dir).map_err(|error| io_error("inspect", dir, error))?;
    ensure_private(&metadata, dir, Kind::Directory)
}

/// Reads the connection file, or `None` when there is none.
pub fn read(dir: &Path) -> Result<Option<Record>, StoreError> {
    let path = dir.join(CONNECTION_FILE);
    let Some((mut file, capacity)) = open_connection(&path)? else {
        return Ok(None);
    };
    let bytes = read_bounded(&mut file, capacity, &path)?;
    record::decode(&path, &bytes).map(Some)
}

/// Handles a file that grows after `fstat` without leaving an unwiped old
/// allocation behind. The advisory lock does not stop a noncooperating writer.
fn read_bounded<R: Read>(
    reader: &mut R,
    capacity: usize,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let count = reader
            .read(&mut *chunk)
            .map_err(|error| io_error("read", path, error))?;
        if count == 0 {
            return Ok(bytes);
        }
        let next_len = bytes
            .len()
            .checked_add(count)
            .filter(|len| *len <= record::MAX_RECORD_BYTES)
            .ok_or(StoreError::RecordTooLarge)?;
        if next_len > bytes.capacity() {
            let new_capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(next_len)
                .min(record::MAX_RECORD_BYTES);
            let mut expanded = Zeroizing::new(Vec::with_capacity(new_capacity));
            expanded.extend_from_slice(&bytes);
            bytes = expanded;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

/// Verifies the file through its open handle before any contents are read.
fn open_connection(path: &Path) -> Result<Option<(File, usize)>, StoreError> {
    let file = match open_existing(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(open_error(path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect", path, error))?;
    ensure_private(&metadata, path, Kind::File)?;
    let capacity = bounded_capacity(metadata.len())?;
    Ok(Some((file, capacity)))
}

fn bounded_capacity(len: u64) -> Result<usize, StoreError> {
    if len > record::MAX_RECORD_BYTES as u64 {
        return Err(StoreError::RecordTooLarge);
    }
    usize::try_from(len).map_err(|_| StoreError::RecordTooLarge)
}

/// Opens or creates the lock file and checks it.
pub fn open_lock(dir: &Path) -> Result<File, StoreError> {
    let path = dir.join(LOCK_FILE);
    let file = open_lock_file(&path).map_err(|error| open_error(&path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect", &path, error))?;
    ensure_private(&metadata, &path, Kind::File)?;
    Ok(file)
}

/// Writes `bytes` as the new connection file. Every failure leaves the old
/// file untouched; on success the new file is committed.
pub fn write(dir: &Path, sync_up_to: &Path, bytes: &[u8]) -> Result<Durability, StoreError> {
    let path = dir.join(CONNECTION_FILE);
    let temporary = prepare_temporary(dir, bytes)?;
    temporary
        .persist(&path)
        .map_err(|error| io_error("replace", &path, error.error))?;
    Ok(flush_dir(dir, sync_up_to))
}

/// Completes every fallible step before the atomic rename.
fn prepare_temporary(dir: &Path, bytes: &[u8]) -> Result<tempfile::NamedTempFile, StoreError> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".connection-")
        .tempfile_in(dir)
        .map_err(|error| io_error("create a temporary file in", dir, error))?;
    let temporary_path = temporary.path().to_path_buf();
    temporary
        .write_all(bytes)
        .map_err(|error| io_error("write", &temporary_path, error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| io_error("flush", &temporary_path, error))?;
    let metadata = temporary
        .as_file()
        .metadata()
        .map_err(|error| io_error("inspect", &temporary_path, error))?;
    ensure_private_temporary(&metadata, &temporary_path)?;
    Ok(temporary)
}

/// Deletes the connection file; `None` when there was none.
pub fn remove(dir: &Path, sync_up_to: &Path) -> Result<Option<Durability>, StoreError> {
    let path = dir.join(CONNECTION_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(Some(flush_dir(dir, sync_up_to))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("remove", &path, error)),
    }
}

#[cfg(unix)]
mod platform {
    use std::fs::{DirBuilder, File, Metadata, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;

    use nix::errno::Errno;
    use nix::fcntl::OFlag;

    use super::{Kind, io_error};
    use crate::{Durability, StoreError};

    /// Any permission bit for group or others.
    const GROUP_OR_OTHER: u32 = 0o077;

    pub fn private_dir_builder() -> DirBuilder {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
    }

    /// Never follows a symlink, and never blocks on a planted FIFO.
    pub fn open_existing(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
            .open(path)
    }

    pub fn open_lock_file(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
            .open(path)
    }

    /// `O_NOFOLLOW` on a symlink fails with `ELOOP`.
    pub fn open_error(path: &Path, error: std::io::Error) -> StoreError {
        if error.raw_os_error() == Some(Errno::ELOOP as i32) {
            StoreError::UnprotectedPath {
                path: path.to_path_buf(),
            }
        } else {
            io_error("open", path, error)
        }
    }

    pub fn ensure_private(metadata: &Metadata, path: &Path, kind: Kind) -> Result<(), StoreError> {
        let file_type = metadata.file_type();
        let right_kind = match kind {
            Kind::Directory => file_type.is_dir(),
            Kind::File => file_type.is_file(),
        };
        if right_kind
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & GROUP_OR_OTHER == 0
        {
            Ok(())
        } else {
            Err(StoreError::UnprotectedPath {
                path: path.to_path_buf(),
            })
        }
    }

    /// A new connection file must have exactly owner read and write
    /// permissions before it is published.
    pub fn ensure_private_temporary(metadata: &Metadata, path: &Path) -> Result<(), StoreError> {
        ensure_private(metadata, path, Kind::File)?;
        if metadata.mode() & 0o777 == 0o600 {
            Ok(())
        } else {
            Err(StoreError::UnprotectedPath {
                path: path.to_path_buf(),
            })
        }
    }

    pub fn flush_dir(dir: &Path, sync_up_to: &Path) -> Durability {
        // Sync the connection directory and the parent entries of any
        // directories created when this store was opened.
        for ancestor in dir.ancestors() {
            if File::open(ancestor)
                .and_then(|directory| directory.sync_all())
                .is_err()
            {
                return Durability::Uncertain;
            }
            if ancestor == sync_up_to {
                return Durability::Durable;
            }
        }
        Durability::Uncertain
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{DirBuilder, File, Metadata, OpenOptions};
    use std::path::Path;

    use super::{Kind, io_error};
    use crate::{Durability, StoreError};

    pub fn private_dir_builder() -> DirBuilder {
        DirBuilder::new()
    }

    pub fn open_existing(path: &Path) -> std::io::Result<File> {
        File::open(path)
    }

    pub fn open_lock_file(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
    }

    pub fn open_error(path: &Path, error: std::io::Error) -> StoreError {
        io_error("open", path, error)
    }

    /// Outside Unix the files inherit the profile's access control and never
    /// hold a secret; only the kind is checked. Metadata read through a
    /// handle describes the reparse point's target.
    pub fn ensure_private(metadata: &Metadata, path: &Path, kind: Kind) -> Result<(), StoreError> {
        let right_kind = match kind {
            Kind::Directory => metadata.is_dir(),
            Kind::File => metadata.is_file(),
        };
        if right_kind {
            Ok(())
        } else {
            Err(StoreError::UnprotectedPath {
                path: path.to_path_buf(),
            })
        }
    }

    pub fn ensure_private_temporary(metadata: &Metadata, path: &Path) -> Result<(), StoreError> {
        ensure_private(metadata, path, Kind::File)
    }

    /// There is no directory flush on Windows without `unsafe` code.
    pub fn flush_dir(_dir: &Path, _sync_up_to: &Path) -> Durability {
        Durability::Uncertain
    }
}
