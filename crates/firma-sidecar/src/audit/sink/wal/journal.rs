//! Single-writer journal with crash-safe replacement and independent JSONL records.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

use crate::audit::{AuditSinkError, ExecutionEvent};
use crate::authority_credentials::ResolvedSidecarCredentials;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    version: u8,
    endpoint: String,
    sidecar: Option<(String, String)>,
}

impl Scope {
    pub(super) fn new(endpoint: &str, credentials: Option<&ResolvedSidecarCredentials>) -> Self {
        Self {
            version: 1,
            endpoint: endpoint.to_owned(),
            sidecar: credentials.map(|c| (c.workspace_id.clone(), c.sidecar_id.clone())),
        }
    }
}

pub(super) struct Journal {
    path: PathBuf,
    max_bytes: u64,
    size: u64,
    records: VecDeque<Vec<u8>>,
    // Separate inode: replacing the queue must not release the writer lock.
    _lock: File,
}

impl Journal {
    pub(super) async fn open(
        path: PathBuf,
        max_bytes: u64,
        scope: Scope,
    ) -> Result<Self, AuditSinkError> {
        blocking(move || {
            let lock = private_file(&sibling(&path, ".lock"))?;
            lock.try_lock()
                .map_err(|_| failure("audit WAL is already in use"))?;
            let mut file = private_file(&path)?;
            let scope_path = sibling(&path, ".scope");
            match std::fs::read(&scope_path) {
                Ok(bytes) => {
                    let stored: Scope = serde_json::from_slice(&bytes)
                        .map_err(|_| failure("invalid audit WAL scope"))?;
                    if stored != scope {
                        return Err(failure(
                            "audit WAL destination does not match its stored scope",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if file.metadata()?.len() != 0 {
                        return Err(failure(
                            "nonempty legacy audit WAL has no scope; explicit migration is required",
                        ));
                    }
                    let bytes = serde_json::to_vec(&scope)
                        .map_err(|_| failure("cannot encode audit WAL scope"))?;
                    replace(&scope_path, &bytes)?;
                }
                Err(error) => return Err(error),
            }
            repair_tail(&mut file)?;
            let size = file.metadata()?.len();
            if size > max_bytes {
                return Err(failure(
                    "audit WAL exceeds configured capacity; retained without eviction",
                ));
            }
            let mut bytes = Vec::new();
            file.rewind()?;
            file.read_to_end(&mut bytes)?;
            let records = bytes
                .split_inclusive(|byte| *byte == b'\n')
                .map(<[u8]>::to_vec)
                .collect();
            sync_parent(&path)?;
            Ok(Self {
                path,
                max_bytes,
                size,
                records,
                _lock: lock,
            })
        })
        .await
    }

    pub(super) fn records(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.records.iter()
    }

    pub(super) async fn append(mut self, event: ExecutionEvent) -> Result<Self, AuditSinkError> {
        blocking(move || {
            let mut record =
                serde_json::to_vec(&event).map_err(|_| failure("cannot encode audit WAL event"))?;
            record.push(b'\n');
            if self.size.saturating_add(record.len() as u64) > self.max_bytes {
                return Err(failure(
                    "audit WAL capacity exhausted; pending records retained",
                ));
            }
            let mut file = private_file(&self.path)?;
            repair_tail(&mut file)?;
            file.seek(std::io::SeekFrom::End(0))?;
            file.write_all(&record)?;
            file.sync_all()?;
            self.size += record.len() as u64;
            self.records.push_back(record);
            Ok(self)
        })
        .await
    }

    /// Archive sync precedes reclamation. A crash between them may repeat the
    /// archive entry, but cannot discard the only retained copy.
    pub(super) async fn reject(
        &self,
        record: Vec<u8>,
        code: &str,
        reason: &str,
    ) -> Result<(), AuditSinkError> {
        let path = sibling(&self.path, ".rejected.jsonl");
        let code = code.to_owned();
        let reason = reason.to_owned();
        blocking(move || {
            let mut file = private_file(&path)?;
            repair_tail(&mut file)?;
            file.seek(std::io::SeekFrom::End(0))?;
            serde_json::to_writer(
                &mut file,
                &serde_json::json!({"record": record, "code": code, "reason": reason}),
            )
            .map_err(|_| failure("cannot write audit rejection archive"))?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            sync_parent(&path)?;
            Ok(())
        })
        .await
    }

    pub(super) async fn reclaim(mut self, count: usize) -> Result<Self, AuditSinkError> {
        if count == 0 {
            return Ok(self);
        }
        blocking(move || {
            let bytes: Vec<u8> = self.records.iter().skip(count).flatten().copied().collect();
            replace(&self.path, &bytes)?;
            self.records.drain(..count);
            self.size = bytes.len() as u64;
            Ok(self)
        })
        .await
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        options.mode(0o600);
        let file = options.open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        options.open(path)
    }
}

/// Restore a record boundary without deleting a possibly torn final record.
fn repair_tail(file: &mut File) -> std::io::Result<()> {
    if file.metadata()?.len() == 0 {
        return Ok(());
    }
    file.seek(std::io::SeekFrom::End(-1))?;
    let mut last = [0];
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    Ok(())
}

fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

fn failure(message: &str) -> std::io::Error {
    std::io::Error::other(message)
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, AuditSinkError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| AuditSinkError::ServerError(error.to_string()))?
        .map_err(|error| AuditSinkError::ServerError(error.to_string()))
}
