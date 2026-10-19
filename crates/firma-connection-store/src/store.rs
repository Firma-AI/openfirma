//! The connection store, its locks, and the replace/remove protocol.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyring_core::CredentialStore;
use zeroize::Zeroizing;

use crate::id::ConnectionId;
use crate::native::{NativeError, NativeStore};
use crate::record::{self, Record, SecretField, StoredSecret};
use crate::{
    Backend, Connection, ConnectionSecret, LoadedSecret, Removed, Replaced, SavedConnection,
    SecretPolicy, StoreError, file,
};

/// The private directory that holds the connection.
#[derive(Clone, Debug)]
pub struct ConnectionStore {
    dir: PathBuf,
    sync_up_to: PathBuf,
    native: Arc<NativeStore>,
}

impl ConnectionStore {
    /// Opens `dir`, creating it with mode `0700` (and missing parents with
    /// default permissions) when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RelativeDirectory`] for a relative `dir`,
    /// [`StoreError::UnprotectedPath`] when `dir` is a symlink,
    /// belongs to another user or is accessible to group or others (Unix),
    /// and [`StoreError::Io`] when it cannot be created or inspected.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_with_backend(dir.into(), NativeStore::platform())
    }

    /// Opens an existing private directory without creating anything.
    /// Returns `None` when the directory does not exist.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_existing(dir: impl Into<PathBuf>) -> Result<Option<Self>, StoreError> {
        let dir = dir.into();
        if !dir.is_absolute() {
            return Err(StoreError::RelativeDirectory { path: dir });
        }
        if !file::existing_dir(&dir)? {
            return Ok(None);
        }
        Ok(Some(Self {
            sync_up_to: dir.clone(),
            dir,
            native: Arc::new(NativeStore::platform()),
        }))
    }

    /// Opens `dir` with the supplied credential backend. The backend is used
    /// only for native secrets and belongs to this store instance.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_with_native_store(
        dir: impl Into<PathBuf>,
        native: Arc<CredentialStore>,
    ) -> Result<Self, StoreError> {
        Self::open_with_backend(dir.into(), NativeStore::supplied(native))
    }

    fn open_with_backend(dir: PathBuf, native: NativeStore) -> Result<Self, StoreError> {
        if !dir.is_absolute() {
            return Err(StoreError::RelativeDirectory { path: dir });
        }
        let sync_up_to = file::prepare_dir(&dir)?;
        Ok(Self {
            dir,
            sync_up_to,
            native: Arc::new(native),
        })
    }

    /// The connection directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Waits for a shared lock: other readers may hold it at the same time,
    /// writers wait. The guard owns its lock handle and a copy of the store,
    /// so it can move to another thread. Locks are not reentrant: taking a
    /// second guard for the same directory while holding one can deadlock.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory or the lock file is not private,
    /// or the lock cannot be taken.
    pub fn shared(&self) -> Result<ReadGuard, StoreError> {
        let lock = self.lock(fs2::FileExt::lock_shared)?;
        Ok(ReadGuard {
            store: self.clone(),
            _lock: lock,
        })
    }

    /// Waits for the exclusive lock. Every change goes through it. Like
    /// [`Self::shared`], this is not reentrant.
    ///
    /// # Errors
    ///
    /// As [`Self::shared`].
    pub fn exclusive(&self) -> Result<WriteGuard, StoreError> {
        let lock = self.lock(fs2::FileExt::lock_exclusive)?;
        Ok(WriteGuard {
            store: self.clone(),
            _lock: lock,
        })
    }

    /// Each acquisition opens its own handle, so the lock belongs to exactly
    /// one open file and is released when the guard drops it.
    fn lock(&self, acquire: fn(&File) -> std::io::Result<()>) -> Result<File, StoreError> {
        file::check_dir(&self.dir)?;
        let lock = file::open_lock(&self.dir)?;
        acquire(&lock).map_err(|source| StoreError::Lock {
            path: self.dir.join(file::LOCK_FILE),
            source,
        })?;
        Ok(lock)
    }

    fn load(&self) -> Result<Option<SavedConnection>, StoreError> {
        let Some(record) = file::read(&self.dir)? else {
            return Ok(None);
        };
        let secret = match record.secret {
            StoredSecret::None => LoadedSecret::None,
            StoredSecret::File(secret) => LoadedSecret::File(ConnectionSecret::new(secret)),
            StoredSecret::Native => LoadedSecret::Native(ConnectionSecret::new(
                self.native.get(&record.id).map_err(native_error)?,
            )),
        };
        Ok(Some(SavedConnection {
            connection: record.connection,
            secret,
        }))
    }

    /// Finds the native credential referenced by the current record. An
    /// unreadable record may own one that cannot be identified or retired.
    fn current_native_id(&self) -> Result<PreviousNative, StoreError> {
        match file::read(&self.dir) {
            Ok(Some(Record {
                id,
                secret: StoredSecret::Native,
                ..
            })) => Ok(PreviousNative::Known(id)),
            Ok(_) | Err(StoreError::PlaintextFileUnsupported) => Ok(PreviousNative::None),
            Err(
                StoreError::CorruptConnection { .. }
                | StoreError::RecordTooLarge
                | StoreError::UnprotectedPath { .. },
            ) => Ok(PreviousNative::Unknown),
            Err(StoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Ok(PreviousNative::Unknown)
            }
            Err(error) => Err(error),
        }
    }

    fn replace(
        &self,
        connection: &Connection,
        secret: Option<&ConnectionSecret>,
        policy: SecretPolicy,
    ) -> Result<Replaced, StoreError> {
        let previous = self.current_native_id()?;
        let id = ConnectionId::generate()?;
        let (bytes, backend) = prepare(&self.native, &id, connection, secret, policy)?;
        let durability = file::write(&self.dir, &self.sync_up_to, &bytes).inspect_err(|_| {
            if backend == Backend::Native {
                // Not committed: the new credential belongs to nothing.
                let _ = self.native.delete(&id);
            }
        })?;
        Ok(Replaced {
            backend,
            durability,
            stale_secret_left: previous.stale_secret_left_after_retirement(&self.native),
        })
    }

    fn remove(&self) -> Result<Removed, StoreError> {
        let previous = self.current_native_id()?;
        Ok(
            file::remove(&self.dir, &self.sync_up_to)?.map_or(Removed::Nothing, |durability| {
                Removed::Existing {
                    durability,
                    stale_secret_left: previous.stale_secret_left_after_retirement(&self.native),
                }
            }),
        )
    }
}

/// Encodes the new record and stores its secret. Records are encoded before
/// the native credential is written, so nothing after a successful write
/// can fail before the commit except the file write itself.
fn prepare(
    native: &NativeStore,
    id: &ConnectionId,
    connection: &Connection,
    secret: Option<&ConnectionSecret>,
    policy: SecretPolicy,
) -> Result<(Zeroizing<Vec<u8>>, Backend), StoreError> {
    let Some(secret) = secret else {
        return Ok((
            record::encode(id, connection, SecretField::None)?,
            Backend::None,
        ));
    };
    // Encoded up front even if the secret ends up in the file: after a
    // successful `set` nothing but the file write may fail.
    let native_record = record::encode(id, connection, SecretField::Native)?;
    match native.set(id, secret.expose()) {
        Ok(()) => Ok((native_record, Backend::Native)),
        Err(NativeError::Unavailable(reason)) => match policy {
            SecretPolicy::NativeOnly => Err(StoreError::NativeStorageUnavailable { reason }),
            SecretPolicy::AllowPlaintextFile => prepare_file(id, connection, secret),
        },
        Err(error) => Err(native_error(error)),
    }
}

fn prepare_file(
    id: &ConnectionId,
    connection: &Connection,
    secret: &ConnectionSecret,
) -> Result<(Zeroizing<Vec<u8>>, Backend), StoreError> {
    if !cfg!(unix) {
        return Err(StoreError::PlaintextFileUnsupported);
    }
    Ok((
        record::encode(
            id,
            connection,
            SecretField::File {
                value: secret.expose(),
            },
        )?,
        Backend::File,
    ))
}

/// Identifies the credential that needs retirement after the commit point.
enum PreviousNative {
    None,
    Known(ConnectionId),
    /// The old record may refer to a credential that cannot be identified.
    Unknown,
}

impl PreviousNative {
    /// Retires the previous native credential and reports whether it may remain.
    fn stale_secret_left_after_retirement(self, native: &NativeStore) -> bool {
        match self {
            Self::None => false,
            Self::Known(id) => native.delete(&id).is_err(),
            Self::Unknown => true,
        }
    }
}

fn native_error(error: NativeError) -> StoreError {
    match error {
        NativeError::Unavailable(reason) => StoreError::NativeStorageUnavailable { reason },
        NativeError::NoEntry => StoreError::SecretMissing,
        NativeError::Failed(failure) => StoreError::Native(failure),
    }
}

/// A shared lock on the connection.
#[derive(Debug)]
pub struct ReadGuard {
    store: ConnectionStore,
    _lock: File,
}

impl ReadGuard {
    /// Reads the saved connection and its secret, or `None` when there is
    /// none.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptConnection`] for an invalid file,
    /// [`StoreError::SecretMissing`] when its native credential is gone,
    /// [`StoreError::PlaintextFileUnsupported`] for a file secret outside
    /// Unix, and credential-store or filesystem errors.
    pub fn load(&self) -> Result<Option<SavedConnection>, StoreError> {
        self.store.load()
    }
}

/// The exclusive lock on the connection.
#[derive(Debug)]
pub struct WriteGuard {
    store: ConnectionStore,
    _lock: File,
}

impl WriteGuard {
    /// Reads the saved connection, as [`ReadGuard::load`].
    ///
    /// # Errors
    ///
    /// As [`ReadGuard::load`].
    pub fn load(&self) -> Result<Option<SavedConnection>, StoreError> {
        self.store.load()
    }

    /// Replaces the saved connection with `connection` and `secret`.
    ///
    /// A secret goes to the operating system credential store; when that is
    /// unavailable, `policy` decides between failing and a `0600` file
    /// (Unix only). The new record is committed by an atomic rename; after
    /// it, the previous record's native credential is deleted best effort.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NativeStorageUnavailable`] under
    /// [`SecretPolicy::NativeOnly`] when the credential store is unavailable,
    /// [`StoreError::PlaintextFileUnsupported`] when a file would be needed
    /// outside Unix, and credential-store or filesystem errors. On error the
    /// previous connection is unchanged.
    pub fn replace(
        &self,
        connection: &Connection,
        secret: Option<&ConnectionSecret>,
        policy: SecretPolicy,
    ) -> Result<Replaced, StoreError> {
        self.store.replace(connection, secret, policy)
    }

    /// Removes the saved connection and, after that, its native credential
    /// best effort.
    ///
    /// # Errors
    ///
    /// Returns filesystem errors; on error nothing was removed.
    pub fn remove(&self) -> Result<Removed, StoreError> {
        self.store.remove()
    }
}
