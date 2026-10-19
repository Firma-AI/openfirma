//! Fixtures.
//!
//! Every fixture gets its own credential backend, so native tests can run in
//! parallel without changing `keyring-core`'s process default.

use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use firma_connection_store::{
    Connection, ConnectionSecret, ConnectionStore, OriginMode, SecretPolicy, WriteGuard,
};
use firma_identifiers::{MembershipId, WorkspaceId};
use keyring_core::api::CredentialStoreApi;
use keyring_core::{CredentialStore, Entry, Error, mock};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

pub struct Keyring {
    backend: Arc<SwitchableStore>,
}

pub fn keyring() -> Keyring {
    let initial = mock::Store::new().expect("initial mock store");
    Keyring {
        backend: Arc::new(SwitchableStore {
            current: RwLock::new(initial),
        }),
    }
}

/// Selects an in-memory mock for this fixture.
pub fn mock(keyring: &Keyring) -> Arc<mock::Store> {
    let store = mock::Store::new().expect("mock store");
    keyring.backend.select(store.clone());
    store
}

/// Installs a store that refuses every entry, counting the attempts.
pub fn refusing(keyring: &Keyring, error: fn() -> Error) -> Arc<RefusingStore> {
    let store = Arc::new(RefusingStore {
        builds: AtomicUsize::new(0),
        error,
    });
    keyring.backend.select(store.clone());
    store
}

struct SwitchableStore {
    current: RwLock<Arc<CredentialStore>>,
}

impl SwitchableStore {
    fn select(&self, backend: Arc<CredentialStore>) {
        *self.current.write().expect("backend lock") = backend;
    }
}

impl CredentialStoreApi for SwitchableStore {
    fn vendor(&self) -> String {
        "connection store integration tests".to_owned()
    }

    fn id(&self) -> String {
        "fixture".to_owned()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<Entry> {
        self.current
            .read()
            .expect("backend lock")
            .build(service, user, modifiers)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn connection(host: &str) -> Connection {
    Connection {
        origin: Url::parse(&format!("https://{host}/")).expect("origin"),
        origin_mode: OriginMode::Production,
        workspace_id: WorkspaceId::generate(),
        membership_id: MembershipId::generate(),
    }
}

pub fn secret(value: &str) -> ConnectionSecret {
    ConnectionSecret::new(SecretString::from(value.to_owned()))
}

/// A store in a fresh private directory, plus the guard that deletes it.
pub fn store() -> (TempDir, ConnectionStore) {
    let root = tempfile::tempdir().expect("temporary directory");
    let store = ConnectionStore::open(root.path().join("firma")).expect("open store");
    (root, store)
}

pub fn store_with_keyring(keyring: &Keyring) -> (TempDir, ConnectionStore) {
    let root = tempfile::tempdir().expect("temporary directory");
    let store =
        ConnectionStore::open_with_native_store(root.path().join("firma"), keyring.backend.clone())
            .expect("open store");
    (root, store)
}

/// An exclusive guard on a store whose connection to `host` keeps
/// `value` in the native store.
pub fn with_native(store: &ConnectionStore, host: &str, value: &str) -> WriteGuard {
    let guard = store.exclusive().expect("lock");
    guard
        .replace(
            &connection(host),
            Some(&secret(value)),
            SecretPolicy::NativeOnly,
        )
        .expect("replace");
    guard
}

/// Native credentials still holding a secret in the mock.
pub fn live_credentials(store: &mock::Store) -> usize {
    let credentials = store.inner.lock().expect("mock store lock");
    credentials
        .borrow()
        .iter()
        .filter(|credential| {
            Entry::new_with_credential(Arc::clone(credential) as _)
                .get_secret()
                .is_ok()
        })
        .count()
}

/// The native entry of the saved connection.
pub fn native_entry(keyring: &Keyring, dir: &Path) -> Entry {
    let bytes = std::fs::read(dir.join("connection.json")).expect("connection file");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("connection json");
    let id = value["connection_id"].as_str().expect("connection id");
    keyring.backend.build("firma", id, None).expect("entry")
}

#[cfg(unix)]
pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[derive(Debug)]
pub struct RefusingStore {
    builds: AtomicUsize,
    error: fn() -> Error,
}

impl RefusingStore {
    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }
}

impl CredentialStoreApi for RefusingStore {
    fn vendor(&self) -> String {
        "refusing test store".to_owned()
    }

    fn id(&self) -> String {
        "refusing".to_owned()
    }

    fn build(
        &self,
        _service: &str,
        _user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<Entry> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        Err((self.error)())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn unavailable() -> Error {
    Error::NoStorageAccess(Box::new(std::io::Error::other(
        "credential store is locked",
    )))
}

pub fn rejected() -> Error {
    Error::Invalid("user".to_owned(), "rejected by the test store".to_owned())
}
