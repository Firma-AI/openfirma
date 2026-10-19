//! The operating system credential store, through `keyring-core`.
//!
//! Platform matrix: macOS uses the login Keychain, Windows the Credential
//! Manager, Linux the Secret Service over D-Bus.
//!
//! Nothing is initialized until an operation needs a native credential. Each
//! connection store owns its backend; it never changes `keyring-core`'s
//! process-wide default. No `keyring_core::Error` leaves this module: its `BadEncoding` and
//! `BadDataFormat` variants carry the raw credential bytes.

use std::fmt;
use std::sync::{Arc, OnceLock};

use keyring_core::{CredentialStore, Entry, Error};
use secrecy::SecretString;

use crate::NativeFailure;
use crate::id::ConnectionId;

const SERVICE: &str = "firma";

/// A credential-store outcome with no secret payload.
pub enum NativeError {
    /// The store cannot be used here.
    Unavailable(String),
    /// No credential exists for the connection.
    NoEntry,
    /// The store refused the operation.
    Failed(NativeFailure),
}

/// A credential backend selected for one connection store. A platform backend
/// is created only when the first native credential is used.
pub struct NativeStore {
    backend: OnceLock<Arc<CredentialStore>>,
}

impl fmt::Debug for NativeStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeStore")
    }
}

impl NativeStore {
    pub fn platform() -> Self {
        Self {
            backend: OnceLock::new(),
        }
    }

    pub fn supplied(backend: Arc<CredentialStore>) -> Self {
        let selected = OnceLock::new();
        // A new OnceLock cannot already be set.
        let _ = selected.set(backend);
        Self { backend: selected }
    }

    fn backend(&self) -> Result<Arc<CredentialStore>, NativeError> {
        if let Some(backend) = self.backend.get() {
            return Ok(Arc::clone(backend));
        }
        let backend = platform_store().map_err(|error| match classify(&error) {
            NativeError::Failed(failure) => NativeError::Unavailable(failure.to_string()),
            other => other,
        })?;
        let _ = self.backend.set(Arc::clone(&backend));
        Ok(Arc::clone(self.backend.get().unwrap_or(&backend)))
    }

    fn entry(&self, id: &ConnectionId) -> Result<Entry, NativeError> {
        self.backend()?
            .build(SERVICE, id.as_str(), None)
            .map_err(|error| classify(&error))
    }

    /// Stores `secret` as the credential of `id`.
    pub fn set(&self, id: &ConnectionId, secret: &str) -> Result<(), NativeError> {
        self.entry(id)?
            .set_password(secret)
            .map_err(|error| classify(&error))
    }

    /// Reads the credential of `id`.
    pub fn get(&self, id: &ConnectionId) -> Result<SecretString, NativeError> {
        self.entry(id)?
            .get_password()
            .map(SecretString::from)
            .map_err(|error| classify(&error))
    }

    /// Deletes the credential of `id`; a missing one is not an error.
    pub fn delete(&self, id: &ConnectionId) -> Result<(), NativeError> {
        match self
            .entry(id)?
            .delete_credential()
            .map_err(|error| classify(&error))
        {
            Err(NativeError::NoEntry) => Ok(()),
            other => other,
        }
    }
}

fn classify(error: &Error) -> NativeError {
    match error {
        Error::NoStorageAccess(_) | Error::PlatformFailure(_) => {
            NativeError::Unavailable("the platform credential store cannot be accessed".to_owned())
        }
        Error::NoDefaultStore => {
            NativeError::Unavailable("no credential store exists on this platform".to_owned())
        }
        Error::NoEntry => NativeError::NoEntry,
        Error::BadEncoding(_) | Error::BadDataFormat(..) => {
            NativeError::Failed(NativeFailure::BadData)
        }
        // `Ambiguous` contains entries whose Debug representation may include
        // credential data. Unknown future variants are treated the same way.
        Error::Ambiguous(_) => NativeError::Failed(NativeFailure::Other(
            "more than one credential matches the connection".to_owned(),
        )),
        _ => NativeError::Failed(NativeFailure::Other(
            "the credential store refused the operation".to_owned(),
        )),
    }
}

#[cfg(target_os = "macos")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(windows)]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(windows_native_keyring_store::Store::new()?)
}

#[cfg(target_os = "linux")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(zbus_secret_service_keyring_store::Store::new()?)
}
