//! The public values the store saves and returns.

use std::fmt;

use firma_identifiers::{MembershipId, WorkspaceId};
use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

/// How the saved origin was validated at login; callers re-validate the
/// origin in the same mode after loading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginMode {
    /// HTTPS origins only.
    Production,
    /// Also `http` on a loopback address, for local development.
    DevelopmentLoopback,
}

/// Where a `firma login` connection points and which Membership it acts as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// The Control Plane origin, as validated by the login that saved it.
    pub origin: Url,
    /// How the origin was validated.
    pub origin_mode: OriginMode,
    /// The approved Workspace.
    pub workspace_id: WorkspaceId,
    /// The user's Membership in that Workspace.
    pub membership_id: MembershipId,
}

/// The one opaque secret kept with a connection. Never formatted.
pub struct ConnectionSecret(SecretString);

impl ConnectionSecret {
    /// Wraps a secret.
    #[must_use]
    pub const fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    /// Returns the wrapped secret without exposing its text.
    #[must_use]
    pub const fn as_secret(&self) -> &SecretString {
        &self.0
    }

    /// Returns the secret text.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ConnectionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionSecret([REDACTED])")
    }
}

/// Where a new secret may be stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SecretPolicy {
    /// Only the operating system credential store.
    #[default]
    NativeOnly,
    /// The credential store, or, when it is unavailable and only on Unix, a
    /// `0600` file in the private connection directory. The user must have
    /// asked for this explicitly.
    AllowPlaintextFile,
}

/// Where the secret of a saved connection lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Backend {
    /// The connection has no secret.
    None,
    /// The operating system credential store.
    Native,
    /// The connection file itself (Unix only, after an explicit opt-in).
    File,
}

/// The secret of a loaded connection, with where it was read from.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoadedSecret {
    /// The connection has no secret.
    None,
    /// Read from the operating system credential store.
    Native(ConnectionSecret),
    /// Read from the connection file.
    File(ConnectionSecret),
}

impl LoadedSecret {
    /// The secret, when there is one.
    #[must_use]
    pub const fn secret(&self) -> Option<&ConnectionSecret> {
        match self {
            Self::None => None,
            Self::Native(secret) | Self::File(secret) => Some(secret),
        }
    }

    /// Where the secret was read from.
    #[must_use]
    pub const fn backend(&self) -> Backend {
        match self {
            Self::None => Backend::None,
            Self::Native(_) => Backend::Native,
            Self::File(_) => Backend::File,
        }
    }
}

/// A connection read back from disk.
#[derive(Debug)]
pub struct SavedConnection {
    /// The connection.
    pub connection: Connection,
    /// Its secret.
    pub secret: LoadedSecret,
}

/// Whether a committed change is known to survive a crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// The directory entries in the connection path were flushed.
    Durable,
    /// The change is visible but a directory entry was not flushed
    /// (always the case on Windows); a crash may bring back the previous
    /// state.
    Uncertain,
}

/// The outcome of a committed replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Replaced {
    /// Where the new secret was stored.
    pub backend: Backend,
    /// Whether the replacement is known to survive a crash.
    pub durability: Durability,
    /// A superseded native secret may remain because deletion failed or the
    /// old record could not be decoded.
    pub stale_secret_left: bool,
}

/// The outcome of a removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Removed {
    /// There was no saved connection.
    Nothing,
    /// The saved connection was removed.
    Existing {
        /// Whether the removal is known to survive a crash.
        durability: Durability,
        /// A native secret may remain because deletion failed or the old
        /// record could not be decoded.
        stale_secret_left: bool,
    },
}
