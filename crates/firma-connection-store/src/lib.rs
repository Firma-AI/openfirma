//! Local storage for the `firma login` connection: the Control Plane origin,
//! the Workspace and Membership, and optionally one opaque secret, kept in the
//! operating system's credential store unless the caller opts into a
//! user-private file on Unix.
//!
//! One installation holds one connection, in `connection.json` inside the
//! directory from [`default_dir`]. Every read and write happens under an
//! advisory lock on `connection.lock` in the same directory, taken through
//! [`ConnectionStore::shared`] or [`ConnectionStore::exclusive`], so separate
//! processes never observe a half-written connection.
//!
//! Each store owns its credential backend. The platform backend is created on
//! first native use; embedders may supply a backend for one store without
//! changing `keyring-core`'s process-wide default.
//!
//! The store never talks to the Control Plane: revoking a superseded secret
//! there is the caller's job.

mod error;
mod file;
mod id;
mod location;
mod model;
mod native;
mod record;
mod store;

pub use error::{NativeFailure, StoreError};
pub use location::default_dir;
pub use model::{
    Backend, Connection, ConnectionSecret, Durability, LoadedSecret, OriginMode, Removed, Replaced,
    SavedConnection, SecretPolicy,
};
pub use store::{ConnectionStore, ReadGuard, WriteGuard};
