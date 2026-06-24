//! Ed25519 (PASETO v4) signing-key generation shared by the
//! `firma authority generate-key` CLI and the per-run autostart supervisor.
//!
//! Keeping the on-disk format in one place guarantees every producer writes
//! exactly what [`crate::server`] reads back: raw PASETO v4 key bytes, secret
//! at `0o600` and public at `0o644`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use pasetors::keys::{AsymmetricKeyPair, Generate as _};
use pasetors::version4::V4;
use thiserror::Error;

/// Paths written by [`write_keypair`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeypairPaths {
    /// Secret key file (the input `path`).
    pub secret: PathBuf,
    /// Public key file (`path` with a `.pub` extension).
    pub public: PathBuf,
}

/// Failure modes for [`write_keypair`].
#[derive(Debug, Error)]
pub enum KeygenError {
    /// PASETO keypair generation failed.
    #[error("generate Ed25519 key pair: {0}")]
    Generate(String),
    /// Writing the secret or public key file failed.
    #[error("write {path}: {source}")]
    Write {
        /// File being written when the error occurred.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Generate a fresh Ed25519 (PASETO v4) keypair and write it to disk.
///
/// `path` receives the secret key; the public key is written alongside it at
/// `path` with the extension replaced by `.pub`. Both files are created with
/// `create_new` so an existing key is never silently overwritten — callers
/// that want to reuse an existing key must check for it first.
///
/// On Unix the secret is mode `0o600` and the public key `0o644`.
///
/// # Errors
///
/// - [`KeygenError::Generate`] when keypair generation fails.
/// - [`KeygenError::Write`] when either file cannot be created or written.
pub fn write_keypair(path: &Path) -> Result<KeypairPaths, KeygenError> {
    let mut secret_opts = std::fs::OpenOptions::new();
    secret_opts.create_new(true).write(true);
    let mut public_opts = std::fs::OpenOptions::new();
    public_opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        secret_opts.mode(0o600);
        public_opts.mode(0o644);
    }

    let kp =
        AsymmetricKeyPair::<V4>::generate().map_err(|e| KeygenError::Generate(e.to_string()))?;

    let mut secret_file = secret_opts
        .open(path)
        .map_err(|source| KeygenError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    secret_file
        .write_all(kp.secret.as_bytes())
        .map_err(|source| KeygenError::Write {
            path: path.to_path_buf(),
            source,
        })?;

    let pub_path = path.with_extension("pub");
    let mut public_file = public_opts
        .open(&pub_path)
        .map_err(|source| KeygenError::Write {
            path: pub_path.clone(),
            source,
        })?;
    public_file
        .write_all(kp.public.as_bytes())
        .map_err(|source| KeygenError::Write {
            path: pub_path.clone(),
            source,
        })?;

    Ok(KeypairPaths {
        secret: path.to_path_buf(),
        public: pub_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_secret_and_public() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("authority.key");

        let paths = write_keypair(&key).expect("write keypair");

        assert_eq!(paths.secret, key);
        assert_eq!(paths.public, dir.path().join("authority.pub"));
        assert!(paths.secret.exists());
        assert!(paths.public.exists());
    }

    #[test]
    fn refuses_to_overwrite_existing_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("authority.key");
        fs_err::write(&key, b"existing").expect("seed key");

        let err = write_keypair(&key).expect_err("must not overwrite");
        assert!(matches!(err, KeygenError::Write { .. }));
        assert_eq!(fs_err::read(&key).expect("read key"), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn secret_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("authority.key");
        write_keypair(&key).expect("write keypair");

        let mode = fs_err::metadata(&key).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
