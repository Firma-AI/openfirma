//! Unix permission checks: an unsafe directory or file is rejected, never
//! repaired.

use std::os::unix::fs::{PermissionsExt as _, symlink};

use firma_connection_store::{ConnectionStore, SecretPolicy, StoreError};

use crate::common::{self, connection};

fn assert_unprotected<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    let error = result.expect_err("unsafe path accepted");
    let rendered = error.to_string();
    let StoreError::UnprotectedPath { path } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(
        rendered,
        format!("{} is not private to the current user", path.display())
    );
}

#[test]
fn a_group_writable_directory_is_rejected_and_left_unchanged() {
    let root = tempfile::tempdir().expect("temporary directory");
    let dir = root.path().join("firma");
    std::fs::create_dir(&dir).expect("create");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).expect("chmod");

    assert_unprotected(ConnectionStore::open(&dir));
    assert_eq!(common::mode(&dir), 0o770);
}

#[test]
fn a_relative_directory_is_rejected() {
    let error = ConnectionStore::open("firma").expect_err("relative directory accepted");

    assert!(
        matches!(error, StoreError::RelativeDirectory { .. }),
        "{error:?}"
    );
}

#[test]
fn a_symlinked_directory_is_rejected() {
    let root = tempfile::tempdir().expect("temporary directory");
    let target = root.path().join("elsewhere");
    std::fs::create_dir(&target).expect("create");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let dir = root.path().join("firma");
    symlink(&target, &dir).expect("symlink");

    assert_unprotected(ConnectionStore::open(&dir));
}

#[test]
fn a_directory_opened_earlier_is_checked_again_when_locking() {
    let (_root, store) = common::store();
    std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o750)).expect("chmod");

    assert_unprotected(store.exclusive());
}

#[test]
fn a_planted_or_readable_connection_file_is_rejected_before_it_is_read() {
    let (root, store) = common::store();
    let path = store.dir().join("connection.json");
    let outside = root.path().join("planted.json");
    std::fs::write(&outside, "{}").expect("write");
    symlink(&outside, &path).expect("symlink");
    let guard = store.exclusive().expect("lock");

    assert_unprotected(guard.load());
    let replaced = guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace symlink without reading it");
    assert!(replaced.stale_secret_left);
    assert_eq!(std::fs::read_to_string(&outside).expect("outside"), "{}");
    assert!(path.is_file());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");

    assert_unprotected(guard.load());
    let removed = guard
        .remove()
        .expect("remove unsafe file without reading it");
    assert!(matches!(
        removed,
        firma_connection_store::Removed::Existing {
            stale_secret_left: true,
            ..
        }
    ));
    assert!(!path.exists());

    symlink(&outside, &path).expect("symlink again");
    assert!(matches!(
        guard.remove().expect("remove symlink"),
        firma_connection_store::Removed::Existing {
            stale_secret_left: true,
            ..
        }
    ));
    assert_eq!(std::fs::read_to_string(&outside).expect("outside"), "{}");
}

#[test]
fn a_planted_or_readable_lock_file_is_rejected() {
    let (root, store) = common::store();
    let path = store.dir().join("connection.lock");
    let outside = root.path().join("planted.lock");
    std::fs::write(&outside, "").expect("write");
    symlink(&outside, &path).expect("symlink");

    assert_unprotected(store.shared());

    std::fs::remove_file(&path).expect("remove symlink");
    drop(store.shared().expect("lock"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");

    assert_unprotected(store.shared());
}

#[test]
fn a_permission_denied_connection_file_keeps_its_io_cause_and_can_be_replaced() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let (_root, store) = common::store();
    let guard = store.exclusive().expect("lock");
    let path = store.dir().join("connection.json");
    std::fs::write(&path, "{}").expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let error = guard.load().expect_err("unreadable file accepted");
    let StoreError::Io { action, source, .. } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(action, "open");
    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);

    let replaced = guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace unreadable file");
    assert!(replaced.stale_secret_left);
    assert_eq!(common::mode(&path), 0o600);
}

#[test]
fn an_oversized_record_is_rejected_before_allocation() {
    let (_root, store) = common::store();
    let path = store.dir().join("connection.json");
    let file = std::fs::File::create(&path).expect("create record");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    file.set_len(16 * 1024 * 1024 + 1).expect("extend record");

    let error = store
        .shared()
        .expect("lock")
        .load()
        .expect_err("large record accepted");
    assert!(matches!(error, StoreError::RecordTooLarge), "{error:?}");

    let guard = store.exclusive().expect("lock");
    let replaced = guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace oversized record");
    assert!(replaced.stale_secret_left);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open record")
        .set_len(16 * 1024 * 1024 + 1)
        .expect("extend record");
    let removed = guard.remove().expect("remove oversized record");
    assert!(matches!(
        removed,
        firma_connection_store::Removed::Existing {
            stale_secret_left: true,
            ..
        }
    ));
}
