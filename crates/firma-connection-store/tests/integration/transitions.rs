//! Retiring a native credential when the record that owned it is replaced
//! or removed, and loading records a crash could bring back.

use firma_connection_store::{Backend, Removed, SecretPolicy, StoreError};

use crate::common::{self, connection};

#[test]
fn operations_on_records_without_a_native_secret_never_touch_the_credential_store() {
    let keyring = common::keyring();
    let refusing = common::refusing(&keyring, common::unavailable);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = store.exclusive().expect("lock");

    guard
        .replace(&connection("a.example"), None, SecretPolicy::NativeOnly)
        .expect("replace a");
    guard
        .replace(&connection("b.example"), None, SecretPolicy::NativeOnly)
        .expect("replace b");
    guard.load().expect("load").expect("saved connection");
    guard.remove().expect("remove");

    assert_eq!(refusing.builds(), 0);
}

#[test]
fn replacing_a_native_record_with_one_without_a_secret_deletes_the_old_secret() {
    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");

    let replaced = guard
        .replace(&connection("b.example"), None, SecretPolicy::NativeOnly)
        .expect("replace b");

    assert_eq!(replaced.backend, Backend::None);
    assert!(!replaced.stale_secret_left);
    assert_eq!(common::live_credentials(&native), 0);
}

#[cfg(unix)]
#[test]
fn a_file_record_that_replaces_a_native_one_reports_the_secret_it_could_not_delete() {
    use crate::common::secret;

    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");
    let previous = common::native_entry(&keyring, store.dir());
    // The credential store goes away between the two logins.
    common::refusing(&keyring, common::unavailable);

    let replaced = guard
        .replace(
            &connection("b.example"),
            Some(&secret("secret-b")),
            SecretPolicy::AllowPlaintextFile,
        )
        .expect("replace b");

    assert_eq!(replaced.backend, Backend::File);
    assert!(replaced.stale_secret_left);
    assert!(previous.get_password().is_ok(), "left behind, as reported");
    assert_eq!(common::live_credentials(&native), 1);
}

#[test]
fn replace_and_remove_commit_even_when_the_old_secret_cannot_be_deleted() {
    let keyring = common::keyring();
    common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");
    common::refusing(&keyring, common::unavailable);
    let second = connection("b.example");

    let replaced = guard
        .replace(&second, None, SecretPolicy::NativeOnly)
        .expect("replace b");

    assert!(replaced.stale_secret_left);
    assert_eq!(
        guard.load().expect("load").expect("saved").connection,
        second
    );

    common::mock(&keyring);
    drop(guard);
    let guard = common::with_native(&store, "c.example", "secret-c");
    common::refusing(&keyring, common::unavailable);

    let removed = guard.remove().expect("remove");

    assert!(matches!(
        removed,
        Removed::Existing {
            stale_secret_left: true,
            ..
        }
    ));
    assert!(guard.load().expect("load").is_none());
}

#[test]
fn a_recovered_native_record_whose_secret_is_gone_is_reported_missing() {
    let keyring = common::keyring();
    common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");
    common::native_entry(&keyring, store.dir())
        .delete_credential()
        .expect("delete credential");

    let error = guard.load().expect_err("secret gone");

    assert!(matches!(error, StoreError::SecretMissing), "{error:?}");
}

#[test]
fn replacing_or_removing_a_corrupt_record_reports_the_unretired_secret() {
    use crate::common::secret;

    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");
    std::fs::write(store.dir().join("connection.json"), b"invalid record").expect("corrupt");

    let replaced = guard
        .replace(&connection("b.example"), None, SecretPolicy::NativeOnly)
        .expect("replace corrupt record");
    assert!(replaced.stale_secret_left);
    assert_eq!(common::live_credentials(&native), 1);

    guard
        .replace(
            &connection("c.example"),
            Some(&secret("secret-c")),
            SecretPolicy::NativeOnly,
        )
        .expect("save c");
    std::fs::write(store.dir().join("connection.json"), b"invalid record").expect("corrupt");
    let removed = guard.remove().expect("remove corrupt record");
    assert!(matches!(
        removed,
        Removed::Existing {
            stale_secret_left: true,
            ..
        }
    ));
    assert_eq!(common::live_credentials(&native), 2);
}

#[cfg(unix)]
#[test]
fn a_failed_write_deletes_the_new_secret_and_keeps_the_old_connection() {
    use std::os::unix::fs::PermissionsExt as _;

    use crate::common::secret;

    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: root ignores the read-only directory this test relies on");
        return;
    }
    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");
    let first = guard.load().expect("load").expect("saved").connection;
    // A read-only directory: the new credential is stored, then the
    // temporary file cannot be created.
    std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o500)).expect("chmod");

    let result = guard.replace(
        &connection("b.example"),
        Some(&secret("secret-b")),
        SecretPolicy::NativeOnly,
    );

    std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod back");
    let error = result.expect_err("temporary file refused");
    assert!(matches!(error, StoreError::Io { .. }), "{error:?}");
    assert_eq!(
        common::live_credentials(&native),
        1,
        "only secret-a is left"
    );
    let loaded = guard.load().expect("load").expect("saved connection");
    assert_eq!(loaded.connection, first);
    assert_eq!(loaded.secret.secret().expect("secret").expose(), "secret-a");
}
