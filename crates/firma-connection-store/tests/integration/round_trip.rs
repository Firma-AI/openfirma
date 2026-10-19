use firma_connection_store::{Backend, Removed, SecretPolicy, StoreError};

use crate::common::{self, connection, secret};

#[test]
fn opening_a_missing_store_for_read_only_use_does_not_create_it() {
    let root = tempfile::tempdir().expect("temporary directory");
    let dir = root.path().join("missing").join("firma");

    assert!(
        firma_connection_store::ConnectionStore::open_existing(&dir)
            .expect("inspect missing store")
            .is_none()
    );
    assert!(!dir.parent().expect("parent").exists());
}

#[test]
fn a_connection_without_a_secret_round_trips() {
    let (_root, store) = common::store();
    let saved = connection("cp.example");
    let guard = store.exclusive().expect("lock");

    let replaced = guard
        .replace(&saved, None, SecretPolicy::NativeOnly)
        .expect("replace");

    assert_eq!(replaced.backend, Backend::None);
    assert!(!replaced.stale_secret_left);
    let loaded = guard.load().expect("load").expect("saved connection");
    assert_eq!(loaded.connection, saved);
    assert_eq!(loaded.secret.backend(), Backend::None);
}

#[test]
fn a_secret_round_trips_through_the_native_store_and_stays_out_of_the_file() {
    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let saved = connection("cp.example");
    let guard = store.exclusive().expect("lock");

    let replaced = guard
        .replace(&saved, Some(&secret("refresh-1")), SecretPolicy::NativeOnly)
        .expect("replace");

    assert_eq!(replaced.backend, Backend::Native);
    let loaded = guard.load().expect("load").expect("saved connection");
    assert_eq!(loaded.connection, saved);
    assert_eq!(loaded.secret.backend(), Backend::Native);
    assert_eq!(
        loaded.secret.secret().expect("secret").expose(),
        "refresh-1"
    );
    assert_eq!(common::live_credentials(&native), 1);
    let file = std::fs::read_to_string(store.dir().join("connection.json")).expect("file");
    assert!(!file.contains("refresh-1"));
}

#[test]
fn native_backends_are_isolated_per_store_without_changing_the_process_default() {
    let previous_default = keyring_core::get_default_store();
    let root = tempfile::tempdir().expect("temporary directory");
    let first_backend = keyring_core::mock::Store::new().expect("first backend");
    let second_backend = keyring_core::mock::Store::new().expect("second backend");
    let first = firma_connection_store::ConnectionStore::open_with_native_store(
        root.path().join("first"),
        first_backend.clone(),
    )
    .expect("first store");
    let second = firma_connection_store::ConnectionStore::open_with_native_store(
        root.path().join("second"),
        second_backend.clone(),
    )
    .expect("second store");

    let first_guard = common::with_native(&first, "first.example", "secret-first");
    let second_guard = common::with_native(&second, "second.example", "secret-second");

    assert_eq!(
        first_guard
            .load()
            .expect("first load")
            .expect("first connection")
            .secret
            .secret()
            .expect("first secret")
            .expose(),
        "secret-first"
    );
    assert_eq!(
        second_guard
            .load()
            .expect("second load")
            .expect("second connection")
            .secret
            .secret()
            .expect("second secret")
            .expose(),
        "secret-second"
    );
    assert_eq!(common::live_credentials(&first_backend), 1);
    assert_eq!(common::live_credentials(&second_backend), 1);

    let current_default = keyring_core::get_default_store();
    assert!(match (previous_default, current_default) {
        (None, None) => true,
        (Some(before), Some(after)) => std::sync::Arc::ptr_eq(&before, &after),
        _ => false,
    });
}

#[test]
fn a_new_login_replaces_the_previous_one_and_deletes_its_secret() {
    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "a.example", "secret-a");
    let previous = common::native_entry(&keyring, store.dir());
    let second = connection("b.example");

    guard
        .replace(&second, Some(&secret("secret-b")), SecretPolicy::NativeOnly)
        .expect("replace b");

    let loaded = guard.load().expect("load").expect("saved connection");
    assert_eq!(loaded.connection, second);
    assert_eq!(loaded.secret.secret().expect("secret").expose(), "secret-b");
    assert!(matches!(
        previous.get_password(),
        Err(keyring_core::Error::NoEntry)
    ));
    assert_eq!(common::live_credentials(&native), 1);
}

#[test]
fn remove_deletes_the_connection_and_its_secret_and_is_idempotent() {
    let keyring = common::keyring();
    let native = common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "cp.example", "refresh-1");

    let first = guard.remove().expect("remove");
    let second = guard.remove().expect("remove again");

    assert!(matches!(
        first,
        Removed::Existing {
            stale_secret_left: false,
            ..
        }
    ));
    assert_eq!(second, Removed::Nothing);
    assert!(guard.load().expect("load").is_none());
    assert_eq!(common::live_credentials(&native), 0);
}

#[cfg(unix)]
#[test]
fn a_committed_change_on_unix_is_durable() {
    use firma_connection_store::Durability;

    let (_root, store) = common::store();
    let guard = store.exclusive().expect("lock");

    let replaced = guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace");

    assert_eq!(replaced.durability, Durability::Durable);
}

#[cfg(unix)]
#[test]
fn an_existing_store_does_not_sync_unrelated_ancestors() {
    use std::os::unix::fs::PermissionsExt as _;

    use firma_connection_store::{ConnectionStore, Durability};

    let (root, created) = common::store();
    let store = ConnectionStore::open(created.dir()).expect("reopen existing store");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o711))
        .expect("restrict parent reads");

    let replaced = store
        .exclusive()
        .expect("lock")
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace");

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions");
    assert_eq!(replaced.durability, Durability::Durable);
}

#[test]
fn an_invalid_file_is_reported_without_its_contents() {
    let (_root, store) = common::store();
    let guard = store.exclusive().expect("lock");
    guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace");
    let path = store.dir().join("connection.json");
    let valid = std::fs::read_to_string(&path).expect("file");
    let id = serde_json::from_str::<serde_json::Value>(&valid).expect("json")["connection_id"]
        .as_str()
        .expect("id")
        .to_owned();

    for (label, contents) in [
        (
            "version",
            valid.replace("\"version\": 1", "\"version\": 99"),
        ),
        (
            "unknown field",
            valid.replacen('{', "{\n  \"sentinel-field\": \"sentinel-value\",", 1),
        ),
        ("connection id", valid.replace(&id, "sentinel-id")),
        (
            "origin",
            valid.replace("https://cp.example/", "sentinel origin"),
        ),
        ("not JSON", "sentinel {".to_owned()),
        #[cfg(unix)]
        (
            "file secret in an unsupported version",
            valid.replace("\"version\": 1", "\"version\": 99").replace(
                "\"backend\": \"none\"",
                "\"backend\": \"file\",\n    \"value\": \"sentinel-secret\"",
            ),
        ),
    ] {
        std::fs::write(&path, contents).expect("rewrite");
        let error = guard.load().expect_err(label);
        assert!(
            matches!(error, StoreError::CorruptConnection { .. }),
            "{label}: {error:?}"
        );
        for rendering in [error.to_string(), format!("{error:?}")] {
            assert!(!rendering.contains("sentinel"), "{label}: {rendering}");
        }
    }
}
