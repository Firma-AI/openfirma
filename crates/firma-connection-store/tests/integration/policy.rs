use firma_connection_store::{SecretPolicy, StoreError};

use crate::common::{self, connection, secret};

#[test]
fn native_only_refuses_to_store_a_secret_without_a_credential_store() {
    let keyring = common::keyring();
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = store.exclusive().expect("lock");
    guard
        .replace(&connection("a.example"), None, SecretPolicy::NativeOnly)
        .expect("replace a");
    let path = store.dir().join("connection.json");
    let before = std::fs::read(&path).expect("file");
    common::refusing(&keyring, common::unavailable);

    let error = guard
        .replace(
            &connection("b.example"),
            Some(&secret("refresh-1")),
            SecretPolicy::NativeOnly,
        )
        .expect_err("no credential store");

    assert!(
        matches!(error, StoreError::NativeStorageUnavailable { .. }),
        "{error:?}"
    );
    assert_eq!(std::fs::read(&path).expect("file"), before);
}

#[test]
fn a_credential_store_rejection_is_not_a_reason_to_use_a_file() {
    let keyring = common::keyring();
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = store.exclusive().expect("lock");
    guard
        .replace(&connection("a.example"), None, SecretPolicy::NativeOnly)
        .expect("replace a");
    let path = store.dir().join("connection.json");
    let before = std::fs::read(&path).expect("file");
    common::refusing(&keyring, common::rejected);

    let error = guard
        .replace(
            &connection("b.example"),
            Some(&secret("refresh-1")),
            SecretPolicy::AllowPlaintextFile,
        )
        .expect_err("rejected");

    assert!(matches!(error, StoreError::Native(_)), "{error:?}");
    assert_eq!(std::fs::read(&path).expect("file"), before);
}

#[cfg(unix)]
#[test]
fn an_opted_in_plaintext_file_is_private_and_round_trips() {
    use firma_connection_store::Backend;

    let keyring = common::keyring();
    common::refusing(&keyring, common::unavailable);
    let (_root, store) = common::store_with_keyring(&keyring);
    let saved = connection("cp.example");
    let guard = store.exclusive().expect("lock");

    let replaced = guard
        .replace(
            &saved,
            Some(&secret("refresh-1")),
            SecretPolicy::AllowPlaintextFile,
        )
        .expect("replace");

    assert_eq!(replaced.backend, Backend::File);
    assert_eq!(common::mode(&store.dir().join("connection.json")), 0o600);
    assert_eq!(common::mode(store.dir()), 0o700);
    let loaded = guard.load().expect("load").expect("saved connection");
    assert_eq!(loaded.connection, saved);
    assert_eq!(loaded.secret.backend(), Backend::File);
    assert_eq!(
        loaded.secret.secret().expect("secret").expose(),
        "refresh-1"
    );
}

#[cfg(unix)]
#[test]
fn a_large_ascii_secret_uses_its_actual_json_size() {
    let keyring = common::keyring();
    common::refusing(&keyring, common::unavailable);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = store.exclusive().expect("lock");
    let large = "x".repeat(3 * 1024 * 1024);

    let replaced = guard
        .replace(
            &connection("cp.example"),
            Some(&secret(&large)),
            SecretPolicy::AllowPlaintextFile,
        )
        .expect("record below 16 MiB");

    assert_eq!(replaced.backend, firma_connection_store::Backend::File);
    assert_eq!(
        guard
            .load()
            .expect("load")
            .expect("saved")
            .secret
            .secret()
            .expect("file secret")
            .expose(),
        large
    );
}

#[cfg(unix)]
#[test]
fn an_oversized_encoded_secret_keeps_the_previous_record() {
    let keyring = common::keyring();
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = store.exclusive().expect("lock");
    guard
        .replace(
            &connection("before.example"),
            None,
            SecretPolicy::NativeOnly,
        )
        .expect("save previous");
    let path = store.dir().join("connection.json");
    let before = std::fs::read(&path).expect("previous record");
    common::refusing(&keyring, common::unavailable);
    let oversized = "x".repeat(16 * 1024 * 1024);

    let error = guard
        .replace(
            &connection("after.example"),
            Some(&secret(&oversized)),
            SecretPolicy::AllowPlaintextFile,
        )
        .expect_err("record above 16 MiB");

    assert!(matches!(error, StoreError::RecordTooLarge), "{error:?}");
    assert_eq!(std::fs::read(&path).expect("record"), before);
}

#[cfg(windows)]
#[test]
fn windows_never_writes_a_plaintext_secret() {
    let keyring = common::keyring();
    common::refusing(&keyring, common::unavailable);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = store.exclusive().expect("lock");

    let error = guard
        .replace(
            &connection("cp.example"),
            Some(&secret("refresh-1")),
            SecretPolicy::AllowPlaintextFile,
        )
        .expect_err("plaintext refused");

    assert!(
        matches!(error, StoreError::PlaintextFileUnsupported),
        "{error:?}"
    );
    assert!(!store.dir().join("connection.json").exists());
}

#[cfg(windows)]
#[test]
fn windows_never_reads_a_plaintext_secret() {
    let (_root, store) = common::store();
    let guard = store.exclusive().expect("lock");
    guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace");
    let path = store.dir().join("connection.json");
    let copied_from_unix = std::fs::read_to_string(&path).expect("file").replace(
        "\"backend\": \"none\"",
        "\"backend\": \"file\",\n    \"value\": \"refresh-1\"",
    );
    std::fs::write(&path, copied_from_unix).expect("rewrite");

    let error = guard.load().expect_err("plaintext refused");

    assert!(
        matches!(error, StoreError::PlaintextFileUnsupported),
        "{error:?}"
    );
}

#[cfg(windows)]
#[test]
fn an_unsupported_version_is_reported_before_its_file_secret() {
    let (_root, store) = common::store();
    let guard = store.exclusive().expect("lock");
    guard
        .replace(&connection("cp.example"), None, SecretPolicy::NativeOnly)
        .expect("replace");
    let path = store.dir().join("connection.json");
    let future_record = std::fs::read_to_string(&path)
        .expect("file")
        .replace("\"version\": 1", "\"version\": 99")
        .replace(
            "\"backend\": \"none\"",
            "\"backend\": \"file\",\n    \"value\": \"refresh-1\"",
        );
    std::fs::write(&path, future_record).expect("rewrite");

    let error = guard.load().expect_err("unsupported version accepted");
    let rendered = error.to_string();
    let StoreError::CorruptConnection { reason, .. } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(reason, "unsupported version 99");
    assert_eq!(
        rendered,
        format!(
            "the saved connection in {} is unreadable (unsupported version 99); run `firma login` again",
            path.display()
        )
    );
}
