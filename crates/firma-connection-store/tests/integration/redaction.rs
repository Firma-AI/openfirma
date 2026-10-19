use std::error::Error as _;

use firma_connection_store::StoreError;

use crate::common::{self, secret};

#[test]
fn debug_output_never_shows_a_secret() {
    let keyring = common::keyring();
    common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "cp.example", "refresh-sentinel");

    let loaded = guard.load().expect("load").expect("saved connection");

    assert_eq!(
        format!("{:?}", secret("refresh-sentinel")),
        "ConnectionSecret([REDACTED])"
    );
    assert!(!format!("{loaded:?}").contains("refresh-sentinel"));
}

#[test]
fn a_malformed_native_secret_is_reported_without_its_bytes() {
    let keyring = common::keyring();
    common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "cp.example", "placeholder");
    common::native_entry(&keyring, store.dir())
        .set_secret(b"refresh-sentinel\xff")
        .expect("store invalid UTF-8");

    let error = guard.load().expect_err("malformed secret");

    assert!(matches!(error, StoreError::Native(_)), "{error:?}");
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = error.source();
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    for rendering in renderings {
        assert!(!rendering.contains("refresh-sentinel"), "{rendering}");
        assert!(!rendering.contains("255"), "{rendering}");
    }
}

#[test]
fn an_ambiguous_native_error_does_not_render_credential_entries() {
    let keyring = common::keyring();
    common::mock(&keyring);
    let (_root, store) = common::store_with_keyring(&keyring);
    let guard = common::with_native(&store, "cp.example", "refresh-sentinel");
    let entry = common::native_entry(&keyring, store.dir());
    let credential = entry.get_credential().expect("credential wrapper");
    entry
        .as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
        .expect("mock credential")
        .set_error(keyring_core::Error::Ambiguous(vec![credential]));

    let error = guard.load().expect_err("ambiguous credential");
    assert!(!error.to_string().contains("refresh-sentinel"));
    assert!(!format!("{error:?}").contains("refresh-sentinel"));
}
