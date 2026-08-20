use std::collections::HashSet;

use firma_http::Authority;
use firma_secret_provider::{ExposeSecret, SecretPlaceholder, store::SecretStore};
use secrecy::SecretString;

#[test]
fn wildcard_entry_resolves_for_any_domain() {
    let mut store = SecretStore::new();
    let placeholder = SecretPlaceholder::new();
    store.insert(
        placeholder.clone(),
        HashSet::new(),
        SecretString::from("s3cr3t"),
    );

    assert_eq!(
        store
            .resolve(&placeholder, &Authority::from_static("api.github.com"))
            .map(SecretString::expose_secret),
        Some("s3cr3t")
    );
    assert_eq!(
        store
            .resolve(&placeholder, &Authority::from_static("api.stripe.com"))
            .map(SecretString::expose_secret),
        Some("s3cr3t")
    );
    assert_eq!(
        store
            .resolve(
                &SecretPlaceholder::new(),
                &Authority::from_static("api.github.com")
            )
            .map(SecretString::expose_secret),
        None
    );
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}

#[test]
fn same_domain_insert_replaces_existing_entry() {
    let mut store = SecretStore::new();
    let placeholder = SecretPlaceholder::new();
    store.insert(
        placeholder.clone(),
        HashSet::new(),
        SecretString::from("old-value"),
    );
    store.insert(
        placeholder.clone(),
        HashSet::new(),
        SecretString::from("new-value"),
    );

    assert_eq!(store.len(), 1);
    assert_eq!(
        store
            .resolve(&placeholder, &Authority::from_static("any.domain"))
            .map(SecretString::expose_secret),
        Some("new-value")
    );
}

#[test]
fn domain_scoped_entry_does_not_match_wrong_domain() {
    let mut store = SecretStore::new();
    let placeholder = SecretPlaceholder::new();
    store.insert(
        placeholder.clone(),
        std::iter::once(Authority::from_static("api.github.com")).collect(),
        SecretString::from("ghp_xxx"),
    );

    assert_eq!(
        store
            .resolve(&placeholder, &Authority::from_static("api.github.com"))
            .map(SecretString::expose_secret),
        Some("ghp_xxx")
    );
    assert_eq!(
        store
            .resolve(&placeholder, &Authority::from_static("api.stripe.com"))
            .map(SecretString::expose_secret),
        None
    );
}
