//! In-memory secret dictionary for the `firma run` secret broker.
//!
//! The broker keeps real secret values out of the agent: each value is stored
//! under an opaque placeholder token and the agent only ever sees the token.
//! This module owns the **dictionary** — placeholder ↔ secret value, populated
//! by intercept and consulted for rehydration ([`SecretStore::resolve`]).
//!
//! The streaming rewrite and the out-of-sandbox broker transport live in other
//! modules; this one is deliberately transport-free so it can be unit-tested in
//! isolation. See `docs/architecture/secrets-interception.md`.

use std::collections::{BTreeMap, HashSet};

use firma_http::Authority;
use firma_secret_provider::{SecretPlaceholder, SecretString};

/// A stored secret with its optional domain scope.
#[derive(Debug, Clone)]
struct SecretEntry {
    value: SecretString,
    /// When not empty, this secret is only returned for requests whose domain
    /// matches exactly. Empty means the secret is domain-agnostic (wildcard).
    domain: HashSet<Authority>,
}

/// In-memory placeholder ↔ secret dictionary.
///
/// Each placeholder holds exactly one entry. The entry's optional `domain`
/// field scopes resolution: `None` resolves for any host; `Some(host)` resolves
/// only for that exact host. Integrations that expose a URL/website field in
/// their vault output (e.g. 1Password's `urls[0].href`) populate this field via
/// the matcher's `domain_path` so the Sidecar cannot reuse a credential for a
/// different service.
///
/// The dictionary is run-scoped: values are zeroized when the store is dropped.
#[derive(Debug, Clone, Default)]
pub struct SecretStore {
    by_placeholder: BTreeMap<SecretPlaceholder, SecretEntry>,
}

impl SecretStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a placeholder → secret mapping.
    ///
    /// `domain = None` makes the entry resolve for any request host (wildcard).
    /// `domain = Some(host)` scopes it to that host only.
    pub fn insert(
        &mut self,
        placeholder: SecretPlaceholder,
        domain: HashSet<Authority>,
        secret: SecretString,
    ) {
        self.by_placeholder.insert(
            placeholder,
            SecretEntry {
                value: secret,
                domain,
            },
        );
    }

    /// Resolve a placeholder token to its secret bytes for the given request domain.
    ///
    /// Returns `None` when the placeholder is unknown or its stored domain does
    /// not match `domain`.
    #[must_use]
    pub fn resolve(&self, placeholder: &SecretPlaceholder, domain: &str) -> Option<&SecretString> {
        self.by_placeholder.get(placeholder).and_then(|entry| {
            (entry.domain.is_empty() || entry.domain.iter().any(|d| d.as_str() == domain))
                .then_some(&entry.value)
        })
    }

    /// Iterate stored `(placeholder, secret bytes)` pairs, ordered by placeholder.
    pub fn iter(&self) -> impl Iterator<Item = (&SecretPlaceholder, &SecretString)> {
        self.by_placeholder
            .iter()
            .map(|(placeholder, entry)| (placeholder, &entry.value))
    }

    /// Number of stored secrets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_placeholder.len()
    }

    /// Whether the store holds no secrets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_placeholder.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use firma_secret_provider::ExposeSecret;

    use super::*;

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
                .resolve(&placeholder, "api.github.com")
                .map(SecretString::expose_secret),
            Some("s3cr3t")
        );
        assert_eq!(
            store
                .resolve(&placeholder, "api.stripe.com")
                .map(SecretString::expose_secret),
            Some("s3cr3t")
        );
        assert_eq!(
            store
                .resolve(&SecretPlaceholder::new(), "api.github.com")
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
                .resolve(&placeholder, "any.domain")
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
                .resolve(&placeholder, "api.github.com")
                .map(SecretString::expose_secret),
            Some("ghp_xxx")
        );
        assert_eq!(
            store
                .resolve(&placeholder, "api.stripe.com")
                .map(SecretString::expose_secret),
            None
        );
    }
}
