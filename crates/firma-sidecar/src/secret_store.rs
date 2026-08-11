//! In-memory placeholder ↔ secret dictionary for the Sidecar MITM pipeline.
//!
//! In the pull model the Sidecar queries the firma-run secret gateway
//! ([`firma_secret_provider::gateway::client::GatewayClient`]) for each outbound
//! request and builds a `SidecarSecretStore` from the returned `(placeholder,
//! secret_bytes)` pairs.
//! The store is scoped to one request-response cycle and discarded after
//! forwarding. firma-run remains the single source of truth; the Sidecar never
//! caches secrets persistently.
//!
//! The design mirrors `firma_run::secret::SecretStore` but lives in the Sidecar
//! crate to avoid a circular dependency. Both use Aho-Corasick for scanning:
//! over secret values (masking inbound responses) and over placeholder tokens
//! (rehydrating outbound requests).

#![allow(dead_code, reason = "This code will be used by later PRs")]

use std::collections::BTreeMap;
use std::ops::Range;

use aho_corasick::{AhoCorasick, BuildError, MatchKind};
use firma_secret_provider::{ExposeSecret, SecretPlaceholder, SecretString};

use crate::secret_rewrite::{MaskOp, RehydrateOp};

/// Errors from mutating the [`SidecarSecretStore`].
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("failed to build secret matcher: {0}")]
    Matcher(#[source] BuildError),
}

/// In-memory placeholder ↔ secret dictionary for the Sidecar redact path.
///
/// Populated by the broker via push; read by the MITM rewrite pipeline.
/// Clone is cheap (Arc-free) and used via `ArcSwap`-style copy-on-write in the
/// accept loop — each `insert` returns a new store rather than mutating in
/// place, so readers see a consistent snapshot without locking.
#[derive(Debug, Clone, Default)]
pub struct SidecarSecretStore {
    by_placeholder: BTreeMap<SecretPlaceholder, SecretString>,
    mask: MatcherPlaceholders,
    rehydrate: MatcherPlaceholders,
}

/// An Aho-Corasick automaton paired with the placeholder each pattern maps to.
///
/// Used for both directions of the rewrite: scanning for secret *values*
/// (masking inbound responses) and scanning for placeholder *tokens*
/// (rehydrating outbound requests). The two directions differ only in what
/// bytes are indexed, so the build/scan machinery lives here once.
#[derive(Debug, Clone, Default)]
struct MatcherPlaceholders {
    /// Aho-Corasick over targets (secrets *values* or placeholder *tokens*).
    matcher: Option<AhoCorasick>,
    /// Aligned by pattern index with `matcher`.
    placeholders: Vec<SecretPlaceholder>,
}

impl MatcherPlaceholders {
    /// Rebuild the automaton from `entries`. An empty iterator clears it.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Matcher`] if the Aho-Corasick automaton
    /// cannot be built.
    fn rebuild<'p>(
        &mut self,
        entries: impl Iterator<Item = (SecretPlaceholder, &'p [u8])>,
    ) -> Result<(), SecretStoreError> {
        let entries: Vec<(SecretPlaceholder, &[u8])> = entries.collect();
        if entries.is_empty() {
            self.matcher = None;
            self.placeholders = Vec::new();
            return Ok(());
        }

        let patterns: Vec<&[u8]> = entries.iter().map(|(_, pattern)| *pattern).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(SecretStoreError::Matcher)?;

        self.placeholders = entries
            .into_iter()
            .map(|(placeholder, _)| placeholder)
            .collect();
        self.matcher = Some(matcher);
        Ok(())
    }

    /// Scan `haystack` for matches, mapping each one's placeholder to an op via `make`.
    ///
    /// Matches are leftmost-longest and non-overlapping. `make` returning
    /// `None` skips the match (used to fail closed on unknown placeholders).
    fn find_ops<'a, T>(
        &'a self,
        haystack: &'a [u8],
        make: impl Fn(Range<usize>, &'a SecretPlaceholder) -> Option<T>,
    ) -> Vec<T> {
        let Some(matcher) = self.matcher.as_ref() else {
            return Vec::new();
        };
        matcher
            .find_iter(haystack)
            .filter_map(|m| {
                let placeholder = self.placeholders.get(m.pattern().as_usize())?;
                make(m.start()..m.end(), placeholder)
            })
            .collect()
    }
}

impl SidecarSecretStore {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.by_placeholder.len()
    }

    /// Whether the store holds no secrets.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.by_placeholder.is_empty()
    }

    /// Insert or replace a placeholder → secret mapping and rebuild both matchers.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Matcher`] if the Aho-Corasick automaton
    /// cannot be rebuilt.
    pub(crate) fn insert(
        &mut self,
        placeholder: SecretPlaceholder,
        secret: SecretString,
    ) -> Result<(), SecretStoreError> {
        self.by_placeholder.insert(placeholder, secret);
        self.rebuild_matchers()
    }

    /// Resolve a placeholder token to its secret bytes, if known.
    #[must_use]
    pub(crate) fn resolve(&self, placeholder: &SecretPlaceholder) -> Option<&SecretString> {
        self.by_placeholder.get(placeholder)
    }

    /// Collect outbound rehydration ops for `haystack`.
    ///
    /// Scans for placeholder tokens and returns each match with the
    /// corresponding secret bytes. Matches are leftmost-longest and
    /// non-overlapping. Unknown placeholders are silently skipped (fail
    /// closed — the literal passes through).
    #[must_use]
    pub(crate) fn rehydrate_ops<'a>(&'a self, haystack: &'a [u8]) -> Vec<RehydrateOp<'a>> {
        self.rehydrate.find_ops(haystack, |range, placeholder| {
            let secret = self.by_placeholder.get(placeholder)?;
            Some(RehydrateOp { range, secret })
        })
    }

    /// Collect inbound masking ops for `haystack`.
    ///
    /// Scans for known secret values and returns each match with its
    /// placeholder token. Matches are leftmost-longest and non-overlapping.
    #[must_use]
    pub(crate) fn mask_ops<'a>(&'a self, haystack: &'a [u8]) -> Vec<MaskOp<'a>> {
        self.mask.find_ops(haystack, |range, placeholder| {
            Some(MaskOp { range, placeholder })
        })
    }

    fn rebuild_matchers(&mut self) -> Result<(), SecretStoreError> {
        // Skip empty secret values (an empty pattern matches at every position).
        let mask_entries = self
            .by_placeholder
            .iter()
            .filter(|(_, secret)| !secret.expose_secret().is_empty())
            .map(|(placeholder, secret)| (placeholder.clone(), secret.expose_secret().as_bytes()));
        self.mask.rebuild(mask_entries)?;

        let rehydrate_patterns: Vec<(SecretPlaceholder, String)> = self
            .by_placeholder
            .keys()
            .map(|placeholder| (placeholder.clone(), placeholder.to_string()))
            .collect();
        let rehydrate_entries = rehydrate_patterns
            .iter()
            .map(|(placeholder, token)| (placeholder.clone(), token.as_bytes()));
        self.rehydrate.rebuild(rehydrate_entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_rewrite::{ContentType, mask_body, rehydrate_body};

    fn store_with<'a>(
        pairs: impl IntoIterator<Item = (SecretPlaceholder, &'a str)>,
    ) -> SidecarSecretStore {
        let mut store = SidecarSecretStore::new();
        for (placeholder, secret) in pairs {
            store
                .insert(placeholder, SecretString::from(secret))
                .expect("insert");
        }
        store
    }

    #[test]
    fn resolve_returns_secret_for_known_placeholder() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder.clone(), "s3cr3t")]);
        assert_eq!(
            store.resolve(&placeholder).map(SecretString::expose_secret),
            Some("s3cr3t")
        );
        assert_eq!(
            store
                .resolve(&SecretPlaceholder::new())
                .map(SecretString::expose_secret),
            None
        );
    }

    #[test]
    fn rehydrate_ops_finds_placeholder_in_body() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder.clone(), "ghp_abc")]);
        let body = format!("Authorization: Bearer {placeholder}\r\n");
        let ops = store.rehydrate_ops(body.as_bytes());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].secret.expose_secret(), "ghp_abc");
        let result = rehydrate_body(body.as_bytes(), ContentType::Raw, &ops);
        assert_eq!(result, b"Authorization: Bearer ghp_abc\r\n");
    }

    #[test]
    fn mask_ops_finds_secret_in_response() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder.clone(), "ghp_abc")]);
        let body = b"error: token ghp_abc is invalid";
        let ops = store.mask_ops(body);
        assert_eq!(ops.len(), 1);
        let result = mask_body(body, &ops);
        assert_eq!(
            result,
            format!("error: token {placeholder} is invalid").into_bytes()
        );
    }

    #[test]
    fn empty_store_produces_no_ops() {
        let placeholder = SecretPlaceholder::new();
        let store = SidecarSecretStore::new();
        assert!(
            store
                .rehydrate_ops(placeholder.to_string().as_bytes())
                .is_empty()
        );
        assert!(store.mask_ops(b"s3cr3t").is_empty());
    }

    #[test]
    fn empty_secret_is_not_matched_for_masking() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder, "")]);
        // An empty secret would match at every position — the store skips it.
        assert!(store.mask_ops(b"anything at all").is_empty());
    }

    #[test]
    fn insert_replaces_existing_entry() {
        let placeholder = SecretPlaceholder::new();
        let mut store = SidecarSecretStore::new();
        store
            .insert(placeholder.clone(), SecretString::from("old"))
            .expect("insert");
        store
            .insert(placeholder.clone(), SecretString::from("new"))
            .expect("replace");
        assert_eq!(
            store.resolve(&placeholder).map(SecretString::expose_secret),
            Some("new")
        );
        assert_eq!(store.len(), 1);
    }
}
