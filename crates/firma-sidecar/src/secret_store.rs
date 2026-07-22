//! In-memory placeholder ↔ secret dictionary for the Sidecar redact path.
//!
//! The broker (firma-run) populates this store by pushing entries over the
//! local-exec channel whenever a vault CLI intercept succeeds. The Sidecar's
//! MITM pipeline then reads the store on each outbound request (rehydrate) and
//! each inbound response (mask).
//!
//! The design mirrors `firma_run::secret::SecretStore` but lives in the Sidecar
//! crate to avoid a circular dependency. The two stores share no code but are
//! structurally identical: an Aho-Corasick scan over secret values (masking)
//! and a parallel scan over placeholder tokens (rehydration), both rebuilt on
//! each `insert`.

use std::borrow::Borrow;
use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, MatchKind};
use zeroize::Zeroizing;

use crate::secret_rewrite::{MaskOp, RehydrateOp};

/// A secret value held in memory, zeroized on drop.
#[derive(Clone, Default)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue(<{} bytes redacted>)", self.0.len())
    }
}

/// Errors from mutating the [`SidecarSecretStore`].
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("failed to build secret matcher: {0}")]
    Matcher(String),
}

/// In-memory placeholder ↔ secret dictionary for the Sidecar redact path.
///
/// Populated by the broker via push; read by the MITM rewrite pipeline.
/// Clone is cheap (Arc-free) and used via `ArcSwap`-style copy-on-write in the
/// accept loop — each `insert` returns a new store rather than mutating in
/// place, so readers see a consistent snapshot without locking.
#[derive(Debug, Clone, Default)]
pub struct SidecarSecretStore {
    by_placeholder: BTreeMap<String, SecretValue>,
    /// Aho-Corasick over secret *values* (for inbound masking).
    mask_matcher: Option<AhoCorasick>,
    /// Aligned by pattern index with `mask_matcher`.
    mask_placeholders: Vec<String>,
    /// Aho-Corasick over placeholder *tokens* (for outbound rehydration).
    rehydrate_matcher: Option<AhoCorasick>,
    /// Aligned by pattern index with `rehydrate_matcher`.
    rehydrate_placeholders: Vec<String>,
}

impl SidecarSecretStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_placeholder.len()
    }

    /// Whether the store holds no secrets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_placeholder.is_empty()
    }

    /// Insert or replace a placeholder → secret mapping and rebuild both matchers.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Matcher`] if the Aho-Corasick automaton
    /// cannot be rebuilt.
    pub fn insert(
        &mut self,
        placeholder: String,
        secret: SecretValue,
    ) -> Result<(), SecretStoreError> {
        self.by_placeholder.insert(placeholder, secret);
        self.rebuild_matchers()
    }

    /// Resolve a placeholder token to its secret bytes, if known.
    #[must_use]
    pub fn resolve(&self, placeholder: &str) -> Option<&[u8]> {
        self.by_placeholder
            .get(placeholder)
            .map(SecretValue::expose)
    }

    /// Collect outbound rehydration ops for `haystack`.
    ///
    /// Scans for placeholder tokens and returns each match with the
    /// corresponding secret bytes. Matches are leftmost-longest and
    /// non-overlapping. Unknown placeholders are silently skipped (fail
    /// closed — the literal passes through).
    #[must_use]
    pub fn rehydrate_ops<'a>(&'a self, haystack: &'a [u8]) -> Vec<RehydrateOp<'a>> {
        let Some(matcher) = self.rehydrate_matcher.as_ref() else {
            return Vec::new();
        };
        matcher
            .find_iter(haystack)
            .filter_map(|m| {
                let placeholder = self.rehydrate_placeholders.get(m.pattern().as_usize())?;
                let secret = self.by_placeholder.get(placeholder.as_str())?.expose();
                Some(RehydrateOp {
                    start: m.start(),
                    end: m.end(),
                    secret,
                })
            })
            .collect()
    }

    /// Collect inbound masking ops for `haystack`.
    ///
    /// Scans for known secret values and returns each match with its
    /// placeholder token. Matches are leftmost-longest and non-overlapping.
    #[must_use]
    pub fn mask_ops<'a>(&'a self, haystack: &'a [u8]) -> Vec<MaskOp<'a>> {
        let Some(matcher) = self.mask_matcher.as_ref() else {
            return Vec::new();
        };
        matcher
            .find_iter(haystack)
            .filter_map(|m| {
                let placeholder = self.mask_placeholders.get(m.pattern().as_usize())?;
                Some(MaskOp {
                    start: m.start(),
                    end: m.end(),
                    placeholder: placeholder.as_str(),
                })
            })
            .collect()
    }

    fn rebuild_matchers(&mut self) -> Result<(), SecretStoreError> {
        self.rebuild_mask_matcher()?;
        self.rebuild_rehydrate_matcher()
    }

    fn rebuild_mask_matcher(&mut self) -> Result<(), SecretStoreError> {
        // Skip empty values (an empty pattern matches at every position).
        let mut entries: Vec<(&str, &[u8])> = self
            .by_placeholder
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.borrow(), v.expose()))
            .collect();
        entries.sort_by_key(|(k, _)| *k);

        if entries.is_empty() {
            self.mask_matcher = None;
            self.mask_placeholders = Vec::new();
            return Ok(());
        }

        let patterns: Vec<&[u8]> = entries.iter().map(|(_, v)| *v).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|e| SecretStoreError::Matcher(e.to_string()))?;

        self.mask_placeholders = entries.iter().map(|(k, _)| (*k).to_owned()).collect();
        self.mask_matcher = Some(matcher);
        Ok(())
    }

    fn rebuild_rehydrate_matcher(&mut self) -> Result<(), SecretStoreError> {
        if self.by_placeholder.is_empty() {
            self.rehydrate_matcher = None;
            self.rehydrate_placeholders = Vec::new();
            return Ok(());
        }

        let placeholders: Vec<&str> = self.by_placeholder.keys().map(String::as_str).collect();
        let patterns: Vec<&[u8]> = placeholders.iter().map(|k| k.as_bytes()).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|e| SecretStoreError::Matcher(e.to_string()))?;

        self.rehydrate_placeholders = placeholders.into_iter().map(str::to_owned).collect();
        self.rehydrate_matcher = Some(matcher);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_rewrite::{ContentType, mask_body, rehydrate_body};

    fn store_with(pairs: &[(&str, &[u8])]) -> SidecarSecretStore {
        let mut store = SidecarSecretStore::new();
        for (placeholder, secret) in pairs {
            store
                .insert((*placeholder).to_owned(), SecretValue::new(secret.to_vec()))
                .expect("insert");
        }
        store
    }

    #[test]
    fn resolve_returns_secret_for_known_placeholder() {
        let store = store_with(&[("firma-secret://bw/token", b"s3cr3t")]);
        assert_eq!(
            store.resolve("firma-secret://bw/token"),
            Some(b"s3cr3t".as_slice())
        );
        assert_eq!(store.resolve("firma-secret://bw/absent"), None);
    }

    #[test]
    fn rehydrate_ops_finds_placeholder_in_body() {
        let store = store_with(&[("firma-secret://bw/token", b"ghp_abc")]);
        let body = b"Authorization: Bearer firma-secret://bw/token\r\n";
        let ops = store.rehydrate_ops(body);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].secret, b"ghp_abc");
        let result = rehydrate_body(body, ContentType::Raw, &ops);
        assert_eq!(result, b"Authorization: Bearer ghp_abc\r\n");
    }

    #[test]
    fn mask_ops_finds_secret_in_response() {
        let store = store_with(&[("firma-secret://bw/token", b"ghp_abc")]);
        let body = b"error: token ghp_abc is invalid";
        let ops = store.mask_ops(body);
        assert_eq!(ops.len(), 1);
        let result = mask_body(body, &ops);
        assert_eq!(result, b"error: token firma-secret://bw/token is invalid");
    }

    #[test]
    fn empty_store_produces_no_ops() {
        let store = SidecarSecretStore::new();
        assert!(store.rehydrate_ops(b"firma-secret://bw/token").is_empty());
        assert!(store.mask_ops(b"s3cr3t").is_empty());
    }

    #[test]
    fn empty_secret_is_not_matched_for_masking() {
        let store = store_with(&[("firma-secret://bw/empty", b"")]);
        // An empty secret would match at every position — the store skips it.
        assert!(store.mask_ops(b"anything at all").is_empty());
    }

    #[test]
    fn leftmost_longest_wins_for_overlapping_placeholders() {
        let store = store_with(&[
            ("firma-secret://bw/a", b"SHORT"),
            ("firma-secret://bw/abc", b"LONG"),
        ]);
        let body = b"value=firma-secret://bw/abc";
        let ops = store.rehydrate_ops(body);
        // The longer token must win.
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].secret, b"LONG");
    }

    #[test]
    fn insert_replaces_existing_entry() {
        let mut store = SidecarSecretStore::new();
        store
            .insert(
                "firma-secret://bw/k".to_owned(),
                SecretValue::new(b"old".to_vec()),
            )
            .expect("insert");
        store
            .insert(
                "firma-secret://bw/k".to_owned(),
                SecretValue::new(b"new".to_vec()),
            )
            .expect("replace");
        assert_eq!(
            store.resolve("firma-secret://bw/k"),
            Some(b"new".as_slice())
        );
        assert_eq!(store.len(), 1);
    }
}
