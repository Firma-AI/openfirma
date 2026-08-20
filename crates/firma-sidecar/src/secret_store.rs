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
//! The design mirrors [`firma_secret_provider::store::SecretStore`] but lives in the
//! Sidecar crate to avoid a circular dependency.
//!
//! The two directions use different matching strategies. Rehydration scans
//! for placeholder tokens, which are fixed-format and never need decoding, so
//! it uses an Aho-Corasick automaton. Masking scans for secret *values*,
//! which the upstream response may have re-encoded for its content type
//! (JSON escaping, percent-encoding, XML entities); a raw byte scan would
//! miss those re-echoes, so masking instead uses the content-type-aware
//! [`crate::secret_rewrite::find_decoded_secret_spans`] per secret, gated by
//! [`MIN_MASKABLE_SECRET_LEN`] to avoid corrupting unrelated response content
//! that coincidentally equals a short secret value.

use std::collections::BTreeMap;
use std::ops::Range;

use aho_corasick::{AhoCorasick, BuildError, MatchKind};
use firma_secret_provider::{ExposeSecret, SecretPlaceholder, SecretString};

use crate::secret_rewrite::{ContentType, MaskOp, RehydrateOp, find_decoded_secret_spans};

/// Minimum secret length eligible for inbound masking.
///
/// Below this, a raw value is common enough — short IDs, status codes,
/// timestamps, single words — that whole-value matching produces more false
/// positives (masking unrelated content that coincidentally equals the
/// secret) than true positives. Such secrets pass through the response
/// unmasked rather than risk corrupting content that was never the secret.
const MIN_MASKABLE_SECRET_LEN: usize = 8;

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
    rehydrate: MatcherPlaceholders,
}

/// An Aho-Corasick automaton over placeholder tokens, paired with the
/// placeholder each pattern maps to.
///
/// Placeholder tokens are fixed-format (see [`SecretPlaceholder`]) and never
/// need content-type-aware decoding, unlike secret values, so a raw
/// byte-pattern automaton is exact here.
#[derive(Debug, Clone, Default)]
struct MatcherPlaceholders {
    /// Aho-Corasick over placeholder tokens.
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

    /// Insert or replace a placeholder → secret mapping and rebuild the
    /// rehydration matcher.
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
    #[cfg(test)]
    fn resolve(&self, placeholder: &SecretPlaceholder) -> Option<&SecretString> {
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

    /// Collect inbound masking ops for `haystack`, a response body of
    /// `content_type`.
    ///
    /// For each known secret at least [`MIN_MASKABLE_SECRET_LEN`] bytes long,
    /// finds every content-type-decoded span in `haystack` that equals the
    /// secret (see [`find_decoded_secret_spans`]) — catching re-encoded
    /// re-echoes (JSON escaping, percent-encoding, XML entities), not just a
    /// byte-identical occurrence. Overlapping spans across different secrets
    /// are resolved by keeping the earliest; spans that start at the same
    /// offset keep the longest instead, so a longer secret that happens to
    /// be a prefix-extension of a shorter one doesn't leave its tail
    /// unmasked. A later span that starts after the kept span but extends
    /// past its end (a "crossing" overlap between two unrelated secrets) is
    /// clipped to its non-overlapping tail rather than dropped, so no byte of
    /// a matched secret is ever left unredacted. The result is
    /// sorted/non-overlapping as [`mask_body`] requires.
    ///
    /// [`mask_body`]: crate::secret_rewrite::mask_body
    #[must_use]
    pub(crate) fn mask_ops<'a>(
        &'a self,
        haystack: &'a [u8],
        content_type: ContentType,
    ) -> Vec<MaskOp<'a>> {
        let mut ops: Vec<MaskOp<'a>> = self
            .by_placeholder
            .iter()
            .filter(|(_, secret)| secret.expose_secret().len() >= MIN_MASKABLE_SECRET_LEN)
            .flat_map(|(placeholder, secret)| {
                find_decoded_secret_spans(haystack, content_type, secret)
                    .into_iter()
                    .map(move |range| MaskOp { range, placeholder })
            })
            .collect();
        ops.sort_by_key(|op| op.range.start);
        ops.into_iter().fold(Vec::new(), |mut kept, op| {
            if let Some(last) = kept.last_mut()
                && op.range.start < last.range.end
            {
                if op.range.start == last.range.start
                    && op.range.end - op.range.start > last.range.end - last.range.start
                {
                    last.range = op.range;
                    last.placeholder = op.placeholder;
                } else if op.range.end > last.range.end {
                    // Crossing overlap between two different secrets: `op`
                    // starts inside `last` but its own match extends past
                    // `last`'s end. Those trailing bytes are real,
                    // unredacted secret bytes and aren't covered by any
                    // other op, so keep them as a clipped tail rather than
                    // dropping `op` outright.
                    let tail = MaskOp {
                        range: last.range.end..op.range.end,
                        placeholder: op.placeholder,
                    };
                    kept.push(tail);
                }
            } else {
                kept.push(op);
            }
            kept
        })
    }

    fn rebuild_matchers(&mut self) -> Result<(), SecretStoreError> {
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
        let store = store_with([(placeholder.clone(), "ghp_abcdef0123")]);
        let body = b"error: token ghp_abcdef0123 is invalid";
        let ops = store.mask_ops(body, ContentType::Raw);
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
        assert!(store.mask_ops(b"s3cr3t", ContentType::Raw).is_empty());
    }

    #[test]
    fn empty_secret_is_not_matched_for_masking() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder, "")]);
        // An empty secret is well below MIN_MASKABLE_SECRET_LEN — the store
        // skips it rather than matching at every position.
        assert!(
            store
                .mask_ops(b"anything at all", ContentType::Raw)
                .is_empty()
        );
    }

    #[test]
    fn mask_ops_skips_secrets_below_minimum_length() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder, "admin")]);
        // "admin" (5 bytes) is below MIN_MASKABLE_SECRET_LEN: matching it
        // would corrupt any unrelated response field that happens to equal
        // this common value (e.g. a JSON `"role":"admin"`).
        let body = br#"{"role":"admin"}"#;
        assert!(store.mask_ops(body, ContentType::Json).is_empty());
    }

    #[test]
    fn mask_ops_matches_json_escaped_re_echo() {
        let placeholder = SecretPlaceholder::new();
        let secret = "s\"ecret-value";
        let store = store_with([(placeholder.clone(), secret)]);
        // The upstream echoes the secret back JSON-escaped, not as a raw
        // byte-identical span; a decode-aware match is required to catch it.
        let body = br#"{"echo":"s\"ecret-value"}"#;
        let ops = store.mask_ops(body, ContentType::Json);
        assert_eq!(ops.len(), 1);
        let result = mask_body(body, &ops);
        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            format!(r#"{{"echo":"{placeholder}"}}"#)
        );
    }

    #[test]
    fn mask_ops_prefers_longer_secret_when_echoes_share_a_start() {
        // Two distinct, prefix-related secrets echoed at the same offset:
        // keeping only the earliest span would redact the shorter secret and
        // leave the longer one's tail unmasked. The longer span must win.
        let short = "sk-live-abcdef";
        let long = "sk-live-abcdef123456";
        let p_short = SecretPlaceholder::new();
        let p_long = SecretPlaceholder::new();
        let store = store_with([(p_short, short), (p_long.clone(), long)]);

        let body = long.as_bytes();
        let ops = store.mask_ops(body, ContentType::Raw);
        let result = mask_body(body, &ops);

        assert_eq!(String::from_utf8(result).expect("utf8"), p_long.to_string());
    }

    #[test]
    fn mask_ops_clips_crossing_overlap_instead_of_dropping_the_tail() {
        // Regression: two different secrets whose matched spans overlap with
        // *different* start offsets (a "crossing" overlap, as opposed to the
        // same-start case above) used to have the later span dropped
        // entirely, leaking its non-overlapping tail — real secret bytes —
        // unmasked into the response.
        let p1 = SecretPlaceholder::new();
        let p2 = SecretPlaceholder::new();
        let store = store_with([(p1.clone(), "AAAA-BBBB"), (p2.clone(), "BBBB-CCCC")]);
        let body = b"AAAA-BBBB-CCCC";

        let ops = store.mask_ops(body, ContentType::Raw);
        let result = mask_body(body, &ops);

        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            format!("{p1}{p2}")
        );
    }

    #[test]
    fn mask_ops_does_not_match_partial_substring_within_longer_value() {
        let placeholder = SecretPlaceholder::new();
        let store = store_with([(placeholder, "sk-real-secret")]);
        // The stored secret is a substring of the JSON value below, but the
        // decoded *whole* string value is longer than the secret, so a
        // whole-value-equality match must not fire (unlike the old raw
        // Aho-Corasick substring scan, which would have masked part of an
        // unrelated, longer value).
        let body = br#"{"id":"sk-real-secret-value-not-the-secret"}"#;
        assert!(store.mask_ops(body, ContentType::Json).is_empty());
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
