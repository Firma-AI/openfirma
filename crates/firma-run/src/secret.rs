//! In-memory secret dictionary and masking matcher for the `firma run` secret
//! broker.
//!
//! The broker keeps real secret values out of the agent: each value is stored
//! under an opaque placeholder token and the agent only ever sees the token.
//! This module owns two pure, synchronous responsibilities:
//!
//! - the **dictionary** — placeholder ↔ secret value, populated by intercept and
//!   consulted for rehydration ([`SecretStore::resolve`]);
//! - the **masking matcher** — locate raw secret values in an output buffer so a
//!   later stage can mask them back to placeholders
//!   ([`SecretStore::mask_matches`]).
//!
//! The streaming rewrite and the out-of-sandbox broker transport live in other
//! modules; this one is deliberately transport-free so it can be unit-tested in
//! isolation. See `docs/architecture/secrets-interception.md`.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use aho_corasick::{AhoCorasick, MatchKind};
use either::Either;
use zeroize::Zeroizing;

/// Out-of-sandbox broker transport (Unix-socket handshake + `SCM_RIGHTS` fd
/// passing). Unix-only: the primitive is `sendmsg`/`recvmsg` ancillary data.
#[cfg(unix)]
pub mod broker;

/// Broker → Sidecar policy-enforcement-point client for secret mediation
/// decisions, with fail-closed semantics.
#[cfg(unix)]
pub mod pep;

/// Intercept transform: extract secrets from a vault CLI's output and rewrite
/// it so the agent sees placeholders.
pub mod intercept;

/// Streaming byte-level rewriters (the `raw` redact transform): rehydrate
/// placeholders into secrets on stdin and mask secrets back on stdout.
pub mod transform;

/// Broker-side application of a secret-mediation decision to a wrapped launch's
/// captured output (fail-closed).
#[cfg(unix)]
pub mod session;

/// Broker-side application of a redact decision to a wrapped tool's
/// bidirectional streams (fail-closed).
#[cfg(unix)]
pub mod redact;

/// Per-connection broker dispatch: route a shim handshake's descriptors to an
/// intercept or redact session by decision (fail-closed).
#[cfg(unix)]
pub mod serve;

/// In-sandbox shim: courier the wrapped tool's descriptors to the broker.
#[cfg(unix)]
pub mod shim;

/// Broker accept loop: accept shim connections, decide, and serve them.
#[cfg(unix)]
pub mod accept;

/// URI scheme that prefixes every placeholder token.
pub const PLACEHOLDER_SCHEME: &str = "firma-secret://";

/// Marker in a `@placeholder` template that mint substitutes with the secret
/// key (percent-encoded).
pub const PLACEHOLDER_NAME_MARKER: &str = "{name}";

/// A placeholder token of the form `firma-secret://<provider>/<name>`.
///
/// The token is treated as an opaque dictionary key; callers never parse
/// `<provider>` or `<name>` back out. Minting percent-encodes any byte outside
/// the segment charset so the token round-trips unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Placeholder(String);

impl Placeholder {
    /// Mint a placeholder for `name` within `provider`.
    ///
    /// Both segments are percent-encoded down to the unreserved set
    /// (`[A-Za-z0-9._-]`); every other byte becomes `%XX`. The provider/name
    /// boundary is therefore the only unescaped `/` in the token.
    #[must_use]
    pub fn mint(provider: &str, name: &str) -> Self {
        let mut token = String::from(PLACEHOLDER_SCHEME);
        encode_segment(provider, &mut token);
        token.push('/');
        encode_segment(name, &mut token);
        Self(token)
    }

    /// Mint a placeholder by substituting [`PLACEHOLDER_NAME_MARKER`] in a
    /// `@placeholder` template with the percent-encoded secret key.
    ///
    /// The template is expected to be pre-validated (scheme + `{name}` marker),
    /// as enforced at Cedar bundle load. The key is percent-encoded to the token
    /// charset so the result round-trips.
    #[must_use]
    pub fn from_template(template: &str, name: &str) -> Self {
        let mut encoded = String::new();
        encode_segment(name, &mut encoded);
        Self(template.replace(PLACEHOLDER_NAME_MARKER, &encoded))
    }

    /// Wrap an existing token, validating the scheme and token charset.
    ///
    /// Returns `None` if the token does not begin with [`PLACEHOLDER_SCHEME`],
    /// has an empty body, or contains a byte outside `[A-Za-z0-9._/%-]`.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let rest = token.strip_prefix(PLACEHOLDER_SCHEME)?;
        if rest.is_empty() || !rest.bytes().all(is_token_byte) {
            return None;
        }
        Some(Self(token.to_owned()))
    }

    /// The token as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Borrow<str> for Placeholder {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// A secret value held in memory, zeroized on drop.
///
/// The `Debug` impl is redacted so a value never leaks into logs or panic
/// messages.
#[derive(Clone, Default)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Wrap raw secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for SecretValue {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes().to_vec())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<{} bytes redacted>)", self.0.len())
    }
}

/// A located occurrence of a secret value inside a buffer.
///
/// `start..end` are byte offsets into the searched haystack; `placeholder` is
/// the token the value should be masked to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskMatch<'a> {
    /// Inclusive start offset of the match.
    pub start: usize,
    /// Exclusive end offset of the match.
    pub end: usize,
    /// Placeholder the matched value maps to.
    pub placeholder: &'a Placeholder,
}

/// A located occurrence of a placeholder token inside a buffer.
///
/// `start..end` are byte offsets into the searched haystack; `secret` is the
/// value the placeholder should be rehydrated to (borrowed from the store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehydrateMatch<'a> {
    /// Inclusive start offset of the match.
    pub start: usize,
    /// Exclusive end offset of the match.
    pub end: usize,
    /// Secret bytes the matched placeholder resolves to.
    pub secret: &'a [u8],
}

/// Errors from mutating the [`SecretStore`].
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// The masking automaton could not be rebuilt after a change.
    #[error("failed to build secret matcher: {0}")]
    Matcher(String),
}

/// In-memory placeholder ↔ secret dictionary with a masking matcher.
///
/// The dictionary is run-scoped: values are zeroized when the store is dropped.
///
/// SECURITY: the masking automaton holds internal copies of the secret bytes
/// that are not zeroized (they live for the store's lifetime and are freed with
/// it). Tightening this is tracked as hardening in the design doc.
#[derive(Debug, Clone, Default)]
pub struct SecretStore {
    by_placeholder: BTreeMap<Placeholder, SecretValue>,
    matcher: Option<AhoCorasick>,
    /// Placeholder for each masking-matcher pattern, aligned by pattern index.
    pattern_placeholders: Vec<Placeholder>,
    rehydrate_matcher: Option<AhoCorasick>,
    /// Placeholder for each rehydration-matcher pattern, aligned by pattern
    /// index; used to resolve the secret the token maps to.
    rehydrate_placeholders: Vec<Placeholder>,
}

impl SecretStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a placeholder → secret mapping and rebuild the matcher.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Matcher`] if the masking automaton cannot be
    /// rebuilt for the new value set.
    pub fn insert(
        &mut self,
        placeholder: Placeholder,
        secret: SecretValue,
    ) -> Result<(), SecretStoreError> {
        self.by_placeholder.insert(placeholder, secret);
        self.rebuild_matcher()
    }

    /// Resolve a placeholder token to its secret bytes, if known.
    #[must_use]
    pub fn resolve(&self, placeholder: &str) -> Option<&[u8]> {
        self.by_placeholder
            .get(placeholder)
            .map(SecretValue::expose)
    }

    /// Iterate stored `(placeholder, secret bytes)` pairs, ordered by
    /// placeholder.
    pub fn iter(&self) -> impl Iterator<Item = (&Placeholder, &[u8])> {
        self.by_placeholder
            .iter()
            .map(|(placeholder, value)| (placeholder, value.expose()))
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

    /// Find every occurrence of a stored secret value in `haystack`.
    ///
    /// Matches are leftmost-longest and non-overlapping: at any position the
    /// longest secret wins, so a secret that is a substring of a longer one does
    /// not produce a spurious inner match. Returns an empty vector when the
    /// store is empty.
    pub fn mask_matches<'a>(
        &'a self,
        haystack: &'a [u8],
    ) -> impl Iterator<Item = MaskMatch<'a>> + 'a {
        let Some(matcher) = self.matcher.as_ref() else {
            return Either::Left(None.into_iter());
        };
        Either::Right(matcher.find_iter(haystack).filter_map(|m| {
            self.pattern_placeholders
                .get(m.pattern().as_usize())
                .map(|placeholder| MaskMatch {
                    start: m.start(),
                    end: m.end(),
                    placeholder,
                })
        }))
    }

    /// Find every occurrence of a stored placeholder token in `haystack`.
    ///
    /// The inverse of [`SecretStore::mask_matches`]: matches are leftmost-longest
    /// and non-overlapping, and each carries the secret bytes the token resolves
    /// to. Tokens that are not in the store never match, so an unknown
    /// placeholder passes through untouched (the caller substitutes nothing —
    /// fail closed). Returns an empty vector when the store is empty.
    pub fn rehydrate_matches<'a>(
        &'a self,
        haystack: &'a [u8],
    ) -> impl Iterator<Item = RehydrateMatch<'a>> + 'a {
        let Some(matcher) = self.rehydrate_matcher.as_ref() else {
            return Either::Left(None.into_iter());
        };
        Either::Right(matcher.find_iter(haystack).filter_map(|m| {
            let placeholder = self.rehydrate_placeholders.get(m.pattern().as_usize())?;
            let secret = self.by_placeholder.get(placeholder)?.expose();
            Some(RehydrateMatch {
                start: m.start(),
                end: m.end(),
                secret,
            })
        }))
    }

    /// Length in bytes of the longest stored secret value (0 if empty).
    ///
    /// The masking overlap buffer must retain `max_secret_len - 1` bytes so a
    /// secret split across reads is not missed.
    #[must_use]
    pub fn max_secret_len(&self) -> usize {
        self.by_placeholder
            .values()
            .map(SecretValue::len)
            .max()
            .unwrap_or(0)
    }

    /// Length in bytes of the longest stored placeholder token (0 if empty).
    ///
    /// The rehydration overlap buffer must retain `max_placeholder_len - 1`
    /// bytes so a token split across reads is not missed.
    #[must_use]
    pub fn max_placeholder_len(&self) -> usize {
        self.by_placeholder
            .keys()
            .map(|placeholder| placeholder.as_str().len())
            .max()
            .unwrap_or(0)
    }

    /// Rebuild both the masking and rehydration automatons after a change.
    fn rebuild_matcher(&mut self) -> Result<(), SecretStoreError> {
        self.rebuild_mask_matcher()?;
        self.rebuild_rehydrate_matcher()
    }

    /// Rebuild the masking automaton (secret value → placeholder) from the
    /// current value set.
    ///
    /// Empty secret values are skipped (an empty pattern has no meaningful
    /// match). Patterns are ordered by placeholder for deterministic pattern
    /// indices and tie-breaking.
    fn rebuild_mask_matcher(&mut self) -> Result<(), SecretStoreError> {
        let mut entries: Vec<(&Placeholder, &[u8])> = self
            .by_placeholder
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(placeholder, value)| (placeholder, value.expose()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        if entries.is_empty() {
            self.matcher = None;
            self.pattern_placeholders = Vec::new();
            return Ok(());
        }

        let patterns: Vec<&[u8]> = entries.iter().map(|(_, value)| *value).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|error| SecretStoreError::Matcher(error.to_string()))?;

        self.pattern_placeholders = entries
            .iter()
            .map(|(placeholder, _)| (*placeholder).clone())
            .collect();
        self.matcher = Some(matcher);
        Ok(())
    }

    /// Rebuild the rehydration automaton (placeholder token → secret value).
    ///
    /// Every placeholder is a non-empty token, so all keys are included; the
    /// resolved secret may itself be empty, which rehydrates to nothing. Keys
    /// come from a `BTreeMap`, so pattern indices are already deterministic.
    fn rebuild_rehydrate_matcher(&mut self) -> Result<(), SecretStoreError> {
        if self.by_placeholder.is_empty() {
            self.rehydrate_matcher = None;
            self.rehydrate_placeholders = Vec::new();
            return Ok(());
        }

        let placeholders: Vec<&Placeholder> = self.by_placeholder.keys().collect();
        let patterns: Vec<&[u8]> = placeholders
            .iter()
            .map(|placeholder| placeholder.as_str().as_bytes())
            .collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|error| SecretStoreError::Matcher(error.to_string()))?;

        self.rehydrate_placeholders = placeholders.into_iter().cloned().collect();
        self.rehydrate_matcher = Some(matcher);
        Ok(())
    }
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'%')
}

fn encode_segment(input: &str, out: &mut String) {
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0f));
        }
    }
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn mint_encodes_reserved_bytes_and_roundtrips() {
        // Space, `:` and unicode fall outside the unreserved set; `/` inside a
        // segment is escaped so the only literal `/` is the provider/name boundary.
        let placeholder = Placeholder::mint("bitwarden", "db/prod pw:é");
        assert_eq!(
            placeholder.as_str(),
            "firma-secret://bitwarden/db%2Fprod%20pw%3A%C3%A9"
        );
        // The minted token is itself a valid, parseable placeholder.
        assert_eq!(Placeholder::parse(placeholder.as_str()), Some(placeholder));
    }

    #[test]
    fn parse_rejects_bad_scheme_empty_body_and_illegal_byte() {
        // Wrong scheme.
        assert_eq!(Placeholder::parse("https://bitwarden/x"), None);
        // Correct scheme but empty body.
        assert_eq!(Placeholder::parse(PLACEHOLDER_SCHEME), None);
        // Byte outside the token charset (space is not `%`-escaped here).
        assert_eq!(Placeholder::parse("firma-secret://bitwarden/a b"), None);
    }

    #[test]
    fn resolve_returns_inserted_value_and_none_for_unknown() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store
            .insert(placeholder.clone(), SecretValue::from("s3cr3t"))
            .unwrap();

        assert_eq!(store.resolve(placeholder.as_str()), Some(&b"s3cr3t"[..]));
        assert_eq!(store.resolve("firma-secret://bitwarden/absent"), None);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn insert_replaces_existing_placeholder_and_updates_matcher() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store
            .insert(placeholder.clone(), SecretValue::from("old-value"))
            .unwrap();
        store
            .insert(placeholder.clone(), SecretValue::from("new-value"))
            .unwrap();

        assert_eq!(store.len(), 1);
        assert_eq!(store.resolve(placeholder.as_str()), Some(&b"new-value"[..]));
        // The stale value is no longer matched; the current one is.
        assert_eq!(store.mask_matches(b"has old-value here").count(), 0);
        let matches = store
            .mask_matches(b"has new-value here")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].placeholder, &placeholder);
    }

    #[test]
    fn mask_matches_locates_single_secret_with_offsets() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store
            .insert(placeholder.clone(), SecretValue::from("abc"))
            .unwrap();

        assert_eq!(
            store.mask_matches(b"xxabcyy").collect::<Vec<_>>(),
            vec![MaskMatch {
                start: 2,
                end: 5,
                placeholder: &placeholder,
            }]
        );
    }

    #[test]
    fn mask_matches_is_leftmost_longest_without_inner_match() {
        let mut store = SecretStore::new();
        let short = Placeholder::mint("bitwarden", "short");
        let long = Placeholder::mint("bitwarden", "long");
        store.insert(short, SecretValue::from("abc")).unwrap();
        store
            .insert(long.clone(), SecretValue::from("abcdef"))
            .unwrap();

        // The longer secret contains the shorter one; only the longest match at the
        // position is reported.
        let matches = store.mask_matches(b"_abcdef_").collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 1);
        assert_eq!(matches[0].end, 7);
        assert_eq!(matches[0].placeholder, &long);
    }

    #[test]
    fn mask_matches_reports_every_occurrence() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store.insert(placeholder, SecretValue::from("abc")).unwrap();

        let matches = store.mask_matches(b"abc-abc").collect::<Vec<_>>();
        assert_eq!(matches.len(), 2);
        assert_eq!((matches[0].start, matches[0].end), (0, 3));
        assert_eq!((matches[1].start, matches[1].end), (4, 7));
    }

    #[test]
    fn rehydrate_matches_locates_known_token_and_ignores_unknown() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store
            .insert(placeholder.clone(), SecretValue::from("s3cr3t"))
            .unwrap();

        let haystack = format!("login={placeholder} other=firma-secret://bitwarden/absent");
        let matches = store
            .rehydrate_matches(haystack.as_bytes())
            .collect::<Vec<_>>();
        // Only the known token resolves; the unknown one is left for passthrough.
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].secret, b"s3cr3t");
        assert_eq!(
            &haystack.as_bytes()[matches[0].start..matches[0].end],
            placeholder.as_str().as_bytes()
        );
    }

    #[test]
    fn rehydrate_matches_is_leftmost_longest() {
        let mut store = SecretStore::new();
        let short = Placeholder::mint("bw", "a");
        let long = Placeholder::mint("bw", "abc");
        store.insert(short, SecretValue::from("S")).unwrap();
        store
            .insert(long.clone(), SecretValue::from("LONG"))
            .unwrap();

        let matches = store
            .rehydrate_matches(long.as_str().as_bytes())
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].secret, b"LONG");
    }

    #[test]
    fn max_lengths_track_longest_entries() {
        let mut store = SecretStore::new();
        assert_eq!(store.max_secret_len(), 0);
        assert_eq!(store.max_placeholder_len(), 0);

        let short = Placeholder::mint("bw", "a");
        let long = Placeholder::mint("bw", "longer-name");
        store.insert(short, SecretValue::from("ab")).unwrap();
        store
            .insert(long.clone(), SecretValue::from("abcdef"))
            .unwrap();

        assert_eq!(store.max_secret_len(), 6);
        assert_eq!(store.max_placeholder_len(), long.as_str().len());
    }

    #[test]
    fn mask_matches_empty_store_returns_nothing() {
        let store = SecretStore::new();
        assert!(store.is_empty());
        assert_eq!(store.mask_matches(b"anything at all").count(), 0);
    }

    #[test]
    fn empty_secret_value_is_never_matched() {
        let mut store = SecretStore::new();
        store
            .insert(
                Placeholder::mint("bitwarden", "empty"),
                SecretValue::from(""),
            )
            .unwrap();

        // An empty value must not match at every position (or anywhere).
        assert_eq!(store.mask_matches(b"non-empty haystack").count(), 0);
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let secret = SecretValue::from("top-secret-token");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("top-secret-token"),
            "debug leaked the value: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }

    proptest! {
        /// Any minted token parses back to the same placeholder, and its body is
        /// composed only of token-charset bytes.
        #[test]
        fn mint_output_is_always_parseable(provider in ".*", name in ".*") {
            let minted = Placeholder::mint(&provider, &name);
            let reparsed = Placeholder::parse(minted.as_str());
            prop_assert_eq!(reparsed.as_ref(), Some(&minted));

            let body = minted
                .as_str()
                .strip_prefix(PLACEHOLDER_SCHEME)
                .expect("minted token carries the scheme");
            prop_assert!(
                body.bytes().all(|b| b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'_' | b'-' | b'/' | b'%'))
            );
        }
    }
}
