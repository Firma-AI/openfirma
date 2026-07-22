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

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

/// Out-of-sandbox broker transport (JSON line protocol).
/// Supports Unix domain sockets and TCP loopback.
pub mod broker;

/// Secret resolution gateway for the Sidecar MITM pipeline.
///
/// Resolves placeholder tokens on demand so firma-run remains the single source
/// of truth. Supports Unix domain sockets and TCP loopback.
pub mod gateway;

/// Broker → Sidecar policy-enforcement-point client for secret mediation
/// decisions, with fail-closed semantics.
pub mod pep;

/// Intercept transform: extract secrets from a vault CLI's output and rewrite
/// it so the agent sees placeholders.
pub mod intercept;

/// Built-in integration specs for supported vault CLIs (bws, op, vault, doppler).
pub mod integration;

/// Per-request broker dispatch: run the real vault CLI and apply the intercept
/// transform by decision (fail-closed).
pub mod serve;

/// In-sandbox shim: send a tool-launch request to the out-of-sandbox broker.
pub mod shim;

/// Broker accept loop: accept shim connections, decide, and serve them.
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

/// In-memory placeholder ↔ secret dictionary.
///
/// The dictionary is run-scoped: values are zeroized when the store is dropped.
#[derive(Debug, Clone, Default)]
pub struct SecretStore {
    by_placeholder: BTreeMap<Placeholder, SecretValue>,
}

impl SecretStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a placeholder → secret mapping.
    pub fn insert(&mut self, placeholder: Placeholder, secret: SecretValue) {
        self.by_placeholder.insert(placeholder, secret);
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
        assert_eq!(Placeholder::parse(placeholder.as_str()), Some(placeholder));
    }

    #[test]
    fn parse_rejects_bad_scheme_empty_body_and_illegal_byte() {
        assert_eq!(Placeholder::parse("https://bitwarden/x"), None);
        assert_eq!(Placeholder::parse(PLACEHOLDER_SCHEME), None);
        assert_eq!(Placeholder::parse("firma-secret://bitwarden/a b"), None);
    }

    #[test]
    fn resolve_returns_inserted_value_and_none_for_unknown() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store.insert(placeholder.clone(), SecretValue::from("s3cr3t"));

        assert_eq!(store.resolve(placeholder.as_str()), Some(&b"s3cr3t"[..]));
        assert_eq!(store.resolve("firma-secret://bitwarden/absent"), None);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn insert_replaces_existing_placeholder() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store.insert(placeholder.clone(), SecretValue::from("old-value"));
        store.insert(placeholder.clone(), SecretValue::from("new-value"));

        assert_eq!(store.len(), 1);
        assert_eq!(store.resolve(placeholder.as_str()), Some(&b"new-value"[..]));
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
}
