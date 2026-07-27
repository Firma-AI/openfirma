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

/// Intercept transform: extract secrets from a vault CLI's output and rewrite
/// it so the agent sees placeholders.
pub mod intercept;

/// In-sandbox shim: send a tool-launch request to the out-of-sandbox broker.
pub mod shim;

/// URI scheme that prefixes every placeholder token.
pub const PLACEHOLDER_SCHEME: &str = "firma-secret://";

/// Marker in a `@placeholder` template that mint substitutes with the secret
/// key (percent-encoded).
pub const PLACEHOLDER_NAME_MARKER: &str = "{name}";

/// Optional marker substituted with the percent-encoded item title.
///
/// Used for structured-item stores (e.g. 1Password) where the placeholder
/// format is `firma-secret://<provider>/{item}/{name}`.
pub const PLACEHOLDER_ITEM_MARKER: &str = "{item}";

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

    /// Mint a placeholder by substituting markers in a `@placeholder` template.
    ///
    /// - [`PLACEHOLDER_NAME_MARKER`] (`{name}`) is always replaced with the
    ///   percent-encoded `name`.
    /// - [`PLACEHOLDER_ITEM_MARKER`] (`{item}`) is replaced with the
    ///   percent-encoded `item` when `item` is `Some`; if the template contains
    ///   `{item}` but `item` is `None` the marker is left unchanged (the caller
    ///   should validate the template against the matcher config at load time).
    ///
    /// The template is expected to be pre-validated (scheme present, markers
    /// present and consistent with the matcher), as enforced at Cedar bundle
    /// load.
    #[must_use]
    pub fn from_template(template: &str, item: Option<&str>, name: &str) -> Self {
        Self(firma_secret_provider::mint_placeholder(
            template, item, name,
        ))
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

/// A stored secret with its optional domain scope.
#[derive(Debug, Clone)]
struct SecretEntry {
    value: SecretValue,
    /// When `Some`, this secret is only returned for requests whose domain
    /// matches exactly. `None` means the secret is domain-agnostic (wildcard).
    domain: Option<String>,
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
    by_placeholder: BTreeMap<Placeholder, SecretEntry>,
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
        placeholder: Placeholder,
        domain: Option<String>,
        secret: SecretValue,
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
    pub fn resolve(&self, placeholder: &str, domain: &str) -> Option<&[u8]> {
        self.by_placeholder.get(placeholder).and_then(|entry| {
            entry
                .domain
                .as_deref()
                .is_none_or(|d| d == domain)
                .then_some(entry.value.expose())
        })
    }

    /// Iterate stored `(placeholder, secret bytes)` pairs, ordered by placeholder.
    pub fn iter(&self) -> impl Iterator<Item = (&Placeholder, &[u8])> {
        self.by_placeholder
            .iter()
            .map(|(placeholder, entry)| (placeholder, entry.value.expose()))
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
    fn wildcard_entry_resolves_for_any_domain() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store.insert(placeholder.clone(), None, SecretValue::from("s3cr3t"));

        assert_eq!(
            store.resolve(placeholder.as_str(), "api.github.com"),
            Some(&b"s3cr3t"[..])
        );
        assert_eq!(
            store.resolve(placeholder.as_str(), "api.stripe.com"),
            Some(&b"s3cr3t"[..])
        );
        assert_eq!(
            store.resolve("firma-secret://bitwarden/absent", "api.github.com"),
            None
        );
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn same_domain_insert_replaces_existing_entry() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store.insert(placeholder.clone(), None, SecretValue::from("old-value"));
        store.insert(placeholder.clone(), None, SecretValue::from("new-value"));

        assert_eq!(store.len(), 1);
        assert_eq!(
            store.resolve(placeholder.as_str(), "any.domain"),
            Some(&b"new-value"[..])
        );
    }

    #[test]
    fn domain_scoped_entry_does_not_match_wrong_domain() {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bitwarden", "token");
        store.insert(
            placeholder.clone(),
            Some("api.github.com".to_owned()),
            SecretValue::from("ghp_xxx"),
        );

        assert_eq!(
            store.resolve(placeholder.as_str(), "api.github.com"),
            Some(&b"ghp_xxx"[..])
        );
        assert_eq!(store.resolve(placeholder.as_str(), "api.stripe.com"), None);
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
