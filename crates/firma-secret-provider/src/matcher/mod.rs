//! Compiled secret matchers.
//!
//! A [`SecretMatcher`] spec (from a `secret_providers` config entry) is
//! compiled once to **validate** it — a bad `JSONPath` or `Regex` is rejected
//! at config-resolution time — and again to **execute** it. Execution is
//! transport-agnostic: it extracts `(name, value)` pairs from a raw byte
//! buffer and rewrites it with placeholders supplied by a mint callback, so
//! the agent only ever sees placeholders. Used by `firma-run`'s broker for
//! CLI vault stdout and by `firma-sidecar`'s HTTPS MITM path for HTTP vault
//! response bodies. See `docs/architecture/secrets-interception.md`.

mod domain;
mod error;
mod json;
mod regex;

use firma_core::SecretMatcher;
use http::uri::Authority;

use crate::Secret;

pub use error::MatcherError;
pub use json::CompiledJsonMatcher;
pub use regex::CompiledRegexMatcher;

/// A compiled, ready-to-run secret matcher.
#[derive(Debug)]
pub enum CompiledMatcher {
    /// Extracts secrets via `JSONPath` value/name selectors over a JSON body.
    Json(CompiledJsonMatcher),
    /// Extracts secrets via a regex with `value` and `name` named groups over raw text.
    Regex(CompiledRegexMatcher),
}

impl CompiledMatcher {
    /// Compile and validate a matcher spec.
    ///
    /// # Errors
    ///
    /// Returns [`MatcherError`] for an invalid `JSONPath`, an invalid `Regex`, or a
    /// `Regex` missing its required `value` / `name` named capture groups.
    pub fn compile(spec: &SecretMatcher) -> Result<Self, MatcherError> {
        match spec {
            SecretMatcher::Json {
                record_path,
                value_path,
                name_path,
                item_selector,
                domain_selector,
            } => CompiledJsonMatcher::compile(
                record_path,
                value_path,
                name_path,
                item_selector.as_ref(),
                domain_selector.as_ref(),
            )
            .map(Self::Json),
            SecretMatcher::Regex { pattern } => {
                CompiledRegexMatcher::compile(pattern).map(Self::Regex)
            }
        }
    }

    /// Extract secrets from `output` and return it rewritten with placeholders.
    ///
    /// `mint(name, value, domain, item) -> placeholder` is invoked once per
    /// extracted secret:
    /// - `name`: field label (always present).
    /// - `value`: plaintext secret.
    /// - `domain`: hostname scope when `domain_selector` is configured, else `None`.
    /// - `item`: item title when `item_selector` is configured, else `None`.
    ///
    /// The caller mints and stores the `placeholder → value` mapping and returns
    /// the placeholder to substitute in place of the value.
    ///
    /// # Errors
    ///
    /// Returns [`MatcherError`] if the output does not match the matcher's shape
    /// (bad JSON / UTF-8, non-string or misaligned nodes) or re-serialization
    /// fails.
    pub fn rewrite(
        &self,
        output: &[u8],
        mint: &mut impl FnMut(&str, Secret, Option<&Authority>, Option<&str>) -> String,
    ) -> Result<Vec<u8>, MatcherError> {
        match self {
            Self::Json(matcher) => matcher.rewrite(output, mint),
            Self::Regex(matcher) => matcher.rewrite(output, mint),
        }
    }
}
