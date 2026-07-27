//! Compiled secret matchers.
//!
//! A [`SecretMatcher`] spec (from a `secret_providers` config entry) is
//! compiled once to **validate** it — a bad `JSONPath` or `Regex` is rejected
//! at config-resolution time — and again to **execute** it. Execution is
//! transport-agnostic: it extracts `(name, value)` pairs from a raw byte
//! buffer and rewrites it with placeholders supplied by a mint callback, so
//! the agent only ever sees placeholders. Used by `firma-run`'s broker for
//! CLI vault stdout and by `firma-sidecar`'s HTTPS MITM path for HTTP vault
//! response bodies.

mod domain;
mod error;
mod json;
mod regex;

use std::collections::HashSet;

use firma_core::SecretMatcher;
use firma_http::Authority;

use crate::{SecretPlaceholder, SecretString};

pub use error::MatcherError;

use json::CompiledJsonMatcher;
use regex::CompiledRegexMatcher;

/// A compiled, ready-to-run secret matcher.
#[derive(Debug)]
pub struct CompiledMatcher {
    kind: MatcherKind,
}

#[derive(Debug)]
enum MatcherKind {
    Json(CompiledJsonMatcher),
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
                name,
                item_selector,
                domain_selector,
            } => CompiledJsonMatcher::compile(
                record_path,
                value_path,
                name,
                item_selector.as_ref(),
                domain_selector.as_ref(),
            )
            .map(MatcherKind::Json),
            SecretMatcher::Regex { pattern } => {
                CompiledRegexMatcher::compile(pattern).map(MatcherKind::Regex)
            }
        }
        .map(|kind| Self { kind })
    }

    /// Extract secrets from `output` and return it rewritten with placeholders.
    ///
    /// `mint(name, value, domains, item) -> placeholder` is invoked once per
    /// extracted secret:
    /// - `name`: field label (always present).
    /// - `value`: plaintext secret.
    /// - `domains`: hostname scopes when `domain_selector` is configured, else
    ///   empty. A secret may legitimately be scoped to more than one host
    ///   (e.g. a `domain_selector` matching several URLs on the same vault
    ///   item), so all of them are passed through; an empty set means the
    ///   secret is unscoped and resolves for any host.
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
        mint: &mut impl FnMut(
            String,
            SecretString,
            HashSet<Authority>,
            Option<String>,
        ) -> SecretPlaceholder,
    ) -> Result<Vec<u8>, MatcherError> {
        match &self.kind {
            MatcherKind::Json(matcher) => matcher.rewrite(output, mint),
            MatcherKind::Regex(matcher) => matcher.rewrite(output, mint),
        }
    }
}
