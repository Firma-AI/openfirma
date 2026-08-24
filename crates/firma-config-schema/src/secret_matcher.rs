//! Schema for secret-extraction matchers.
//!
//! Representation only: how to extract `(name, value)` pairs from a vault
//! CLI's stdout or an HTTP vault's response body. The execution (`JSONPath` /
//! `Regex` compilation and rewrite) lives in `firma-secret-provider`; these
//! types are the concrete configuration a user writes.

use serde::{Deserialize, Serialize};

/// How to extract `(name, value)` pairs from a vault CLI's stdout or an
/// HTTP vault's response body.
///
/// Internally tagged (`{"type": "json", ...}` rather than the default
/// `{"Json": {...}}`) so it nests as a flat table when embedded in TOML (e.g.
/// the Sidecar's `http_secret_providers` config) as well as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretMatcher {
    /// `JSONPath` extraction over structured output.
    Json {
        /// `JSONPath` evaluated once against the document root to select each
        /// logical secret record.
        record_path: String,
        /// Record-relative `JSONPath` selecting the matching value
        /// (`@match_value`). It must select exactly one string from each record.
        value_path: String,
        /// How the matching name is derived for each record, aligned by
        /// document order with the value path.
        name: SecretNameSource,
        /// Optional scoped selector for the structured-item title. A
        /// record-scoped selector must match exactly one node per record. A
        /// document-scoped selector may match zero or one node; its value is
        /// broadcast to every record. For either scope, a selected non-string
        /// node leaves the item absent, while an empty string is rejected.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_selector: Option<SecretJsonSelector>,
        /// Optional scoped selector for the domain(s) associated with each
        /// secret. Unlike `item_selector`, this selector may match any number
        /// of nodes: a secret can legitimately be scoped to more than one
        /// host (e.g. several URLs on the same vault item), and each matched
        /// string node contributes one domain. String nodes are validated and
        /// normalized as HTTP authorities or URLs, then deduplicated. Once a
        /// selector is configured, every applicable root must yield at least
        /// one valid string domain: zero matches, non-string nodes, or invalid
        /// domains reject the complete rewrite before any placeholder is
        /// minted. Omit the selector to leave a secret unscoped.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_selector: Option<SecretJsonSelector>,
    },
    /// `Regex` extraction over text output. The pattern carries a required
    /// `value` and `name` named capture group, and an optional `domain` group
    /// (`@match_pattern`).
    Regex {
        /// The `Regex` source.
        pattern: String,
    },
}

/// How a JSON record's secret name is determined.
///
/// Most providers store the secret's name as an explicit string value (e.g. a
/// `label` or `key` field) selected by [`Path`](Self::Path). Some providers —
/// e.g. `HashiCorp` Vault's `kv get -format=json`, which returns a flat
/// `{name: value, ...}` secret map with no separate name field — instead
/// encode the name as the record's own key in its parent JSON object; use
/// [`RecordKey`](Self::RecordKey) when `record_path` selects records that way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SecretNameSource {
    /// Record-relative `JSONPath` selecting the name string, aligned by
    /// document order with `value_path`. Must select exactly one non-empty
    /// string per record.
    Path {
        /// The `JSONPath` expression.
        path: String,
    },
    /// The record's own key in its parent JSON object — the final segment of
    /// the record's `JSONPath`-selected location.
    RecordKey,
}

/// A `JSONPath` selector whose evaluation root is explicit.
///
/// The scope is part of the serialized shape, for example
/// `{"path":"$.title","scope":"document"}`; scope is never inferred from
/// `JSONPath` syntax. Cardinality depends on both the selector's role and its
/// scope: record-scoped item selectors require one match per record, while a
/// document-scoped item selector accepts zero or one match. Domain selectors
/// require one or more valid string matches at every applicable root. See the
/// field docs on [`SecretMatcher::Json`] for failure behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretJsonSelector {
    /// `JSONPath` evaluated at the root selected by [`Self::scope`].
    pub path: String,
    /// Whether the path is relative to each record or to the whole document.
    pub scope: SecretJsonSelectorScope,
}

/// Evaluation root for a [`SecretJsonSelector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretJsonSelectorScope {
    /// Evaluate independently against every node selected by `record_path`.
    Record,
    /// Evaluate once against the document root and broadcast the selector results.
    Document,
}
