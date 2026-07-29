use http::uri::InvalidUri;
use serde_json_path::ParseError;

/// Errors from compiling or executing a secret matcher.
#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    /// A `JSONPath` expression failed to parse.
    #[error("invalid JSONPath `{path}`: {reason}")]
    JsonPath {
        /// The offending path.
        path: String,
        /// Parser message.
        #[source]
        reason: ParseError,
    },
    /// The regex failed to compile.
    #[error("invalid regex: {0}")]
    Regex(#[source] regex::Error),
    /// The regex miss a named capture group.
    #[error("regex matcher must contain a named `{missing}` capture group, found {found}")]
    MissingGroup {
        /// The name of the missing group.
        missing: &'static str,
        /// Available groups.
        found: String,
    },
    /// The regex matches an empty capture group.
    #[error("regex matches an empty capture group: `{0}`")]
    EmptyGroup(&'static str),
    /// The vault output was not valid JSON (json matcher).
    #[error("vault output is not valid JSON: {0}")]
    Json(#[source] serde_json::Error),
    /// The vault output was not valid UTF-8 (regex matcher).
    #[error("vault output is not valid UTF-8")]
    NotUtf8,
    /// The record selector did not identify any logical records.
    #[error("json matcher record_path selected no records")]
    NoRecords,
    /// A record-relative selector did not select exactly one node.
    #[error(
        "json matcher {selector} selected {matches} node(s) in record {record_index}; expected exactly one"
    )]
    RecordSelectorMatchCount {
        /// Name of the selector field.
        selector: &'static str,
        /// Zero-based index of the record selected by `record_path`.
        record_index: usize,
        /// Number of nodes selected within the record.
        matches: usize,
    },
    /// A document-scoped selector did not select exactly one node.
    #[error("json matcher {selector} selected {matches} document node(s); expected exactly one")]
    DocumentSelectorMatchCount {
        /// Name of the selector field.
        selector: &'static str,
        /// Number of nodes selected from the document root.
        matches: usize,
    },
    /// A selected value or name node was not a JSON string.
    #[error("json matcher {selector} selected a non-string node in record {record_index}")]
    NonStringNode {
        /// Name of the selector field.
        selector: &'static str,
        /// Zero-based index of the record selected by `record_path`.
        record_index: usize,
    },
    /// A selected value or name node was a whitespace string.
    #[error("json matcher {selector} selected a whitespace string in record {record_index}")]
    EmptyNode {
        /// Name of the selector field.
        selector: &'static str,
        /// Zero-based index of the record selected by `record_path`.
        record_index: usize,
    },
    /// Re-serializing the rewritten JSON failed.
    #[error("failed to serialize rewritten output: {0}")]
    Serialize(#[source] serde_json::Error),
    /// Found Uri is not valid.
    #[error("invalid uri {uri}: {error}")]
    InvalidUri {
        /// The offending Uri.
        uri: String,
        /// Error details.
        #[source]
        error: InvalidUri,
    },
    /// Found Uri has no host.
    #[error("no host uri {0}")]
    NoHostInUri(String),
    /// No matches found, probable misconfiguration.
    #[error("no matches")]
    NoMatches,
    /// Domain is configured but it didn't match the pattern.
    #[error("no domain matched")]
    NoDomainMatched,
}
