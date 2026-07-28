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

use std::str::FromStr;

use either::Either;
use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher};
use http::{
    Uri,
    uri::{Authority, InvalidUri},
};

use regex::Regex;
use serde_json::Value;
use serde_json_path::ParseError;

use crate::Secret;

use jsonpath::JsonPath;
mod jsonpath;

const NAME: &str = "name";
const VALUE: &str = "value";
const DOMAIN: &str = "domain";

/// Errors from compiling or executing a [`SecretMatcher`].
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

/// A compiled, ready-to-run secret matcher.
#[derive(Debug)]
pub enum CompiledMatcher {
    /// Extracts secrets via `JSONPath` value/name selectors over a JSON body.
    Json(CompiledJsonMatcher),
    /// Extracts secrets via a regex with `value` and `name` named groups over raw text.
    Regex(CompiledRegexMatcher),
}

/// Compiled record-relative `JSONPath` selectors.
#[derive(Debug)]
pub struct CompiledJsonMatcher {
    record: JsonPath,
    value: JsonPath,
    name: JsonPath,
    item: Option<CompiledJsonSelector>,
    domain: Option<CompiledJsonSelector>,
}

#[derive(Debug)]
struct CompiledJsonSelector {
    path: JsonPath,
    scope: SecretJsonSelectorScope,
}

/// Compiled regex with `value` and `name` named groups.
#[derive(Debug)]
pub struct CompiledRegexMatcher {
    /// The compiled pattern.
    pub pattern: Regex,
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
            } => {
                let parse_path = |path: &str| {
                    JsonPath::parse(path).map_err(|error| MatcherError::JsonPath {
                        path: path.to_owned(),
                        reason: error,
                    })
                };
                let compile_selector = |selector: &SecretJsonSelector| {
                    Ok(CompiledJsonSelector {
                        path: parse_path(&selector.path)?,
                        scope: selector.scope,
                    })
                };
                let record = parse_path(record_path)?;
                let value = parse_path(value_path)?;
                let name = parse_path(name_path)?;
                let item = item_selector.as_ref().map(compile_selector).transpose()?;
                let domain = domain_selector.as_ref().map(compile_selector).transpose()?;
                Ok(Self::Json(CompiledJsonMatcher {
                    record,
                    value,
                    name,
                    item,
                    domain,
                }))
            }
            SecretMatcher::Regex { pattern } => {
                let pattern = Regex::new(pattern).map_err(MatcherError::Regex)?;
                let groups = get_groups(&pattern);
                if !groups.contains(&VALUE) {
                    return Err(MatcherError::MissingGroup {
                        missing: VALUE,
                        found: groups.join(", "),
                    });
                }
                if !groups.contains(&NAME) {
                    return Err(MatcherError::MissingGroup {
                        missing: NAME,
                        found: groups.join(", "),
                    });
                }
                Ok(Self::Regex(CompiledRegexMatcher { pattern }))
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
            Self::Json(matcher) => rewrite_json(output, matcher, mint),
            Self::Regex(matcher) => rewrite_regex(output, matcher, mint),
        }
    }
}

struct Record<'a> {
    pointer: String,
    node: &'a Value,
}

struct ValueHit {
    pointer: String,
    value: String,
}

fn one_record_node<'a>(
    path: &JsonPath,
    record: &'a Record<'a>,
    selector: &'static str,
    record_index: usize,
) -> Result<(&'a Value, String), MatcherError> {
    let located = path.query_located(record.node);
    if located.len() != 1 {
        return Err(MatcherError::RecordSelectorMatchCount {
            selector,
            record_index,
            matches: located.len(),
        });
    }
    let Some(node) = located.iter().next() else {
        return Err(MatcherError::RecordSelectorMatchCount {
            selector,
            record_index,
            matches: 0,
        });
    };
    let relative_pointer = node.location().to_json_pointer();
    let absolute_pointer = match (record.pointer.is_empty(), relative_pointer.is_empty()) {
        (true, _) => relative_pointer,
        (_, true) => record.pointer.clone(),
        (false, false) => format!("{}{relative_pointer}", record.pointer),
    };
    Ok((node.node(), absolute_pointer))
}

fn optional_strings(
    selector: &CompiledJsonSelector,
    root: &Value,
    records: &[Record<'_>],
    selector_name: &'static str,
) -> Result<Vec<Option<String>>, MatcherError> {
    match selector.scope {
        SecretJsonSelectorScope::Record => records
            .iter()
            .enumerate()
            .map(|(record_index, record)| {
                one_record_node(&selector.path, record, selector_name, record_index)
                    .map(|(node, _)| node.as_str().map(str::to_owned))
            })
            .collect(),
        SecretJsonSelectorScope::Document => {
            let nodes = selector.path.query(root);
            if nodes.len() != 1 {
                return Err(MatcherError::DocumentSelectorMatchCount {
                    selector: selector_name,
                    matches: nodes.len(),
                });
            }
            let value = nodes
                .iter()
                .next()
                .and_then(|node| node.as_str())
                .map(str::to_owned);
            Ok(std::iter::repeat_n(value, records.len()).collect())
        }
    }
}

fn rewrite_json(
    output: &[u8],
    matcher: &CompiledJsonMatcher,
    mint: &mut impl FnMut(&str, Secret, Option<&Authority>, Option<&str>) -> String,
) -> Result<Vec<u8>, MatcherError> {
    let mut root: Value = serde_json::from_slice(output).map_err(MatcherError::Json)?;

    // Resolve and validate the complete extraction before invoking `mint`.
    let records = matcher
        .record
        .query_located(&root)
        .iter()
        .map(|node| Record {
            pointer: node.location().to_json_pointer(),
            node: node.node(),
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return Err(MatcherError::NoRecords);
    }

    let value_hits = records
        .iter()
        .enumerate()
        .map(|(record_index, record)| {
            let (node, pointer) =
                one_record_node(&matcher.value, record, "value_path", record_index)?;
            let value = node
                .as_str()
                .ok_or(MatcherError::NonStringNode {
                    selector: "value_path",
                    record_index,
                })?
                .to_owned();
            Ok(ValueHit { pointer, value })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let names = records
        .iter()
        .enumerate()
        .map(|(record_index, record)| {
            let (node, _) = one_record_node(&matcher.name, record, "name_path", record_index)?;
            node.as_str()
                .ok_or(MatcherError::NonStringNode {
                    selector: "name_path",
                    record_index,
                })
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let items = match &matcher.item {
        None => vec![None; records.len()],
        Some(selector) => optional_strings(selector, &root, &records, "item_selector")?,
    };
    let domains = match &matcher.domain {
        None => vec![None; records.len()],
        Some(selector) => optional_strings(selector, &root, &records, "domain_selector")?
            .into_iter()
            .map(|domain| domain.as_deref().map(validate_domain).transpose())
            .collect::<Result<Vec<_>, _>>()?,
    };

    for (((value_hit, name), item), domain) in
        value_hits.into_iter().zip(names).zip(items).zip(domains)
    {
        let placeholder = mint(
            &name,
            Secret::new(&value_hit.value),
            domain.as_ref(),
            item.as_deref(),
        );
        if let Some(slot) = root.pointer_mut(&value_hit.pointer) {
            *slot = Value::String(placeholder);
        }
    }

    serde_json::to_vec(&root).map_err(MatcherError::Serialize)
}

/// Extract the host (and port, if non-standard) from a URL string.
///
/// Strips the scheme prefix and any path/query/fragment suffix. Intended for
/// converting vault-stored URLs like `https://github.com` into the bare hostname
/// `github.com` that matches HTTP `Host` headers.
fn validate_domain(url: &str) -> Result<Authority, MatcherError> {
    if let Ok(authority) = Authority::from_str(url) {
        return anonymize(&authority).map_err(|error| MatcherError::InvalidUri {
            uri: strip_params(url),
            error,
        });
    }

    let uri = Uri::from_str(url).map_err(|error| MatcherError::InvalidUri {
        uri: strip_params(url),
        error,
    })?;
    let authority = uri
        .authority()
        .ok_or_else(|| MatcherError::NoHostInUri(strip_params(url)))?;
    anonymize(authority).map_err(|error| MatcherError::InvalidUri {
        uri: strip_params(url),
        error,
    })
}

/// strips credentials from Authority
#[inline]
fn anonymize(authority: &Authority) -> Result<Authority, InvalidUri> {
    authority.as_str().split_once('@').map_or_else(
        || Ok(authority.clone()),
        |(_credentials, domain)| Authority::from_str(domain),
    )
}

/// Strip params from url to avoid leaking secrets
fn strip_params(url: &str) -> String {
    let url = url.split_once('?').map_or(url, |(base, _params)| base);
    let Some((credentials, domain)) = url.split_once('@') else {
        return url.to_owned();
    };
    format!(
        "{}{domain}",
        credentials
            .find("://")
            .map_or("", |pos| &credentials[0..pos + 3])
    )
}

fn rewrite_regex(
    output: &[u8],
    matcher: &CompiledRegexMatcher,
    mint: &mut impl FnMut(&str, Secret, Option<&Authority>, Option<&str>) -> String,
) -> Result<Vec<u8>, MatcherError> {
    enum Item<'a> {
        Str(&'a str),
        // Regex matchers are for flat KV stores; item is always absent.
        Mint {
            name: String,
            secret: String,
            domain: Option<Authority>,
        },
    }

    let text = std::str::from_utf8(output).map_err(|_| MatcherError::NotUtf8)?;
    let has_domain = matcher
        .pattern
        .capture_names()
        .any(|name| name.is_some_and(|name| name == DOMAIN));
    let mut items = Vec::new();
    let mut last = 0usize;
    for caps in matcher.pattern.captures_iter(text) {
        let value = caps.name(VALUE).ok_or_else(|| MatcherError::MissingGroup {
            missing: VALUE,
            found: get_groups(&matcher.pattern).join(", "),
        })?;
        let name = caps.name(NAME).ok_or_else(|| MatcherError::MissingGroup {
            missing: NAME,
            found: get_groups(&matcher.pattern).join(", "),
        })?;
        let domain = match caps.name(DOMAIN) {
            Some(m) => Some(validate_domain(m.as_str())?),
            None if has_domain => {
                return Err(MatcherError::NoDomainMatched);
            }
            None => None,
        };

        items.push(Item::Str(&text[last..value.start()]));
        items.push(Item::Mint {
            name: name.as_str().to_owned(),
            secret: value.as_str().to_owned(),
            domain,
        });
        last = value.end();
    }
    if last == 0 {
        return Err(MatcherError::NoMatches);
    }
    items.push(Item::Str(&text[last..]));

    Ok(items
        .into_iter()
        .flat_map(|item| match item {
            Item::Str(str) => Either::Left(str.as_bytes().iter().copied()),
            Item::Mint {
                name,
                secret,
                domain,
            } => Either::Right(
                mint(&name, Secret::new(&secret), domain.as_ref(), None)
                    .into_bytes()
                    .into_iter(),
            ),
        })
        .collect())
}

fn get_groups(pattern: &Regex) -> Vec<&str> {
    pattern.capture_names().flatten().collect()
}
