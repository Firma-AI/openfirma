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
use firma_core::SecretMatcher;
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
    /// The value and name paths selected a different number of nodes.
    #[error("json matcher selected {values} value(s) but {names} name(s); paths must align")]
    Misaligned {
        /// Number of value nodes.
        values: usize,
        /// Number of name nodes.
        names: usize,
    },
    /// The name path selected the right count of nodes, but a node was not a
    /// sibling of its corresponding value node.
    #[error(
        "json matcher name_path selected nodes under different parent elements than value_path; \
         paths must select sibling nodes"
    )]
    NameParentMismatch,
    /// The item path selected a different number of nodes than the value path.
    #[error(
        "json matcher item_path selected {items} node(s) but value_path selected {values}; \
         paths must align"
    )]
    ItemMisaligned {
        /// Number of value nodes.
        values: usize,
        /// Number of item nodes selected.
        items: usize,
    },
    /// The item path selected the right count of nodes, but a positional node
    /// was not a sibling of its corresponding value node.
    #[error(
        "json matcher item_path selected nodes under different parent elements than value_path; \
         paths must select sibling nodes"
    )]
    ItemParentMismatch,
    /// The domain path selected a different number of nodes than the value path.
    #[error(
        "json matcher domain_path selected {domains} node(s) but value_path selected {values}; \
         paths must align"
    )]
    DomainMisaligned {
        /// Number of value nodes.
        values: usize,
        /// Number of domain nodes selected.
        domains: usize,
    },
    /// The domain path selected the right count of nodes, but from different
    /// parent elements than the value path — a coincidental count match that
    /// would otherwise be silently zipped in the wrong order.
    #[error(
        "json matcher domain_path selected nodes under different parent elements than \
         value_path; paths must select sibling nodes"
    )]
    DomainParentMismatch,
    /// A selected value or name node was not a JSON string.
    #[error("json matcher: a selected value/name node is not a string")]
    NonStringNode,
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

/// Compiled `JSONPath` value/name selectors.
#[derive(Debug)]
pub struct CompiledJsonMatcher {
    /// Selects each secret value node.
    pub value: JsonPath,
    /// Selects each matching name node.
    pub name: JsonPath,
    /// Optional path selecting the item title (for structured-item stores).
    pub item: Option<JsonPath>,
    /// Optional path selecting the domain/hostname per item.
    pub domain: Option<JsonPath>,
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
                value_path,
                name_path,
                item_path,
                domain_path,
            } => {
                let value =
                    JsonPath::parse(value_path).map_err(|error| MatcherError::JsonPath {
                        path: value_path.clone(),
                        reason: error,
                    })?;
                let name = JsonPath::parse(name_path).map_err(|error| MatcherError::JsonPath {
                    path: name_path.clone(),
                    reason: error,
                })?;
                let parse_opt_path = |p: &str| {
                    JsonPath::parse(p).map_err(|error| MatcherError::JsonPath {
                        path: p.to_owned(),
                        reason: error,
                    })
                };
                let item = item_path.as_deref().map(parse_opt_path).transpose()?;
                let domain = domain_path.as_deref().map(parse_opt_path).transpose()?;
                Ok(Self::Json(CompiledJsonMatcher {
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
    /// - `domain`: hostname scope when `domain_path` is configured, else `None`.
    /// - `item`: item title when `item_path` is configured, else `None`.
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

/// Strip the last segment off a JSON Pointer, yielding the pointer to its
/// parent element (e.g. `/0/domain` -> `/0`).
fn parent_pointer(pointer: &str) -> &str {
    pointer.rfind('/').map_or("", |idx| &pointer[..idx])
}

struct ValueHit {
    pointer: String,
    parent_pointer: String,
    value: String,
}

#[derive(Clone, Copy)]
enum Selector {
    Name,
    Item,
    Domain,
}

impl Selector {
    fn misaligned(self, values: usize, selected: usize) -> MatcherError {
        match self {
            Self::Name => MatcherError::Misaligned {
                values,
                names: selected,
            },
            Self::Item => MatcherError::ItemMisaligned {
                values,
                items: selected,
            },
            Self::Domain => MatcherError::DomainMisaligned {
                values,
                domains: selected,
            },
        }
    }

    fn parent_mismatch(self) -> MatcherError {
        match self {
            Self::Name => MatcherError::NameParentMismatch,
            Self::Item => MatcherError::ItemParentMismatch,
            Self::Domain => MatcherError::DomainParentMismatch,
        }
    }
}

fn resolve_nodes<'a>(
    path: &JsonPath,
    root: &'a Value,
    values: &[ValueHit],
    selector: Selector,
    allow_shared: bool,
) -> Result<Vec<&'a Value>, MatcherError> {
    let located = path.query_located(root);
    if allow_shared && path.is_singular {
        if located.len() != 1 {
            return Err(selector.misaligned(values.len(), located.len()));
        }
        let Some(node) = located.iter().next() else {
            return Err(selector.misaligned(values.len(), 0));
        };
        return Ok(std::iter::repeat_n(node.node(), values.len()).collect());
    }

    if located.len() != values.len() {
        return Err(selector.misaligned(values.len(), located.len()));
    }

    located
        .iter()
        .zip(values)
        .map(|(node, value)| {
            let pointer = node.location().to_json_pointer();
            if parent_pointer(&pointer) != value.parent_pointer {
                return Err(selector.parent_mismatch());
            }
            Ok(node.node())
        })
        .collect()
}

fn resolve_domains(
    dp: &JsonPath,
    root: &Value,
    values: &[ValueHit],
) -> Result<Vec<Option<Authority>>, MatcherError> {
    resolve_nodes(dp, root, values, Selector::Domain, true)?
        .into_iter()
        .map(|node| node.as_str().map(validate_domain).transpose())
        .collect()
}

fn rewrite_json(
    output: &[u8],
    matcher: &CompiledJsonMatcher,
    mint: &mut impl FnMut(&str, Secret, Option<&Authority>, Option<&str>) -> String,
) -> Result<Vec<u8>, MatcherError> {
    let mut root: Value = serde_json::from_slice(output).map_err(MatcherError::Json)?;

    // Collect value-node JSON pointers + their string values, aligned names,
    // items, and optional domains — all before mutating (queries borrow `root`
    // immutably).
    let value_hits = matcher
        .value
        .query_located(&root)
        .iter()
        .map(|node| {
            let value = node
                .node()
                .as_str()
                .ok_or(MatcherError::NonStringNode)?
                .to_owned();
            let pointer = node.location().to_json_pointer();
            Ok(ValueHit {
                parent_pointer: parent_pointer(&pointer).to_owned(),
                pointer,
                value,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if value_hits.is_empty() {
        return Err(MatcherError::NoMatches);
    }
    let names = resolve_nodes(&matcher.name, &root, &value_hits, Selector::Name, false)?
        .into_iter()
        .map(|node| Ok(node.as_str().ok_or(MatcherError::NonStringNode)?.to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    let n = value_hits.len();

    let items = match &matcher.item {
        None => vec![None; n],
        Some(ip) => resolve_nodes(ip, &root, &value_hits, Selector::Item, true)?
            .into_iter()
            .map(|node| node.as_str().map(str::to_owned))
            .collect(),
    };

    let domains = match &matcher.domain {
        None => vec![None; n],
        Some(dp) => resolve_domains(dp, &root, &value_hits)?,
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
