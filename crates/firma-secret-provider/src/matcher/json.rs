use std::{collections::HashSet, hash::Hash};

use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretNameSource};
use http::uri::Authority;
use serde_json::Value;
use serde_json_path::JsonPath;

use super::{MatcherError, domain::parse_authority, non_empty::NonEmptyStr};
use crate::{Secret, SecretPlaceholder};

/// Compiled record-relative `JSONPath` selectors.
#[derive(Debug)]
pub(super) struct CompiledJsonMatcher {
    record: JsonPath,
    value: JsonPath,
    name: CompiledName,
    item: Option<CompiledJsonSelector>,
    domain: Option<CompiledJsonSelector>,
}

/// Compiled form of [`SecretNameSource`].
#[derive(Debug)]
enum CompiledName {
    /// See [`SecretNameSource::Path`].
    Path(JsonPath),
    /// See [`SecretNameSource::RecordKey`].
    RecordKey,
}

impl CompiledName {
    fn compile(source: &SecretNameSource) -> Result<Self, MatcherError> {
        Ok(match source {
            SecretNameSource::Path { path } => Self::Path(parse_path(path)?),
            SecretNameSource::RecordKey => Self::RecordKey,
        })
    }
}

#[derive(Debug)]
struct CompiledJsonSelector {
    path: JsonPath,
    scope: SecretJsonSelectorScope,
}

struct Record<'a> {
    pointer: String,
    node: &'a Value,
}

struct ValueHit {
    pointer: String,
    value: String,
}

impl CompiledJsonMatcher {
    pub(super) fn compile(
        record_path: &str,
        value_path: &str,
        name: &SecretNameSource,
        item_selector: Option<&SecretJsonSelector>,
        domain_selector: Option<&SecretJsonSelector>,
    ) -> Result<Self, MatcherError> {
        Ok(Self {
            record: parse_path(record_path)?,
            value: parse_path(value_path)?,
            name: CompiledName::compile(name)?,
            item: item_selector
                .map(CompiledJsonSelector::compile)
                .transpose()?,
            domain: domain_selector
                .map(CompiledJsonSelector::compile)
                .transpose()?,
        })
    }

    pub(super) fn rewrite(
        &self,
        output: &[u8],
        mint: &mut impl FnMut(String, Secret, HashSet<Authority>, Option<String>) -> SecretPlaceholder,
    ) -> Result<Vec<u8>, MatcherError> {
        let mut root: Value = serde_json::from_slice(output).map_err(MatcherError::Json)?;

        // Resolve and validate the complete extraction before invoking `mint`.
        let records = self
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
                    one_record_node(&self.value, record, "value_path", record_index)?;
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
            .map(|(record_index, record)| match &self.name {
                CompiledName::Path(path) => {
                    let (node, _) = one_record_node(path, record, "name", record_index)?;
                    let node = node.as_str().ok_or(MatcherError::NonStringNode {
                        selector: "name",
                        record_index,
                    })?;

                    NonEmptyStr::new(node)
                        .map_err(|_| MatcherError::EmptyNode {
                            selector: "name",
                            record_index,
                        })
                        .map(|name| name.to_owned())
                }
                CompiledName::RecordKey => record_key_name(record, record_index),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let items = match &self.item {
            None => vec![None; records.len()],
            Some(selector) => selector.resolve_optional(
                &root,
                &records,
                "item_selector",
                |item, selector, record_index| {
                    let item = NonEmptyStr::new(item).map_err(|_| MatcherError::EmptyNode {
                        selector,
                        record_index,
                    })?;
                    Ok(item.to_owned())
                },
            )?,
        };
        let domains = match &self.domain {
            None => vec![HashSet::new(); records.len()],
            Some(selector) => {
                selector.resolve_many(&root, &records, "domain_selector", |domain, _, _| {
                    parse_authority(domain)
                })?
            }
        };

        for (((value_hit, name), item), domain) in
            value_hits.into_iter().zip(names).zip(items).zip(domains)
        {
            let placeholder = mint(
                name,
                Secret::new(value_hit.value.into_bytes()),
                domain,
                item,
            );
            if let Some(slot) = root.pointer_mut(&value_hit.pointer) {
                *slot = Value::String(placeholder.to_string());
            }
        }

        serde_json::to_vec(&root).map_err(MatcherError::Serialize)
    }
}

impl CompiledJsonSelector {
    fn compile(selector: &SecretJsonSelector) -> Result<Self, MatcherError> {
        Ok(Self {
            path: parse_path(&selector.path)?,
            scope: selector.scope,
        })
    }

    fn resolve_optional<T: Clone>(
        &self,
        root: &Value,
        records: &[Record<'_>],
        selector_name: &'static str,
        validate: impl Fn(&str, &'static str, usize) -> Result<T, MatcherError>,
    ) -> Result<Vec<Option<T>>, MatcherError> {
        match self.scope {
            SecretJsonSelectorScope::Record => records
                .iter()
                .enumerate()
                .map(|(record_index, record)| {
                    let (node, _) =
                        one_record_node(&self.path, record, selector_name, record_index)?;
                    node.as_str()
                        .map(|node| validate(node, selector_name, record_index))
                        .transpose()
                })
                .collect(),
            SecretJsonSelectorScope::Document => {
                let nodes = self.path.query(root);
                if nodes.len() != 1 {
                    return Err(MatcherError::DocumentSelectorMatchCount {
                        selector: selector_name,
                        matches: nodes.len(),
                    });
                }
                let value = nodes
                    .iter()
                    .next()
                    .and_then(|node| node.as_str().map(|node| validate(node, selector_name, 0)))
                    .transpose()?;
                Ok(std::iter::repeat_n(value, records.len()).collect())
            }
        }
    }

    /// Like [`Self::resolve_optional`], but accepts any number of matched
    /// nodes rather than requiring exactly one: every string node
    /// contributes an entry, non-string nodes are skipped, and zero matches
    /// yield an empty list. Used for `domain_selector`, where a secret may
    /// legitimately be scoped to more than one host.
    fn resolve_many<T>(
        &self,
        root: &Value,
        records: &[Record<'_>],
        selector_name: &'static str,
        validate: impl Fn(&str, &'static str, usize) -> Result<T, MatcherError>,
    ) -> Result<Vec<HashSet<T>>, MatcherError>
    where
        T: Clone + Eq + Hash,
    {
        match self.scope {
            SecretJsonSelectorScope::Record => records
                .iter()
                .enumerate()
                .map(|(record_index, record)| {
                    self.path
                        .query(record.node)
                        .iter()
                        .filter_map(|node| node.as_str())
                        .map(|node| validate(node, selector_name, record_index))
                        .collect()
                })
                .collect(),
            SecretJsonSelectorScope::Document => {
                let values = self
                    .path
                    .query(root)
                    .iter()
                    .filter_map(|node| node.as_str())
                    .map(|node| validate(node, selector_name, 0))
                    .collect::<Result<HashSet<_>, _>>()?;
                Ok(std::iter::repeat_n(values, records.len()).collect())
            }
        }
    }
}

fn parse_path(path: &str) -> Result<JsonPath, MatcherError> {
    JsonPath::parse(path).map_err(|reason| MatcherError::JsonPath {
        path: path.to_owned(),
        reason,
    })
}

/// Derives a [`SecretNameSource::RecordKey`] name from a record's own
/// `record_path`-selected location: the final segment of its JSON Pointer,
/// unescaped per RFC 6901. Fails if the record has no parent key (e.g.
/// `record_path` selected the whole document as a single record).
fn record_key_name(record: &Record<'_>, record_index: usize) -> Result<String, MatcherError> {
    if record.pointer.is_empty() {
        return Err(MatcherError::RecordKeyUnavailable { record_index });
    }
    let segment = record.pointer.rsplit('/').next().unwrap_or_default();
    let name = segment.replace("~1", "/").replace("~0", "~");

    NonEmptyStr::new(&name)
        .map_err(|_| MatcherError::EmptyNode {
            selector: "name",
            record_index,
        })
        .map(|name| name.to_owned())
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
