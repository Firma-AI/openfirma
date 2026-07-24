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

use firma_core::SecretMatcher;
use regex::Regex;
use serde_json::Value;
use serde_json_path::JsonPath;

/// Errors from compiling or executing a [`SecretMatcher`].
#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    /// A `JSONPath` expression failed to parse.
    #[error("invalid JSONPath `{path}`: {reason}")]
    JsonPath {
        /// The offending path.
        path: String,
        /// Parser message.
        reason: String,
    },
    /// The regex failed to compile.
    #[error("invalid regex: {0}")]
    Regex(String),
    /// The regex has no named `value` capture group.
    #[error("regex matcher must contain a named `value` capture group")]
    MissingValueGroup,
    /// The regex has no named `name` capture group.
    #[error("regex matcher must contain a named `name` capture group")]
    MissingNameGroup,
    /// The vault output was not valid JSON (json matcher).
    #[error("vault output is not valid JSON: {0}")]
    Json(String),
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
    /// A selected value or name node was not a JSON string.
    #[error("json matcher: a selected value/name node is not a string")]
    NonStringNode,
    /// Re-serializing the rewritten JSON failed.
    #[error("failed to serialize rewritten output: {0}")]
    Serialize(String),
}

/// A compiled, ready-to-run secret matcher.
#[derive(Debug)]
pub enum CompiledMatcher {
    /// Compiled `JSONPath` value/name selectors.
    Json {
        /// Selects each secret value node.
        value: JsonPath,
        /// Selects each matching name node.
        name: JsonPath,
        /// Optional path selecting the item title (for structured-item stores).
        item: Option<JsonPath>,
        /// Optional path selecting the domain/hostname per item.
        domain: Option<JsonPath>,
        /// When `true`, the domain node value is treated as a URL and only the
        /// host portion is extracted.
        domain_is_url: bool,
    },
    /// Compiled regex with `value` and `name` named groups.
    Regex {
        /// The compiled pattern.
        pattern: Regex,
        /// When `true` and the pattern has a `domain` capture group, the
        /// captured value is parsed as a URL and only the host portion is used.
        domain_is_url: bool,
    },
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
                domain_is_url,
            } => {
                let value =
                    JsonPath::parse(value_path).map_err(|error| MatcherError::JsonPath {
                        path: value_path.clone(),
                        reason: error.to_string(),
                    })?;
                let name = JsonPath::parse(name_path).map_err(|error| MatcherError::JsonPath {
                    path: name_path.clone(),
                    reason: error.to_string(),
                })?;
                let parse_opt_path = |p: &str| {
                    JsonPath::parse(p).map_err(|error| MatcherError::JsonPath {
                        path: p.to_owned(),
                        reason: error.to_string(),
                    })
                };
                let item = item_path.as_deref().map(parse_opt_path).transpose()?;
                let domain = domain_path.as_deref().map(parse_opt_path).transpose()?;
                Ok(Self::Json {
                    value,
                    name,
                    item,
                    domain,
                    domain_is_url: *domain_is_url,
                })
            }
            SecretMatcher::Regex {
                pattern,
                domain_is_url,
            } => {
                let pattern =
                    Regex::new(pattern).map_err(|error| MatcherError::Regex(error.to_string()))?;
                let groups: Vec<&str> = pattern.capture_names().flatten().collect();
                if !groups.contains(&"value") {
                    return Err(MatcherError::MissingValueGroup);
                }
                if !groups.contains(&"name") {
                    return Err(MatcherError::MissingNameGroup);
                }
                Ok(Self::Regex {
                    pattern,
                    domain_is_url: *domain_is_url,
                })
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
        mint: &mut impl FnMut(&str, &str, Option<&str>, Option<&str>) -> String,
    ) -> Result<Vec<u8>, MatcherError> {
        match self {
            Self::Json {
                value,
                name,
                item,
                domain,
                domain_is_url,
            } => rewrite_json(
                output,
                value,
                name,
                item.as_ref(),
                domain.as_ref(),
                *domain_is_url,
                mint,
            ),
            Self::Regex {
                pattern,
                domain_is_url,
            } => rewrite_regex(output, pattern, *domain_is_url, mint),
        }
    }
}

fn broadcast_optional_strings(
    raw: Vec<Option<String>>,
    value_count: usize,
) -> (Vec<Option<String>>, usize) {
    let n = raw.len();
    let expanded = match n {
        0 => vec![None; value_count],
        1 => vec![raw.into_iter().next().flatten(); value_count],
        _ if n == value_count => raw,
        _ => return (raw, n), // signal mismatch: return raw with its length
    };
    (expanded, value_count) // signal ok: returned len == value_count
}

fn rewrite_json(
    output: &[u8],
    value_path: &JsonPath,
    name_path: &JsonPath,
    item_path: Option<&JsonPath>,
    domain_path: Option<&JsonPath>,
    domain_is_url: bool,
    mint: &mut impl FnMut(&str, &str, Option<&str>, Option<&str>) -> String,
) -> Result<Vec<u8>, MatcherError> {
    let mut root: Value =
        serde_json::from_slice(output).map_err(|error| MatcherError::Json(error.to_string()))?;

    // Collect value-node JSON pointers + their string values, aligned names,
    // items, and optional domains — all before mutating (queries borrow `root`
    // immutably).
    let mut value_hits: Vec<(String, String)> = Vec::new();
    for node in value_path.query_located(&root).iter() {
        let value = node
            .node()
            .as_str()
            .ok_or(MatcherError::NonStringNode)?
            .to_owned();
        value_hits.push((node.location().to_json_pointer(), value));
    }
    let mut names: Vec<String> = Vec::new();
    for node in name_path.query(&root).iter() {
        names.push(node.as_str().ok_or(MatcherError::NonStringNode)?.to_owned());
    }
    if value_hits.len() != names.len() {
        return Err(MatcherError::Misaligned {
            values: value_hits.len(),
            names: names.len(),
        });
    }
    let n = value_hits.len();

    let items: Vec<Option<String>> = match item_path {
        None => vec![None; n],
        Some(ip) => {
            let raw: Vec<Option<String>> = ip
                .query(&root)
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect();
            let (expanded, ok_len) = broadcast_optional_strings(raw, n);
            if ok_len != n {
                return Err(MatcherError::ItemMisaligned {
                    values: n,
                    items: ok_len,
                });
            }
            expanded
        }
    };

    let domains: Vec<Option<String>> = match domain_path {
        None => vec![None; n],
        Some(dp) => {
            let raw: Vec<Option<String>> = dp
                .query(&root)
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect();
            let (expanded, ok_len) = broadcast_optional_strings(raw, n);
            if ok_len != n {
                return Err(MatcherError::DomainMisaligned {
                    values: n,
                    domains: ok_len,
                });
            }
            if domain_is_url {
                expanded
                    .into_iter()
                    .map(|d| d.map(|url| host_from_url_str(&url)))
                    .collect()
            } else {
                expanded
            }
        }
    };

    for ((((pointer, value), name), item), domain) in
        value_hits.into_iter().zip(names).zip(items).zip(domains)
    {
        let placeholder = mint(&name, &value, domain.as_deref(), item.as_deref());
        if let Some(slot) = root.pointer_mut(&pointer) {
            *slot = Value::String(placeholder);
        }
    }

    serde_json::to_vec(&root).map_err(|error| MatcherError::Serialize(error.to_string()))
}

/// Extract the host (and port, if non-standard) from a URL string.
///
/// Strips the scheme prefix and any path/query/fragment suffix. Intended for
/// converting vault-stored URLs like `https://github.com` into the bare hostname
/// `github.com` that matches HTTP `Host` headers.
fn host_from_url_str(url: &str) -> String {
    let after_scheme = url.find("://").map_or(url, |i| &url[i + 3..]);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme[..end].to_owned()
}

fn rewrite_regex(
    output: &[u8],
    pattern: &Regex,
    domain_is_url: bool,
    mint: &mut impl FnMut(&str, &str, Option<&str>, Option<&str>) -> String,
) -> Result<Vec<u8>, MatcherError> {
    let text = std::str::from_utf8(output).map_err(|_| MatcherError::NotUtf8)?;
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in pattern.captures_iter(text) {
        let value = caps.name("value").ok_or(MatcherError::MissingValueGroup)?;
        let name = caps.name("name").ok_or(MatcherError::MissingNameGroup)?;
        let domain: Option<String> = caps.name("domain").map(|m| {
            if domain_is_url {
                host_from_url_str(m.as_str())
            } else {
                m.as_str().to_owned()
            }
        });
        // Regex matchers are for flat KV stores; item is always absent.
        let placeholder = mint(name.as_str(), value.as_str(), domain.as_deref(), None);
        result.push_str(&text[last..value.start()]);
        result.push_str(&placeholder);
        last = value.end();
    }
    result.push_str(&text[last..]);
    Ok(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(value_path: &str, name_path: &str) -> SecretMatcher {
        SecretMatcher::Json {
            value_path: value_path.to_string(),
            name_path: name_path.to_string(),
            item_path: None,
            domain_path: None,
            domain_is_url: false,
        }
    }

    fn json_with_item(
        value_path: &str,
        name_path: &str,
        item_path: &str,
        domain_path: Option<&str>,
    ) -> SecretMatcher {
        SecretMatcher::Json {
            value_path: value_path.to_string(),
            name_path: name_path.to_string(),
            item_path: Some(item_path.to_string()),
            domain_path: domain_path.map(str::to_owned),
            domain_is_url: false,
        }
    }

    fn json_with_domain(value_path: &str, name_path: &str, domain_path: &str) -> SecretMatcher {
        SecretMatcher::Json {
            value_path: value_path.to_string(),
            name_path: name_path.to_string(),
            item_path: None,
            domain_path: Some(domain_path.to_string()),
            domain_is_url: false,
        }
    }

    fn json_with_url_domain(value_path: &str, name_path: &str, domain_path: &str) -> SecretMatcher {
        SecretMatcher::Json {
            value_path: value_path.to_string(),
            name_path: name_path.to_string(),
            item_path: None,
            domain_path: Some(domain_path.to_string()),
            domain_is_url: true,
        }
    }

    fn regex(pattern: &str) -> SecretMatcher {
        SecretMatcher::Regex {
            pattern: pattern.to_string(),
            domain_is_url: false,
        }
    }

    #[test]
    fn compile_rejects_bad_jsonpath_and_regex() {
        assert!(matches!(
            CompiledMatcher::compile(&json("$[", "$.key")),
            Err(MatcherError::JsonPath { .. })
        ));
        assert!(matches!(
            CompiledMatcher::compile(&regex("(")),
            Err(MatcherError::Regex(_))
        ));
    }

    #[test]
    fn compile_regex_requires_value_and_name_groups() {
        assert!(matches!(
            CompiledMatcher::compile(&regex("(?P<name>.+)")),
            Err(MatcherError::MissingValueGroup)
        ));
        assert!(matches!(
            CompiledMatcher::compile(&regex("(?P<value>.+)")),
            Err(MatcherError::MissingNameGroup)
        ));
        assert!(CompiledMatcher::compile(&regex("(?P<name>[^=]+)=(?P<value>.+)")).is_ok());
    }

    #[test]
    fn json_matcher_rewrites_values_and_reports_pairs() {
        let compiled = CompiledMatcher::compile(&json("$[*].value", "$[*].key")).unwrap();
        let mut pairs = Vec::new();
        let out = compiled
            .rewrite(
                br#"[{"key":"a","value":"AAA"},{"key":"b","value":"BBB"}]"#,
                &mut |name, value, _domain, _item| {
                    pairs.push((name.to_string(), value.to_string()));
                    format!("P:{name}")
                },
            )
            .unwrap();
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out[0]["value"], serde_json::json!("P:a"));
        assert_eq!(out[1]["value"], serde_json::json!("P:b"));
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "AAA".to_string()),
                ("b".to_string(), "BBB".to_string())
            ]
        );
    }

    #[test]
    fn json_matcher_rejects_misaligned_paths_and_bad_json() {
        let compiled = CompiledMatcher::compile(&json("$[*].value", "$[*].missing")).unwrap();
        assert!(matches!(
            compiled.rewrite(br#"[{"key":"a","value":"AAA"}]"#, &mut |_, _, _, _| {
                String::new()
            }),
            Err(MatcherError::Misaligned {
                values: 1,
                names: 0
            })
        ));

        let compiled = CompiledMatcher::compile(&json("$.value", "$.key")).unwrap();
        assert!(matches!(
            compiled.rewrite(b"not json", &mut |_, _, _, _| String::new()),
            Err(MatcherError::Json(_))
        ));
    }

    #[test]
    fn regex_matcher_rewrites_value_spans() {
        let compiled =
            CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
        let out = compiled
            .rewrite(b"a=AAA\nb=BBB\n", &mut |name, _, _, _| format!("P:{name}"))
            .unwrap();
        assert_eq!(out, b"a=P:a\nb=P:b\n");
    }

    #[test]
    fn regex_matcher_rejects_non_utf8() {
        let compiled = CompiledMatcher::compile(&regex(r"(?P<name>.)=(?P<value>.)")).unwrap();
        assert!(matches!(
            compiled.rewrite(&[0xff, 0xfe], &mut |_, _, _, _| String::new()),
            Err(MatcherError::NotUtf8)
        ));
    }

    #[test]
    fn regex_domain_group_passes_domain_to_mint() {
        let compiled = CompiledMatcher::compile(&regex(
            r"(?m)^(?P<name>[^=]+)=(?P<value>[^@]+)@(?P<domain>.+)$",
        ))
        .unwrap();
        let mut domains_seen: Vec<Option<String>> = Vec::new();
        let out = compiled
            .rewrite(
                b"token=ghp_abc@api.github.com\n",
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(str::to_owned));
                    "PLACEHOLDER".to_string()
                },
            )
            .unwrap();
        assert_eq!(out, b"token=PLACEHOLDER@api.github.com\n");
        assert_eq!(domains_seen, vec![Some("api.github.com".to_owned())]);
    }

    #[test]
    fn regex_domain_is_url_extracts_host() {
        let spec = SecretMatcher::Regex {
            pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>[^ ]+) (?P<domain>\S+)$".to_string(),
            domain_is_url: true,
        };
        let compiled = CompiledMatcher::compile(&spec).unwrap();
        let mut domains_seen: Vec<Option<String>> = Vec::new();
        compiled
            .rewrite(
                b"token=ghp_abc https://github.com/login\n",
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(str::to_owned));
                    "PLACEHOLDER".to_string()
                },
            )
            .unwrap();
        assert_eq!(domains_seen, vec![Some("github.com".to_owned())]);
    }

    #[test]
    fn regex_without_domain_group_passes_none() {
        let compiled =
            CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
        let mut domains_seen: Vec<Option<String>> = Vec::new();
        compiled
            .rewrite(b"token=ghp_abc\n", &mut |_, _, domain, _item| {
                domains_seen.push(domain.map(str::to_owned));
                "PLACEHOLDER".to_string()
            })
            .unwrap();
        assert_eq!(domains_seen, vec![None]);
    }

    #[test]
    fn json_domain_path_passes_domain_to_mint() {
        let spec = json_with_domain("$[*].value", "$[*].key", "$[*].domain");
        let compiled = CompiledMatcher::compile(&spec).unwrap();
        let mut domains_seen: Vec<Option<String>> = Vec::new();
        compiled
            .rewrite(
                br#"[{"key":"a","value":"AAA","domain":"api.github.com"},{"key":"b","value":"BBB","domain":null}]"#,
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(str::to_owned));
                    String::new()
                },
            )
            .unwrap();
        assert_eq!(domains_seen, vec![Some("api.github.com".to_owned()), None]);
    }

    #[test]
    fn json_domain_path_broadcasts_single_node_to_all_values() {
        // Simulates 1Password: $.urls[0].href is a single URL for the whole
        // item, but there are N sensitive fields. The single domain is broadcast
        // to all extracted values.
        let spec = json_with_domain("$.fields[*].value", "$.fields[*].label", "$.urls[0].href");
        let compiled = CompiledMatcher::compile(&spec).unwrap();
        let mut domains_seen: Vec<Option<String>> = Vec::new();
        compiled
            .rewrite(
                br#"{"fields":[{"label":"password","value":"s3cr3t"},{"label":"token","value":"ghp_x"}],"urls":[{"href":"github.com"}]}"#,
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(str::to_owned));
                    String::new()
                },
            )
            .unwrap();
        // 1 domain selected → broadcast to both values
        assert_eq!(
            domains_seen,
            vec![Some("github.com".to_owned()), Some("github.com".to_owned())]
        );
    }

    #[test]
    fn json_domain_is_url_extracts_host() {
        let spec = json_with_url_domain("$.fields[*].value", "$.fields[*].label", "$.urls[0].href");
        let compiled = CompiledMatcher::compile(&spec).unwrap();
        let mut domains_seen: Vec<Option<String>> = Vec::new();
        compiled
            .rewrite(
                br#"{"fields":[{"label":"password","value":"s3cr3t"},{"label":"token","value":"ghp_x"}],"urls":[{"href":"https://github.com/login"}]}"#,
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(str::to_owned));
                    String::new()
                },
            )
            .unwrap();
        // URL "https://github.com/login" → host "github.com", broadcast to both
        assert_eq!(
            domains_seen,
            vec![Some("github.com".to_owned()), Some("github.com".to_owned())]
        );
    }

    #[test]
    fn json_domain_path_rejects_misaligned_count() {
        // 3 values, 2 domain nodes (one item lacks the field) → error.
        // Note: 0 domains means wildcard (not an error); the error fires only
        // when M domains are selected where M != 0, 1, or value_count.
        let spec = json_with_domain("$[*].value", "$[*].key", "$[*].domain");
        let compiled = CompiledMatcher::compile(&spec).unwrap();
        assert!(matches!(
            compiled.rewrite(
                br#"[{"key":"a","value":"AAA","domain":"a.com"},{"key":"b","value":"BBB","domain":"b.com"},{"key":"c","value":"CCC"}]"#,
                &mut |_, _, _, _| String::new()
            ),
            Err(MatcherError::DomainMisaligned {
                values: 3,
                domains: 2
            })
        ));
    }

    #[test]
    fn json_item_path_broadcasts_title_to_all_fields() {
        // Simulates 1Password: $.title is one string for the whole item, but
        // there are N sensitive fields. The item title is broadcast to all.
        let spec = json_with_item("$.fields[*].value", "$.fields[*].label", "$.title", None);
        let compiled = CompiledMatcher::compile(&spec).unwrap();
        let mut items_seen: Vec<Option<String>> = Vec::new();
        compiled
            .rewrite(
                br#"{"title":"GitHub","fields":[{"label":"password","value":"s3cr3t"},{"label":"token","value":"ghp_x"}]}"#,
                &mut |_, _, _, item| {
                    items_seen.push(item.map(str::to_owned));
                    String::new()
                },
            )
            .unwrap();
        assert_eq!(
            items_seen,
            vec![Some("GitHub".to_owned()), Some("GitHub".to_owned())]
        );
    }
}
