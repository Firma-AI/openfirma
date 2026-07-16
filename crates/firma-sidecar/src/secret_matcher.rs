//! Compiled secret matchers.
//!
//! A [`SecretMatcher`] spec (from a `secret.mediate` policy's annotations) is
//! compiled once at bundle-load to **validate** it — a bad `JSONPath` or `Regex`
//! fails the bundle closed — and again in the broker to **execute** it.
//! Execution extracts `(name, value)` pairs from a vault CLI's stdout and
//! rewrites the output with placeholders supplied by a mint callback, so the
//! agent only ever sees placeholders. See
//! `docs/architecture/secrets-interception.md`.

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
    },
    /// Compiled regex with `value` and `name` named groups.
    Regex {
        /// The compiled pattern.
        pattern: Regex,
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
                Ok(Self::Json { value, name })
            }
            SecretMatcher::Regex { pattern } => {
                let pattern =
                    Regex::new(pattern).map_err(|error| MatcherError::Regex(error.to_string()))?;
                let groups: Vec<&str> = pattern.capture_names().flatten().collect();
                if !groups.contains(&"value") {
                    return Err(MatcherError::MissingValueGroup);
                }
                if !groups.contains(&"name") {
                    return Err(MatcherError::MissingNameGroup);
                }
                Ok(Self::Regex { pattern })
            }
        }
    }

    /// Extract secrets from `output` and return it rewritten with placeholders.
    ///
    /// `mint(name, value) -> placeholder` is invoked once per extracted secret;
    /// the caller mints and stores the mapping and returns the placeholder to
    /// substitute in place of the value.
    ///
    /// # Errors
    ///
    /// Returns [`MatcherError`] if the output does not match the matcher's shape
    /// (bad JSON / UTF-8, non-string or misaligned nodes) or re-serialization
    /// fails.
    pub fn rewrite(
        &self,
        output: &[u8],
        mint: &mut impl FnMut(&str, &str) -> String,
    ) -> Result<Vec<u8>, MatcherError> {
        match self {
            Self::Json { value, name } => rewrite_json(output, value, name, mint),
            Self::Regex { pattern } => rewrite_regex(output, pattern, mint),
        }
    }
}

fn rewrite_json(
    output: &[u8],
    value_path: &JsonPath,
    name_path: &JsonPath,
    mint: &mut impl FnMut(&str, &str) -> String,
) -> Result<Vec<u8>, MatcherError> {
    let mut root: Value =
        serde_json::from_slice(output).map_err(|error| MatcherError::Json(error.to_string()))?;

    // Collect value-node JSON pointers + their string values, and the aligned
    // names, before mutating (the queries borrow `root` immutably).
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

    for ((pointer, value), name) in value_hits.into_iter().zip(names) {
        let placeholder = mint(&name, &value);
        if let Some(slot) = root.pointer_mut(&pointer) {
            *slot = Value::String(placeholder);
        }
    }

    serde_json::to_vec(&root).map_err(|error| MatcherError::Serialize(error.to_string()))
}

fn rewrite_regex(
    output: &[u8],
    pattern: &Regex,
    mint: &mut impl FnMut(&str, &str) -> String,
) -> Result<Vec<u8>, MatcherError> {
    let text = std::str::from_utf8(output).map_err(|_| MatcherError::NotUtf8)?;
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in pattern.captures_iter(text) {
        let value = caps.name("value").ok_or(MatcherError::MissingValueGroup)?;
        let name = caps.name("name").ok_or(MatcherError::MissingNameGroup)?;
        let placeholder = mint(name.as_str(), value.as_str());
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
        }
    }

    fn regex(pattern: &str) -> SecretMatcher {
        SecretMatcher::Regex {
            pattern: pattern.to_string(),
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
                &mut |name, value| {
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
            compiled.rewrite(br#"[{"key":"a","value":"AAA"}]"#, &mut |_, _| String::new()),
            Err(MatcherError::Misaligned {
                values: 1,
                names: 0
            })
        ));

        let compiled = CompiledMatcher::compile(&json("$.value", "$.key")).unwrap();
        assert!(matches!(
            compiled.rewrite(b"not json", &mut |_, _| String::new()),
            Err(MatcherError::Json(_))
        ));
    }

    #[test]
    fn regex_matcher_rewrites_value_spans() {
        let compiled =
            CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
        let out = compiled
            .rewrite(b"a=AAA\nb=BBB\n", &mut |name, _| format!("P:{name}"))
            .unwrap();
        assert_eq!(out, b"a=P:a\nb=P:b\n");
    }

    #[test]
    fn regex_matcher_rejects_non_utf8() {
        let compiled = CompiledMatcher::compile(&regex(r"(?P<name>.)=(?P<value>.)")).unwrap();
        assert!(matches!(
            compiled.rewrite(&[0xff, 0xfe], &mut |_, _| String::new()),
            Err(MatcherError::NotUtf8)
        ));
    }
}
