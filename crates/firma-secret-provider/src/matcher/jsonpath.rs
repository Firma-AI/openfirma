use std::ops::Deref;

/// A parsed `JSONPath` expression, annotated with whether it is *singular*
/// per RFC 9535 §2.1 (see [`is_singular_jsonpath`]).
#[derive(Debug)]
pub struct JsonPath {
    path: serde_json_path::JsonPath,
    /// `true` if this path selects at most one node regardless of the data
    /// it's run against, per [`is_singular_jsonpath`].
    pub is_singular: bool,
}

impl JsonPath {
    /// Parses a `JSONPath` expression, classifying it as singular or not.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json_path::ParseError`] if `path_str` is not a valid
    /// `JSONPath` expression.
    pub fn parse(path_str: &str) -> Result<Self, serde_json_path::ParseError> {
        let path = serde_json_path::JsonPath::parse(path_str)?;
        Ok(Self {
            path,
            is_singular: is_singular_jsonpath(path_str),
        })
    }
}

impl Deref for JsonPath {
    type Target = serde_json_path::JsonPath;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

/// Returns `true` if `path` is a `JSONPath` *singular-path* per RFC 9535 §2.1:
/// built only from name- and index-selectors, so it selects at most one node
/// regardless of the data it's run against.
///
/// This walks the raw path string rather than a parsed AST — `serde_json_path`
/// doesn't expose its internal `Query` — tracking bracket-string quote state
/// and flagging any construct that can yield zero-or-many matches: wildcard
/// (`*`), descendant segments (`..`), filter selectors (`?`), slices (`:`
/// inside `[...]`), and selector unions (`,` inside `[...]`).
pub(super) fn is_singular_jsonpath(path: &str) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut quote = Quote::None;
    let mut bracket_depth = 0u32;
    let mut chars = path.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Quote::Single => {
                if c == '\\' {
                    chars.next();
                } else if c == '\'' {
                    quote = Quote::None;
                }
                continue;
            }
            Quote::Double => {
                if c == '\\' {
                    chars.next();
                } else if c == '"' {
                    quote = Quote::None;
                }
                continue;
            }
            Quote::None => {}
        }

        match c {
            '\'' => quote = Quote::Single,
            '"' => quote = Quote::Double,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '*' | '?' => return false,
            '.' if chars.peek() == Some(&'.') => return false,
            ':' | ',' if bracket_depth > 0 => return false,
            _ => {}
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::is_singular_jsonpath;

    #[test]
    fn singular_paths() {
        assert!(is_singular_jsonpath("$.title"));
        assert!(is_singular_jsonpath("$.fields[0].value"));
        assert!(is_singular_jsonpath("$['a']['b']"));
        assert!(is_singular_jsonpath("$.foo['a:b,c*d?e']"));
    }

    #[test]
    fn non_singular_paths() {
        assert!(!is_singular_jsonpath("$.fields[*].value"));
        assert!(!is_singular_jsonpath("$.fields[*].label"));
        assert!(!is_singular_jsonpath("$..foo"));
        assert!(!is_singular_jsonpath("$.a[0,1]"));
        assert!(!is_singular_jsonpath("$.a[0:2]"));
        assert!(!is_singular_jsonpath("$.a[?(@.b)]"));
    }
}
