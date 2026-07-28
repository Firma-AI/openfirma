use std::ops::Deref;

/// A parsed `JSONPath` expression.
#[derive(Debug)]
pub struct JsonPath {
    path: serde_json_path::JsonPath,
}

impl JsonPath {
    /// Parses a `JSONPath` expression.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json_path::ParseError`] if `path_str` is not a valid
    /// `JSONPath` expression.
    pub fn parse(path_str: &str) -> Result<Self, serde_json_path::ParseError> {
        serde_json_path::JsonPath::parse(path_str).map(|path| Self { path })
    }
}

impl Deref for JsonPath {
    type Target = serde_json_path::JsonPath;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}
