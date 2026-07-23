use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// Shared (de)serializable string that avoids allocating if possible
///
/// Without it, deserializing to &str b"\"" or any multi byte UTF8 char
/// would result in a panic
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Str<'a>(#[serde(borrow)] pub Cow<'a, str>);

impl<'a> From<&'a str> for Str<'a> {
    fn from(value: &'a str) -> Self {
        Str(Cow::Borrowed(value))
    }
}

impl From<String> for Str<'_> {
    fn from(value: String) -> Self {
        Str(Cow::Owned(value))
    }
}
