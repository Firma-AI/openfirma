use std::{borrow::Cow, fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};

/// Shared (de)serializable string that avoids allocating if possible
///
/// Without it, deserializing to &str b"\"" or any multi byte UTF8 char
/// would result in a panic
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Str<'a>(#[serde(borrow)] pub Cow<'a, str>);

impl Deref for Str<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Display for Str<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> From<&'a str> for Str<'a> {
    fn from(value: &'a str) -> Self {
        Str(Cow::Borrowed(value))
    }
}

impl<'a, T> From<&'a T> for Str<'a>
where
    T: AsRef<str>,
{
    fn from(value: &'a T) -> Self {
        Str(Cow::Borrowed(value.as_ref()))
    }
}

impl From<String> for Str<'_> {
    fn from(value: String) -> Self {
        Str(Cow::Owned(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_allocate() {
        let s = r#""test""#;
        let res = serde_json::from_str::<Str>(s).expect("deserialize");
        std::assert_matches!(res, Str(Cow::Borrowed(_)));
    }

    #[test]
    fn does_allocate() {
        let s = r#""\"""#;
        let res = serde_json::from_str::<Str>(s).expect("deserialize");
        std::assert_matches!(res, Str(Cow::Owned(_)));
    }
}
