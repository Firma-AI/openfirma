use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapped version of `http::HeaderValue` that allows (de)serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValue(pub http::HeaderValue);

impl Hash for HeaderValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<http::HeaderValue> for HeaderValue {
    fn borrow(&self) -> &http::HeaderValue {
        &self.0
    }
}

impl Deref for HeaderValue {
    type Target = http::HeaderValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&HeaderValue> for http::HeaderValue {
    fn from(value: &HeaderValue) -> Self {
        value.0.clone()
    }
}

impl From<HeaderValue> for http::HeaderValue {
    fn from(value: HeaderValue) -> Self {
        value.0
    }
}

impl From<&http::HeaderValue> for HeaderValue {
    fn from(value: &http::HeaderValue) -> Self {
        Self(value.clone())
    }
}

impl FromStr for HeaderValue {
    type Err = <http::HeaderValue as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(http::HeaderValue::from_str(s)?))
    }
}

impl Serialize for HeaderValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0
            .to_str()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HeaderValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let temp = crate::Str::deserialize(deserializer)?;
        http::HeaderValue::from_str(temp.0.as_ref())
            .map(HeaderValue)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "fuzz")]
impl arbitrary::Arbitrary<'_> for HeaderValue {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let s = <&str>::arbitrary(u)?;
        Self::from_str(s).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn http_compatibility() {
        let mut hm = HashMap::new();
        hm.insert(
            // since hawk made us remove `from_static` wrapper, we have to do this explicitly
            HeaderValue(http::HeaderValue::from_static("x-api-key")),
            "foo",
        );
        assert!(hm.contains_key(&http::HeaderValue::from_static("x-api-key")));
    }
}
