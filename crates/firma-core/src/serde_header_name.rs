use std::{
    borrow::{Borrow, Cow},
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapped version of `http::HeaderName` that allows (de)serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderName(pub http::HeaderName);

impl HeaderName {
    #[must_use]
    pub const fn from_static(src: &'static str) -> Self {
        Self(http::HeaderName::from_static(src))
    }
}

impl Hash for HeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<http::HeaderName> for HeaderName {
    fn borrow(&self) -> &http::HeaderName {
        &self.0
    }
}

impl Deref for HeaderName {
    type Target = http::HeaderName;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&HeaderName> for http::HeaderName {
    fn from(value: &HeaderName) -> Self {
        value.0.clone()
    }
}

impl From<&http::HeaderName> for HeaderName {
    fn from(value: &http::HeaderName) -> Self {
        Self(value.clone())
    }
}

impl FromStr for HeaderName {
    type Err = <http::HeaderName as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(http::HeaderName::from_str(s)?))
    }
}

impl Serialize for HeaderName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HeaderName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Temp<'a>(#[serde(borrow)] Cow<'a, str>);

        let temp = Temp::deserialize(deserializer)?;
        http::HeaderName::from_str(temp.0.as_ref())
            .map(HeaderName)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "fuzz")]
impl arbitrary::Arbitrary<'_> for HeaderName {
    fn arbitrary<'a>(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let s = <&str>::arbitrary(u)?;
        HeaderName::from_str(s).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn http_compatibility() {
        let mut hm = HashMap::new();
        hm.insert(HeaderName::from_static("x-api-key"), "foo");
        assert!(hm.contains_key(&http::HeaderName::from_static("x-api-key")));
    }
}
