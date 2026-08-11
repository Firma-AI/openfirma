use std::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapped version of `http::uri::Authority` that allows (de)serialization
#[derive(Clone, PartialEq, Eq)]
pub struct Authority(pub http::uri::Authority);

impl Authority {
    #[must_use]
    pub const fn from_static(src: &'static str) -> Self {
        Self(http::uri::Authority::from_static(src))
    }
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Hash for Authority {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<http::uri::Authority> for Authority {
    fn borrow(&self) -> &http::uri::Authority {
        &self.0
    }
}

impl Deref for Authority {
    type Target = http::uri::Authority;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Authority> for http::uri::Authority {
    fn from(value: &Authority) -> Self {
        value.0.clone()
    }
}

impl From<&http::uri::Authority> for Authority {
    fn from(value: &http::uri::Authority) -> Self {
        Self(value.clone())
    }
}

impl FromStr for Authority {
    type Err = <http::uri::Authority as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        http::uri::Authority::from_str(s).map(Self)
    }
}

impl Serialize for Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Authority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let temp = crate::Str::deserialize(deserializer)?;
        Self::from_str(temp.0.as_ref()).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "fuzz")]
impl arbitrary::Arbitrary<'_> for Authority {
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
        hm.insert(Authority::from_static("x-api-key"), "foo");
        assert!(hm.contains_key(&http::uri::Authority::from_static("x-api-key")));
    }
}
