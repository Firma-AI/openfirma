use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapped version of `http::Method` that allows (de)serialization
#[derive(Clone, PartialEq, Eq)]
pub struct Method(pub http::Method);

impl Method {
    /// GET
    pub const GET: Self = Self(http::Method::GET);

    /// POST
    pub const POST: Self = Self(http::Method::POST);

    /// PUT
    pub const PUT: Self = Self(http::Method::PUT);

    /// DELETE
    pub const DELETE: Self = Self(http::Method::DELETE);

    /// HEAD
    pub const HEAD: Self = Self(http::Method::HEAD);

    /// OPTIONS
    pub const OPTIONS: Self = Self(http::Method::OPTIONS);

    /// CONNECT
    pub const CONNECT: Self = Self(http::Method::CONNECT);

    /// PATCH
    pub const PATCH: Self = Self(http::Method::PATCH);

    /// TRACE
    pub const TRACE: Self = Self(http::Method::TRACE);
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Hash for Method {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Deref for Method {
    type Target = http::Method;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Method {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Temp<'a>(#[serde(borrow)] Cow<'a, str>);

        let temp = Temp::deserialize(deserializer)?;
        http::Method::from_str(temp.0.as_ref())
            .map(Method)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "fuzz")]
impl arbitrary::Arbitrary<'_> for Method {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let s = <&str>::arbitrary(u)?;
        http::Method::from_str(s)
            .map(Method)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}
