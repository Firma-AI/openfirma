use std::{
    borrow::Borrow,
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use either::Either;
use http::header::ToStrError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const FIRMA_SESSION_ID_HEADER_NAME: &str = "x-firma-session-id";

/// A wrapped version of `http::HeaderMap` that allows (de)serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMap(pub http::HeaderMap);

impl HeaderMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns firma session id header value
    ///
    /// # Errors
    /// * invalid header value
    pub fn get_firma_session_id(&self) -> Result<Option<&str>, ToStrError> {
        self.get(FIRMA_SESSION_ID_HEADER_NAME)
            .map(|value| value.to_str())
            .transpose()
    }
}

impl Default for HeaderMap {
    fn default() -> Self {
        Self(http::HeaderMap::new())
    }
}

impl Borrow<http::HeaderMap> for HeaderMap {
    fn borrow(&self) -> &http::HeaderMap {
        &self.0
    }
}

impl Deref for HeaderMap {
    type Target = http::HeaderMap;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HeaderMap {
    fn deref_mut(&mut self) -> &mut http::HeaderMap {
        &mut self.0
    }
}

impl From<&HeaderMap> for http::HeaderMap {
    fn from(value: &HeaderMap) -> Self {
        value.0.clone()
    }
}

type SerializableHeaderMap = HashMap<crate::HeaderName, OneOrMany<crate::HeaderValue>>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(Option<T>),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::One(None)
    }
}

impl<T> OneOrMany<T> {
    fn push(&mut self, item: T) {
        match self {
            Self::One(prev) => {
                if let Some(prev) = prev.take() {
                    *self = Self::Many(vec![prev, item]);
                } else {
                    *self = Self::One(Some(item));
                }
            }
            Self::Many(vec) => vec.push(item),
        }
    }
}

impl<T> IntoIterator for OneOrMany<T> {
    type Item = T;
    type IntoIter = Either<std::option::IntoIter<T>, std::vec::IntoIter<T>>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::One(item) => Either::Left(item.into_iter()),
            Self::Many(items) => Either::Right(items.into_iter()),
        }
    }
}

impl Serialize for HeaderMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0
            .iter()
            .fold(SerializableHeaderMap::new(), |mut acc, (k, v)| {
                let values = acc.entry(crate::HeaderName::from(k)).or_default();
                values.push(crate::HeaderValue::from(v));
                acc
            })
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HeaderMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SerializableHeaderMap::deserialize(deserializer)?
            .into_iter()
            .try_fold(Self(http::HeaderMap::new()), |mut acc, (k, vv)| {
                for v in vv {
                    if acc.contains_key(&*k) {
                        acc.try_append(
                            http::HeaderName::from(k.clone()),
                            http::HeaderValue::from(v),
                        )
                        .map_err(serde::de::Error::custom)?;
                    } else {
                        acc.try_insert(
                            http::HeaderName::from(k.clone()),
                            http::HeaderValue::from(v),
                        )
                        .map_err(serde::de::Error::custom)?;
                    }
                }
                Ok(acc)
            })
    }
}

impl FromIterator<(http::HeaderName, http::HeaderValue)> for HeaderMap {
    fn from_iter<T: IntoIterator<Item = (http::HeaderName, http::HeaderValue)>>(iter: T) -> Self {
        iter.into_iter()
            .fold(Self(http::HeaderMap::new()), |mut acc, (k, v)| {
                if acc.contains_key(&k) {
                    acc.append(k, v);
                } else {
                    acc.insert(k, v);
                }
                acc
            })
    }
}

impl<I> From<I> for HeaderMap
where
    I: IntoIterator<Item = (http::HeaderName, http::HeaderValue)>,
{
    fn from(value: I) -> Self {
        value.into_iter().collect()
    }
}

#[cfg(feature = "fuzz")]
impl arbitrary::Arbitrary<'_> for HeaderMap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        u.arbitrary_iter::<(crate::HeaderName, crate::HeaderValue)>()?
            .map(|res| {
                let (k, v) = res?;
                Ok((http::HeaderName::from(k), http::HeaderValue::from(v)))
            })
            .collect()
    }
}
