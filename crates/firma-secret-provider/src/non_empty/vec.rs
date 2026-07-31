use std::ops::Deref;

use serde::{Deserialize, Serialize};

mod sealed {
    /// Builds a [`crate::non_empty::NonEmptyVec`] from a non-empty literal
    /// list, panicking on emptiness. Restricted to `crate` since the
    /// argument list is always non-empty syntactically, so the `expect` can
    /// only fire on a caller bug, which callers outside this crate can't be
    /// trusted to uphold.
    macro_rules! non_empty_vec {
        ($($x:expr),+ $(,)?) => {
            crate::non_empty::NonEmptyVec::new(vec![$($x),+]).expect("non empty vec")
        };
    }
    pub(crate) use non_empty_vec;
}
pub(crate) use sealed::non_empty_vec;

/// Returned by [`NonEmptyVec::new`] when the input is empty.
#[derive(Debug, thiserror::Error)]
#[error("empty vec")]
pub struct EmptyError;

/// A `Vec<T>` guaranteed to hold at least one element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    /// Wraps `inner`, failing if it's empty.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyError`] if `inner` is empty.
    pub fn new(inner: Vec<T>) -> Result<Self, EmptyError> {
        if inner.is_empty() {
            return Err(EmptyError);
        }

        Ok(Self(inner))
    }
}

impl<'de, T> Deserialize<'de> for NonEmptyVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(Vec::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
