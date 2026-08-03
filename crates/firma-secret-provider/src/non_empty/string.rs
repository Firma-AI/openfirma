use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// Returned by [`NonEmptyString::new`] when the input is empty.
#[derive(Debug, thiserror::Error)]
#[error("empty string")]
pub struct EmptyError;

/// A `String` checked to be non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NonEmptyString(String);

impl NonEmptyString {
    /// Trims `value` and wraps it, failing if nothing is left.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyError`] if `value` is empty after trimming.
    pub fn new(value: String) -> Result<Self, EmptyError> {
        if value.trim().is_empty() {
            return Err(EmptyError);
        }

        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Deref for NonEmptyString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
