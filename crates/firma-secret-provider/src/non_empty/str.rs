use std::{fmt, ops::Deref};

/// Returned by [`NonEmptyStr::new`] when the input is empty (after trimming).
#[derive(Debug, thiserror::Error)]
#[error("empty string")]
pub struct EmptyError;

/// A borrowed string checked to be non-empty.
pub struct NonEmptyStr<'a>(&'a str);

impl<'a> NonEmptyStr<'a> {
    /// Trims `value` and wraps it, failing if nothing is left.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyError`] if `value` is empty after trimming.
    pub fn new(value: &'a str) -> Result<Self, EmptyError> {
        let value = value.trim();
        if value.is_empty() {
            Err(EmptyError)
        } else {
            Ok(Self(value))
        }
    }
}

impl fmt::Debug for NonEmptyStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Display for NonEmptyStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Deref for NonEmptyStr<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}
