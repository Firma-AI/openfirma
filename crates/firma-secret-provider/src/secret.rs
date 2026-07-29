use std::fmt;

/// A borrowed secret value that redacts itself in [`fmt::Debug`] and [`fmt::Display`].
///
/// Passed to the `mint` callback in [`CompiledMatcher::rewrite`](crate::CompiledMatcher::rewrite)
/// so extracted plaintext can't accidentally end up in logs or error messages;
/// call [`Secret::expose`] to access the underlying value.
pub struct Secret<'a>(&'a str);

impl<'a> Secret<'a> {
    #[must_use]
    pub(crate) fn new(secret: &'a str) -> Self {
        Self(secret)
    }

    /// Returns the underlying plaintext secret value.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0
    }
}

impl fmt::Debug for Secret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

impl fmt::Display for Secret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}
