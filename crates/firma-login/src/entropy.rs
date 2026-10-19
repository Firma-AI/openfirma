use thiserror::Error;

/// Failure to obtain cryptographically secure random data.
#[derive(Debug, Error)]
pub enum EntropyError {
    /// The platform random-number generator returned an error.
    #[error("operating-system entropy is unavailable")]
    System(#[source] getrandom::Error),
}
