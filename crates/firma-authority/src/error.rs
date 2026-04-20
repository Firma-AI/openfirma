/// Domain errors for the Mini Authority service.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("policy load failed: {reason}")]
    PolicyLoadFailed { reason: String },

    #[error("policy evaluation failed: {reason}")]
    EvaluationFailed { reason: String },

    #[error("key management error: {reason}")]
    KeyError { reason: String },

    #[error("configuration error: {reason}")]
    ConfigError { reason: String },

    #[error("revocation error: {reason}")]
    RevocationError { reason: String },

    #[error("file watch failed: {reason}")]
    WatchFailed { reason: String },

    #[error("server failed: {reason}")]
    Server { reason: String },
}

impl From<crate::config::ConfigError> for AuthorityError {
    fn from(e: crate::config::ConfigError) -> Self {
        Self::ConfigError {
            reason: e.to_string(),
        }
    }
}
