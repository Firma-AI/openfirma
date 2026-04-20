/// Errors from token signing, verification, and revocation operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Token could not be parsed from the raw string.
    #[error("token parse failure: {reason}")]
    ParseFailure { reason: String },
    /// Token signature verification failed.
    #[error("token signature invalid: {reason}")]
    SignatureInvalid { reason: String },
    /// Token has expired.
    #[error("token expired: {token_id}")]
    Expired { token_id: String },
    /// Token has been revoked.
    #[error("token revoked: {token_id}")]
    Revoked { token_id: String },
    /// Token payload is malformed or missing required fields.
    #[error("token malformed: {reason}")]
    Malformed { reason: String },
}

/// Errors from policy evaluation operations.
#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    /// Policy bundle could not be loaded.
    #[error("policy load failure: {reason}")]
    PolicyLoadFailure { reason: String },
    /// Execution context could not be built from the envelope.
    #[error("context build failure: {reason}")]
    ContextBuildFailure { reason: String },
    /// Internal evaluation error.
    #[error("evaluation internal error: {reason}")]
    InternalError { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_error_parse_failure_display() {
        let err = TokenError::ParseFailure {
            reason: "unexpected EOF".to_string(),
        };
        assert_eq!(err.to_string(), "token parse failure: unexpected EOF");
    }

    #[test]
    fn test_token_error_signature_invalid_display() {
        let err = TokenError::SignatureInvalid {
            reason: "bad key".to_string(),
        };
        assert_eq!(err.to_string(), "token signature invalid: bad key");
    }

    #[test]
    fn test_token_error_expired_display() {
        let err = TokenError::Expired {
            token_id: "tok_001".to_string(),
        };
        assert_eq!(err.to_string(), "token expired: tok_001");
    }

    #[test]
    fn test_token_error_revoked_display() {
        let err = TokenError::Revoked {
            token_id: "tok_002".to_string(),
        };
        assert_eq!(err.to_string(), "token revoked: tok_002");
    }

    #[test]
    fn test_token_error_malformed_display() {
        let err = TokenError::Malformed {
            reason: "missing agent_id".to_string(),
        };
        assert_eq!(err.to_string(), "token malformed: missing agent_id");
    }

    #[test]
    fn test_evaluation_error_policy_load_display() {
        let err = EvaluationError::PolicyLoadFailure {
            reason: "file not found".to_string(),
        };
        assert_eq!(err.to_string(), "policy load failure: file not found");
    }

    #[test]
    fn test_evaluation_error_context_build_display() {
        let err = EvaluationError::ContextBuildFailure {
            reason: "missing action".to_string(),
        };
        assert_eq!(err.to_string(), "context build failure: missing action");
    }

    #[test]
    fn test_evaluation_error_internal_display() {
        let err = EvaluationError::InternalError {
            reason: "unexpected state".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "evaluation internal error: unexpected state"
        );
    }

    #[test]
    fn test_token_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<TokenError>();
    }

    #[test]
    fn test_evaluation_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<EvaluationError>();
    }
}
