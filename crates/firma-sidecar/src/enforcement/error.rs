//! Internal enforcement errors.
//!
//! Every variant maps to a [`DenyReason`] via [`EnforcementError::into_deny`].
//! This is the fail-closed boundary: errors become DENY decisions.
//! These types are never exposed to external callers.

use firma_core::{DenyReason, TokenError};

use super::decision::{EnforcementDecision, EnforcementStage};

/// Internal enforcement error — never exposed to callers.
///
/// Every variant maps to a `DenyReason` via `into_deny()`.
/// This is the fail-closed boundary: errors become DENY decisions.
#[derive(Debug, thiserror::Error)]
pub enum EnforcementError {
    #[error("normalization failed: {detail}")]
    NormalizationFailed { detail: String },

    #[error("no matching capability token: {detail}")]
    NoMatchingToken { detail: String },

    #[error("token validation failed: {0}")]
    TokenValidation(#[from] TokenError),

    #[error("scope violation: {detail}")]
    ScopeViolation { detail: String },

    #[error("policy denied: {detail}")]
    PolicyDenied { detail: String },

    #[error("policy bundle stale")]
    PolicyBundleStale,

    #[error("configuration error: {0}")]
    Config(String),
}

impl EnforcementError {
    /// Convert any internal error to a DENY decision.
    /// This is the fail-closed guarantee.
    #[must_use]
    pub fn into_deny(self, stage: EnforcementStage) -> EnforcementDecision {
        let (reason, detail) = match &self {
            Self::NormalizationFailed { detail } => {
                (DenyReason::UnclassifiedIntent, detail.clone())
            }
            Self::NoMatchingToken { detail } => (DenyReason::TokenInvalid, detail.clone()),
            Self::TokenValidation(e) => (token_error_to_deny_reason(e), e.to_string()),
            Self::ScopeViolation { detail } => (DenyReason::ScopeViolation, detail.clone()),
            Self::PolicyDenied { detail } => (DenyReason::PolicyDenied, detail.clone()),
            Self::PolicyBundleStale => (
                DenyReason::PolicyBundleStale,
                "policy bundle TTL expired".to_string(),
            ),
            Self::Config(msg) => (DenyReason::MalformedRequest, msg.clone()),
        };

        EnforcementDecision::Deny {
            reason,
            stage,
            detail,
            envelope: None,
            identity: None,
        }
    }
}

fn token_error_to_deny_reason(err: &TokenError) -> DenyReason {
    match err {
        TokenError::Expired { .. } => DenyReason::TokenExpired,
        TokenError::Revoked { .. } => DenyReason::TokenRevoked,
        _ => DenyReason::TokenInvalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::decision::{CapabilityValidationStage, ConstraintEnforcementStage};
    use firma_core::token::TokenId;

    #[test]
    fn test_normalization_error_maps_to_unclassified() {
        let err = EnforcementError::NormalizationFailed {
            detail: "unknown host".to_string(),
        };
        let decision = err.into_deny(EnforcementStage::Normalization);
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnclassifiedIntent));
    }

    #[test]
    fn test_token_expired_maps_correctly() {
        let err = EnforcementError::TokenValidation(TokenError::Expired {
            token_id: TokenId::new(),
        });
        let decision = err.into_deny(EnforcementStage::CapabilityValidation(
            CapabilityValidationStage::TokenValidation,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenExpired));
    }

    #[test]
    fn test_scope_violation_maps_correctly() {
        let err = EnforcementError::ScopeViolation {
            detail: "action not in token scope".to_string(),
        };
        let decision = err.into_deny(EnforcementStage::ConstraintEnforcement(
            ConstraintEnforcementStage::ScopeCheck,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::ScopeViolation));
    }

    #[test]
    fn test_no_matching_token_maps_to_token_invalid() {
        let err = EnforcementError::NoMatchingToken {
            detail: "no token found".to_string(),
        };
        let decision = err.into_deny(EnforcementStage::CapabilityValidation(
            CapabilityValidationStage::TokenSelection,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    #[test]
    fn test_token_revoked_maps_correctly() {
        let err = EnforcementError::TokenValidation(TokenError::Revoked {
            token_id: "14f89c0d-b675-c46e-ba6e-0f9d47ef316f"
                .parse()
                .expect("literal token id"),
        });
        let decision = err.into_deny(EnforcementStage::CapabilityValidation(
            CapabilityValidationStage::TokenValidation,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenRevoked));
    }

    #[test]
    fn test_token_signature_invalid_maps_to_token_invalid() {
        let err = EnforcementError::TokenValidation(TokenError::SignatureInvalid {
            reason: "bad key".to_string(),
        });
        let decision = err.into_deny(EnforcementStage::CapabilityValidation(
            CapabilityValidationStage::TokenValidation,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    #[test]
    fn test_token_parse_failure_maps_to_token_invalid() {
        let err = EnforcementError::TokenValidation(TokenError::ParseFailure {
            reason: "not base64".to_string(),
        });
        let decision = err.into_deny(EnforcementStage::CapabilityValidation(
            CapabilityValidationStage::TokenValidation,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    #[test]
    fn test_token_malformed_maps_to_token_invalid() {
        let err = EnforcementError::TokenValidation(TokenError::Malformed {
            reason: "missing fields".to_string(),
        });
        let decision = err.into_deny(EnforcementStage::CapabilityValidation(
            CapabilityValidationStage::TokenValidation,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
    }

    #[test]
    fn test_policy_denied_maps_correctly() {
        let err = EnforcementError::PolicyDenied {
            detail: "cedar denied".to_string(),
        };
        let decision = err.into_deny(EnforcementStage::ConstraintEnforcement(
            ConstraintEnforcementStage::PolicyEvaluation,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
    }

    #[test]
    fn test_policy_bundle_stale_maps_correctly() {
        let err = EnforcementError::PolicyBundleStale;
        let decision = err.into_deny(EnforcementStage::ConstraintEnforcement(
            ConstraintEnforcementStage::BundleFreshness,
        ));
        assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    }

    #[test]
    fn test_config_error_maps_to_malformed_request() {
        let err = EnforcementError::Config("bad config".to_string());
        let decision = err.into_deny(EnforcementStage::Normalization);
        assert_eq!(decision.deny_reason(), Some(DenyReason::MalformedRequest));
    }

    #[test]
    fn test_all_errors_produce_deny_decisions() {
        let errors: Vec<EnforcementError> = vec![
            EnforcementError::NormalizationFailed {
                detail: "test".to_string(),
            },
            EnforcementError::NoMatchingToken {
                detail: "test".to_string(),
            },
            EnforcementError::TokenValidation(TokenError::Expired {
                token_id: "60ae136e-5d49-fbdf-037f-ab5f1d805634"
                    .parse()
                    .expect("literal token id"),
            }),
            EnforcementError::ScopeViolation {
                detail: "test".to_string(),
            },
            EnforcementError::PolicyDenied {
                detail: "test".to_string(),
            },
            EnforcementError::PolicyBundleStale,
            EnforcementError::Config("test".to_string()),
        ];

        for err in errors {
            let decision = err.into_deny(EnforcementStage::Normalization);
            assert!(
                decision.is_deny(),
                "every EnforcementError must produce a DENY"
            );
        }
    }
}
