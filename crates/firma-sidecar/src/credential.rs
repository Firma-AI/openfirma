// Credential injection trait for enriching outbound requests with
// connector-specific authentication headers after enforcement.

pub mod provider;

use async_trait::async_trait;
use firma_core::{ExecutionEnvelope, InjectedCredentials};

/// Errors that can occur during credential injection.
#[derive(Debug, thiserror::Error)]
pub enum CredentialInjectionError {
    /// Connector ID does not map to a known credential source.
    #[error("unknown connector: {connector_id}")]
    UnknownConnector { connector_id: String },
    /// Credential fetch failed (vault unreachable, secret expired, etc.).
    #[error("credential fetch failed for connector {connector_id}: {reason}")]
    FetchFailed {
        connector_id: String,
        reason: String,
    },
}

/// Resolve and inject connector-specific credentials for an outbound request.
///
/// Called after enforcement passes. Implementations look up the credential
/// source for `connector_id`, fetch the secret material, and return headers
/// to attach to the outbound request. The original [`ExecutionEnvelope`] is
/// never mutated — injected headers are returned as a separate value.
#[async_trait]
pub trait CredentialInjector: Send + Sync {
    /// Inject credentials for the given connector and target.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInjectionError`] if the connector is unknown or
    /// the credential cannot be fetched.
    async fn inject(
        &self,
        envelope: &ExecutionEnvelope,
        connector_id: &str,
        target: &str,
    ) -> Result<InjectedCredentials, CredentialInjectionError>;
}

/// No-op injector that always returns empty credentials.
///
/// Used when no credential configuration is provided, and in tests
/// that exercise enforcement logic without credential injection.
#[derive(Debug)]
pub struct NullCredentialInjector;

#[async_trait]
impl CredentialInjector for NullCredentialInjector {
    async fn inject(
        &self,
        _envelope: &ExecutionEnvelope,
        _connector_id: &str,
        _target: &str,
    ) -> Result<InjectedCredentials, CredentialInjectionError> {
        Ok(InjectedCredentials::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_core::{
        ActionParams, ExecutionIntent, ExecutionMetadata, HeaderName, HttpMethod, HttpParams,
    };
    use std::collections::HashMap;

    fn sample_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "filesystem.read".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("https://api.example.com"),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "GET /".to_string(),
            },
            "v4.public.eyJ0...".to_string(),
            ExecutionMetadata {
                session_id: "sess_001".parse().expect("literal session id"),
                agent_id: "agent_abc".parse().expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        )
    }

    // -- CredentialInjectionError tests --

    #[test]
    fn test_credential_injection_error_unknown_connector_display() {
        let err = CredentialInjectionError::UnknownConnector {
            connector_id: "stripe".to_string(),
        };
        assert_eq!(err.to_string(), "unknown connector: stripe");
    }

    #[test]
    fn test_credential_injection_error_fetch_failed_display() {
        let err = CredentialInjectionError::FetchFailed {
            connector_id: "stripe".to_string(),
            reason: "vault timeout".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "credential fetch failed for connector stripe: vault timeout"
        );
    }

    #[test]
    fn test_credential_injection_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<CredentialInjectionError>();
    }

    // -- CredentialInjector trait tests --

    struct MockInjector;

    #[async_trait]
    impl CredentialInjector for MockInjector {
        async fn inject(
            &self,
            _envelope: &ExecutionEnvelope,
            connector_id: &str,
            _target: &str,
        ) -> Result<InjectedCredentials, CredentialInjectionError> {
            if connector_id == "known" {
                Ok(InjectedCredentials::new(HashMap::from([(
                    HeaderName::from_static("x-api-key"),
                    "secret".to_string(),
                )])))
            } else {
                Err(CredentialInjectionError::UnknownConnector {
                    connector_id: connector_id.to_string(),
                })
            }
        }
    }

    #[tokio::test]
    async fn test_credential_injector_known_connector() {
        let injector = MockInjector;
        let envelope = sample_envelope();
        let result = injector
            .inject(&envelope, "known", "https://api.example.com")
            .await;
        let creds = result.expect("should succeed for known connector");
        assert_eq!(
            creds
                .get(&HeaderName::from_static("x-api-key"))
                .map(String::as_str),
            Some("secret")
        );
    }

    #[tokio::test]
    async fn test_credential_injector_unknown_connector() {
        let injector = MockInjector;
        let envelope = sample_envelope();
        let result = injector
            .inject(&envelope, "nope", "https://api.example.com")
            .await;
        assert!(matches!(
            result,
            Err(CredentialInjectionError::UnknownConnector { .. })
        ));
    }
}
