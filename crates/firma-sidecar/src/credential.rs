// Credential injection types and trait for enriching outbound requests
// with connector-specific authentication headers after enforcement.

pub mod provider;
pub mod transport;

use std::collections::HashMap;

use async_trait::async_trait;
use firma_core::ExecutionEnvelope;

/// Headers injected into an outbound request after enforcement passes.
///
/// Produced by a [`CredentialInjector`] implementation. Contains only
/// HTTP headers — the envelope itself is never mutated.
#[derive(Debug, Clone)]
pub struct InjectedCredentials {
    headers: HashMap<String, String>,
}

#[expect(
    dead_code,
    reason = "public API consumed by connector/interceptor callers once wired"
)]
impl InjectedCredentials {
    /// Creates a new `InjectedCredentials` from a header map.
    #[must_use]
    pub fn new(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }

    /// Creates an empty `InjectedCredentials` with no headers.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    /// Returns the injected headers.
    #[must_use]
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Consumes `self` and returns the inner header map.
    #[must_use]
    pub fn into_headers(self) -> HashMap<String, String> {
        self.headers
    }

    /// Returns the value for a single header key, if present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }

    /// Inserts a header key-value pair, replacing any existing value.
    pub fn insert(&mut self, key: String, value: String) {
        self.headers.insert(key, value);
    }

    /// Returns `true` if no headers were injected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

impl From<HashMap<String, String>> for InjectedCredentials {
    fn from(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }
}

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
    use firma_core::{ActionParams, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams};

    fn sample_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "http.get".to_string(),
                resource: "https://api.example.com".to_string(),
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
                session_id: "sess_001".to_string(),
                agent_id: "agent_abc".to_string(),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        )
    }

    // -- InjectedCredentials tests --

    #[test]
    fn test_injected_credentials_new() {
        let headers = HashMap::from([("Authorization".to_string(), "Bearer tok".to_string())]);
        let creds = InjectedCredentials::new(headers.clone());
        assert_eq!(creds.headers(), &headers);
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_injected_credentials_empty() {
        let creds = InjectedCredentials::empty();
        assert!(creds.is_empty());
        assert!(creds.headers().is_empty());
    }

    #[test]
    fn test_injected_credentials_from_hashmap() {
        let headers = HashMap::from([("X-Api-Key".to_string(), "key123".to_string())]);
        let creds = InjectedCredentials::from(headers.clone());
        assert_eq!(creds.headers(), &headers);
    }

    #[test]
    fn test_injected_credentials_get() {
        let creds = InjectedCredentials::new(HashMap::from([(
            "Authorization".to_string(),
            "Bearer tok".to_string(),
        )]));
        assert_eq!(
            creds.get("Authorization").map(String::as_str),
            Some("Bearer tok")
        );
        assert!(creds.get("Missing").is_none());
    }

    #[test]
    fn test_injected_credentials_insert() {
        let mut creds = InjectedCredentials::empty();
        creds.insert("X-Key".to_string(), "val".to_string());
        assert_eq!(creds.get("X-Key").map(String::as_str), Some("val"));
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_injected_credentials_into_headers() {
        let headers = HashMap::from([("Authorization".to_string(), "Bearer tok".to_string())]);
        let creds = InjectedCredentials::new(headers.clone());
        assert_eq!(creds.into_headers(), headers);
    }

    #[test]
    fn test_injected_credentials_debug() {
        let creds = InjectedCredentials::empty();
        let debug = format!("{creds:?}");
        assert!(debug.contains("InjectedCredentials"));
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
                    "X-Api-Key".to_string(),
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
        assert_eq!(creds.get("X-Api-Key").map(String::as_str), Some("secret"));
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
