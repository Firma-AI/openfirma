/// Static credential provider that maps connector IDs to fixed header sets.
///
/// Credentials are loaded at startup and served from memory.
/// Suitable for development, testing, and environments where secrets
/// are injected via configuration rather than a dynamic vault.
use std::collections::HashMap;

use async_trait::async_trait;
use firma_core::{ExecutionEnvelope, InjectedCredentials};

use crate::credential::{CredentialInjectionError, CredentialInjector};

/// In-memory credential store keyed by connector ID.
///
/// Each connector ID maps to a set of HTTP headers that will be
/// injected into outbound requests after enforcement passes.
#[derive(Debug, Clone)]
pub struct BasicCredentialInjector {
    /// `connector_id` to headers map.
    credentials: HashMap<String, HashMap<String, String>>,
}

impl BasicCredentialInjector {
    /// Creates a new `BasicCredentialInjector` from a pre-built map
    /// of connector IDs to header sets.
    #[must_use]
    pub fn new(credentials: HashMap<String, HashMap<String, String>>) -> Self {
        Self { credentials }
    }

    /// Creates an empty injector with no configured connectors.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Registers headers for a connector ID, replacing any previous
    /// entry.
    pub fn insert(&mut self, connector_id: String, headers: HashMap<String, String>) {
        self.credentials.insert(connector_id, headers);
    }

    /// Returns the number of configured connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Returns `true` if no connectors are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

#[async_trait]
impl CredentialInjector for BasicCredentialInjector {
    async fn inject(
        &self,
        _envelope: &ExecutionEnvelope,
        connector_id: &str,
        _target: &str,
    ) -> Result<InjectedCredentials, CredentialInjectionError> {
        self.credentials
            .get(connector_id)
            .map(|headers| InjectedCredentials::new(headers.clone()))
            .ok_or_else(|| CredentialInjectionError::UnknownConnector {
                connector_id: connector_id.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_core::{ActionParams, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams};

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
            },
            None,
        )
    }

    #[test]
    fn test_basic_injector_empty() {
        let injector = BasicCredentialInjector::empty();
        assert!(injector.is_empty());
        assert_eq!(injector.len(), 0);
    }

    #[test]
    fn test_basic_injector_insert_and_len() {
        let mut injector = BasicCredentialInjector::empty();
        injector.insert(
            "stripe".to_string(),
            HashMap::from([("Authorization".to_string(), "Bearer sk_test".to_string())]),
        );
        assert_eq!(injector.len(), 1);
        assert!(!injector.is_empty());
    }

    #[test]
    fn test_basic_injector_new_from_map() {
        let mut creds = HashMap::new();
        creds.insert(
            "stripe".to_string(),
            HashMap::from([("Authorization".to_string(), "Bearer sk_test".to_string())]),
        );
        creds.insert(
            "openai".to_string(),
            HashMap::from([("Authorization".to_string(), "Bearer sk_ai".to_string())]),
        );
        let injector = BasicCredentialInjector::new(creds);
        assert_eq!(injector.len(), 2);
    }

    #[tokio::test]
    async fn test_basic_injector_known_connector() {
        let injector = BasicCredentialInjector::new(HashMap::from([(
            "stripe".to_string(),
            HashMap::from([("Authorization".to_string(), "Bearer sk_test".to_string())]),
        )]));

        let envelope = sample_envelope();
        let result = injector
            .inject(&envelope, "stripe", "https://api.stripe.com")
            .await;
        let creds = result.expect("known connector should succeed");
        assert_eq!(
            creds.get("Authorization").map(String::as_str),
            Some("Bearer sk_test")
        );
    }

    #[tokio::test]
    async fn test_basic_injector_unknown_connector() {
        let injector = BasicCredentialInjector::empty();
        let envelope = sample_envelope();
        let result = injector
            .inject(&envelope, "unknown", "https://example.com")
            .await;
        assert!(matches!(
            result,
            Err(CredentialInjectionError::UnknownConnector { .. })
        ));
    }

    #[tokio::test]
    async fn test_basic_injector_multiple_headers() {
        let headers = HashMap::from([
            ("Authorization".to_string(), "Bearer tok".to_string()),
            ("X-Custom".to_string(), "val".to_string()),
        ]);
        let injector = BasicCredentialInjector::new(HashMap::from([("svc".to_string(), headers)]));

        let envelope = sample_envelope();
        let creds = injector
            .inject(&envelope, "svc", "https://svc.example.com")
            .await
            .expect("known connector should succeed");
        assert_eq!(
            creds.get("Authorization").map(String::as_str),
            Some("Bearer tok")
        );
        assert_eq!(creds.get("X-Custom").map(String::as_str), Some("val"));
    }

    #[test]
    fn test_basic_injector_debug() {
        let injector = BasicCredentialInjector::empty();
        let debug = format!("{injector:?}");
        assert!(debug.contains("BasicCredentialInjector"));
    }
}
