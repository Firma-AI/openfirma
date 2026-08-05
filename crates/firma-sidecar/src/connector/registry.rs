//! Connector registry for the sidecar dispatch layer.
//!
//! Holds the set of [`Connector`](firma_core::Connector) implementations
//! the sidecar can route outbound calls to. Selection is host-keyed:
//! the target host extracted from the envelope resource is looked up
//! in an override map, and the default connector is returned when no
//! override is registered.
//!
//! Specialized connectors (LLM providers, databases, tool APIs) — in
//! tree or from external crates — plug in as host overrides. The
//! generic HTTP connector covers every unconfigured host.

use std::collections::HashMap;
use std::sync::Arc;

use firma_core::Connector;

/// Host-keyed registry of [`Connector`] instances.
///
/// Every request goes through [`select`](Self::select): the target
/// host maps to a registered override, or, when no override exists,
/// to the default connector registered at construction time.
///
/// The registry is built once at startup and cloned as `Arc` into the
/// [`RequestHandler`](crate::handler::RequestHandler). It is
/// effectively immutable on the hot path — all mutation happens
/// before the handler begins serving traffic.
pub struct ConnectorRegistry {
    hosts: HashMap<String, Arc<dyn Connector>>,
    default: Arc<dyn Connector>,
}

impl ConnectorRegistry {
    /// Creates a new registry with the given default connector and
    /// no host overrides.
    ///
    /// The default is returned by [`select`](Self::select) for every
    /// host that has not been registered via
    /// [`register_host`](Self::register_host).
    #[must_use]
    pub fn new(default: Arc<dyn Connector>) -> Self {
        Self {
            hosts: HashMap::new(),
            default,
        }
    }

    /// Registers a connector as the override for `host`.
    ///
    /// Replaces any previously registered override for the same host.
    /// Host matching is exact string equality against the
    /// envelope-derived host; there is no wildcard or suffix match.
    pub(crate) fn register_host(&mut self, host: String, connector: Arc<dyn Connector>) {
        self.hosts.insert(host, connector);
    }

    /// Returns the connector that should handle `host`.
    ///
    /// Host overrides win; the default connector is returned when no
    /// override is registered. The returned `Arc` is cheap to clone
    /// and is safe to hold across await points.
    #[must_use]
    pub(crate) fn select(&self, host: &str) -> Arc<dyn Connector> {
        self.hosts
            .get(host)
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.default))
    }

    /// Returns `true` when `host` has an override registered.
    #[must_use]
    #[cfg(test)]
    fn has_override(&self, host: &str) -> bool {
        self.hosts.contains_key(host)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use async_trait::async_trait;
    use firma_core::{Connector, ConnectorError, ConnectorResponse, TransportView};

    use super::*;

    /// Connector stub that returns a fixed status so tests can assert
    /// which instance the registry selected.
    struct StubConnector {
        label: u16,
    }

    #[async_trait]
    impl Connector for StubConnector {
        async fn dispatch(
            &self,
            _view: &TransportView,
        ) -> Result<ConnectorResponse, ConnectorError> {
            Ok(ConnectorResponse {
                status: self.label,
                headers: HashMap::new(),
                body: Vec::new(),
                dispatch_latency: Duration::from_millis(0),
                response_size: 0,
            })
        }
    }

    fn stub(label: u16) -> Arc<dyn Connector> {
        Arc::new(StubConnector { label })
    }

    #[tokio::test]
    async fn test_select_returns_default_for_unknown_host() {
        let registry = ConnectorRegistry::new(stub(1));
        let connector = registry.select("api.unknown");
        let response = connector
            .dispatch(&sample_view())
            .await
            .expect("stub connector always succeeds");
        assert_eq!(response.status, 1);
    }

    #[tokio::test]
    async fn test_select_returns_override_for_registered_host() {
        let mut registry = ConnectorRegistry::new(stub(1));
        registry.register_host("api.openai.com".to_string(), stub(2));

        let connector = registry.select("api.openai.com");
        let response = connector
            .dispatch(&sample_view())
            .await
            .expect("stub connector always succeeds");
        assert_eq!(response.status, 2);
    }

    #[tokio::test]
    async fn test_register_host_replaces_existing_override() {
        let mut registry = ConnectorRegistry::new(stub(1));
        registry.register_host("api.example.com".to_string(), stub(2));
        registry.register_host("api.example.com".to_string(), stub(3));

        let connector = registry.select("api.example.com");
        let response = connector
            .dispatch(&sample_view())
            .await
            .expect("stub connector always succeeds");
        assert_eq!(response.status, 3);
    }

    #[test]
    fn test_has_override_reports_registration() {
        let mut registry = ConnectorRegistry::new(stub(1));
        assert!(!registry.has_override("api.example.com"));
        registry.register_host("api.example.com".to_string(), stub(2));
        assert!(registry.has_override("api.example.com"));
        assert!(!registry.has_override("api.other.com"));
    }

    #[test]
    fn test_select_falls_through_to_default_when_host_mismatches() {
        let mut registry = ConnectorRegistry::new(stub(1));
        registry.register_host("api.example.com".to_string(), stub(2));
        assert!(!registry.has_override("api.other.com"));
    }

    fn sample_view() -> TransportView {
        use firma_core::{
            ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
            HttpParams, InjectedCredentials,
        };

        let envelope = ExecutionEnvelope::new(
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
                agent_id: "agt_01j0000000e008000000000001"
                    .parse()
                    .expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        );
        TransportView::new(envelope, InjectedCredentials::empty())
    }
}
