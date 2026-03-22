use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ExecutionIntent {
    pub action: String,
    pub resource: String,
    pub params: Option<prost_types::Struct>,
}

#[derive(Debug, Clone)]
pub struct ExecutionMetadata {
    pub session_id: String,
    pub agent_id: String,
    pub timestamp: String,
    pub trace_id: Option<String>,
    pub budget_consumed: f64,
    pub risk_score: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct ExecutionEnvelope {
    pub intent: Option<ExecutionIntent>,
    pub capability: String,
    pub metadata: Option<ExecutionMetadata>,
    pub provenance: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectorResponse {
    pub status_code: i32,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
    pub latency_micros: i64,
    pub response_size_bytes: i64,
}

static REGISTRY: Lazy<RwLock<HashMap<String, Arc<dyn Connector>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone)]
pub enum ConnectorError {
    NotFound,
    TargetError { code: u16, message: String },
    Timeout(std::time::Duration),
    Internal(String),
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorError::NotFound => write!(f, "connector not found"),
            ConnectorError::TargetError { code, message } => {
                write!(f, "target error {}: {}", code, message)
            }
            ConnectorError::Timeout(d) => write!(f, "timeout after {:?}", d),
            ConnectorError::Internal(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for ConnectorError {}

#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> &'static str;

    async fn dispatch(
        &self,
        env: &ExecutionEnvelope,
    ) -> Result<ConnectorResponse, ConnectorError>;
}

/// Registers a connector with the global registry.
///
/// # Arguments
/// * `name` - Unique identifier for the connector
/// * `connector` - Thread-safe reference to the connector implementation
///
/// # Architectural Notes
///
/// Connectors may apply **technical constraints** only:
/// - Rate limits (calls/min to a specific API)
/// - Schema validation
/// - Response format normalization
/// - Protocol translation (HTTP ↔ gRPC ↔ DB)
///
/// **Business logic and authorization must remain in Cedar / Authority / Gate**, per the Firma architecture.
/// A connector that becomes a second policy engine will break the separation of concerns.
pub fn register(name: &str, connector: Arc<dyn Connector>) {
    let mut registry = REGISTRY.write().unwrap();
    registry.insert(name.to_string(), connector);
}

/// Retrieves a connector from the global registry by name.
///
/// # Arguments
/// * `name` - The connector's unique identifier
///
/// # Returns
/// - `Some(Arc<dyn Connector>)` if the connector exists
/// - `None` if no connector is registered with that name
pub fn get(name: &str) -> Option<Arc<dyn Connector>> {
    let registry = REGISTRY.read().unwrap();
    registry.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    struct FakeConnector;

    #[async_trait]
    impl Connector for FakeConnector {
        fn name(&self) -> &'static str {
            "fake"
        }

        async fn dispatch(
            &self,
            _env: &ExecutionEnvelope,
        ) -> Result<ConnectorResponse, ConnectorError> {
            Ok(ConnectorResponse {
                status_code: 200,
                body: b"OK".to_vec(),
                headers: HashMap::new(),
                latency_micros: 1000,
                response_size_bytes: 2,
            })
        }
    }

    #[test]
    async fn test_register_and_get_fake_connector() {
        let fake = Arc::new(FakeConnector);
        register("fake", fake.clone());
        
        let retrieved = get("fake");
        assert!(retrieved.is_some(), "Expected Some, got None");
        assert_eq!(retrieved.unwrap().name(), "fake");
    }

    #[test]
    async fn test_get_missing_connector_returns_none() {
        let retrieved = get("missing");
        assert!(retrieved.is_none(), "Expected None for missing connector");
    }

    #[test]
    async fn test_missing_connector_translates_to_deny() {
        let connector_name = "missing";
        let result = get(connector_name);
        
        if result.is_none() {
            let deny_reason = format!(
                "DENY: CONNECTOR_NOT_FOUND (connector '{}' not registered)",
                connector_name
            );
            assert!(deny_reason.contains("CONNECTOR_NOT_FOUND"));
        }
    }

    #[test]
    async fn test_connector_error_variants() {
        let not_found = ConnectorError::NotFound;
        assert!(matches!(not_found, ConnectorError::NotFound));

        let target_err = ConnectorError::TargetError { 
            code: 404, 
            message: "Not Found".to_string() 
        };
        assert!(matches!(target_err, ConnectorError::TargetError { code: 404, .. }));

        let timeout = ConnectorError::Timeout(std::time::Duration::from_secs(5));
        assert!(matches!(timeout, ConnectorError::Timeout(_)));

        let internal = ConnectorError::Internal("unexpected error".to_string());
        assert!(matches!(internal, ConnectorError::Internal(_)));
    }

    #[test]
    async fn test_registry_is_thread_safe() {
        use std::sync::Barrier;
        use std::thread;

        let barrier = Arc::new(Barrier::new(2));
        let clone_barrier = barrier.clone();

        let handle = thread::spawn(move || {
            let fake = Arc::new(FakeConnector);
            register("thread_safe_test", fake);
            clone_barrier.wait();
        });

        barrier.wait();
        
        let _ = get("thread_safe_test");
        
        handle.join().unwrap();
    }
}
