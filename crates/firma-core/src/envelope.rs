use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The core protocol unit wrapping each outbound agent call.
///
/// Built by the Sidecar when intercepting an agent's request. Contains the
/// typed action intent, the raw capability token, and request metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEnvelope {
    /// Typed action parameters describing what the agent wants to do.
    pub intent: ExecutionIntent,
    /// Raw signed token string. Parsing happens in Stage 1 of the enforcement pipeline.
    pub capability: String,
    /// Session and request metadata for correlation and audit.
    pub metadata: RequestMetadata,
}

/// Typed description of the action an agent intends to perform.
///
/// Uses an enum with typed variants to prevent injection via untyped maps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionIntent {
    /// Outbound HTTP request.
    Http(HttpParams),
    /// Database query.
    DbQuery(DbQueryParams),
    /// Tool/function invocation.
    ToolUse(ToolUseParams),
}

/// Parameters for an outbound HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpParams {
    /// HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// Target URL.
    pub url: String,
    /// HTTP headers.
    pub headers: HashMap<String, String>,
}

/// Parameters for a database query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbQueryParams {
    /// SQL or query statement.
    pub statement: String,
    /// Target database name.
    pub db_name: String,
    /// Hint for policy: is this a read-only query?
    pub read_only: bool,
}

/// Parameters for a tool/function invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseParams {
    /// Name of the tool to invoke.
    pub tool_name: String,
    /// Tool-specific input payload. Schema validated downstream.
    pub input: serde_json::Value,
}

/// Correlation and audit metadata attached to every execution envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Session this request belongs to.
    pub session_id: String,
    /// Agent that initiated this request.
    pub agent_id: String,
    /// When the request was intercepted.
    pub timestamp: DateTime<Utc>,
    /// Optional distributed tracing correlation ID.
    pub trace_id: Option<String>,
}

/// Flattened attribute set consumed by policy evaluation (Stage 2).
///
/// Built from `ExecutionEnvelope` fields plus Sidecar-local state.
/// The derivation of `action` and `resource` from the envelope's intent
/// is Sidecar-specific logic (added in intent 006).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Agent identity, from envelope metadata.
    pub agent_id: String,
    /// Derived action string (e.g., `http:GET`, `tool:execute`).
    pub action: String,
    /// Target resource derived from intent (e.g., URL, DB name, tool name).
    pub resource: String,
    /// Session ID, from envelope metadata.
    pub session_id: String,
    /// Token ID, from parsed capability claims.
    pub token_id: String,
    /// Allowed actions from capability claims, for scope checks.
    pub token_actions: Vec<String>,
    /// Allowed resources from capability claims, for scope checks.
    pub token_resources: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_http_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope {
            intent: ExecutionIntent::Http(HttpParams {
                method: "GET".to_string(),
                url: "https://api.example.com/data".to_string(),
                headers: HashMap::from([("Authorization".to_string(), "Bearer tok".to_string())]),
            }),
            capability: "v4.public.eyJ0...".to_string(),
            metadata: RequestMetadata {
                session_id: "sess_001".to_string(),
                agent_id: "agent_abc".to_string(),
                timestamp: Utc::now(),
                trace_id: Some("trace_123".to_string()),
            },
        }
    }

    #[test]
    fn test_execution_envelope_construction() {
        let envelope = sample_http_envelope();
        assert_eq!(envelope.capability, "v4.public.eyJ0...");
        assert_eq!(envelope.metadata.agent_id, "agent_abc");
    }

    #[test]
    fn test_execution_intent_http() {
        let intent = ExecutionIntent::Http(HttpParams {
            method: "POST".to_string(),
            url: "https://api.example.com".to_string(),
            headers: HashMap::new(),
        });
        assert!(matches!(intent, ExecutionIntent::Http(_)));
    }

    #[test]
    fn test_execution_intent_db_query() {
        let intent = ExecutionIntent::DbQuery(DbQueryParams {
            statement: "SELECT 1".to_string(),
            db_name: "main".to_string(),
            read_only: true,
        });
        assert!(matches!(intent, ExecutionIntent::DbQuery(_)));
    }

    #[test]
    fn test_execution_intent_tool_use() {
        let intent = ExecutionIntent::ToolUse(ToolUseParams {
            tool_name: "calculator".to_string(),
            input: serde_json::json!({"expression": "2+2"}),
        });
        assert!(matches!(intent, ExecutionIntent::ToolUse(_)));
    }

    #[test]
    fn test_request_metadata_optional_trace_id() {
        let meta = RequestMetadata {
            session_id: "sess_001".to_string(),
            agent_id: "agent_abc".to_string(),
            timestamp: Utc::now(),
            trace_id: None,
        };
        assert!(meta.trace_id.is_none());
    }

    #[test]
    fn test_execution_context_construction() {
        let ctx = ExecutionContext {
            agent_id: "agent_abc".to_string(),
            action: "http:GET".to_string(),
            resource: "https://api.example.com/data".to_string(),
            session_id: "sess_001".to_string(),
            token_id: "tok_001".to_string(),
            token_actions: vec!["http:GET".to_string()],
            token_resources: vec!["https://api.example.com/*".to_string()],
        };
        assert_eq!(ctx.agent_id, "agent_abc");
        assert_eq!(ctx.action, "http:GET");
    }

    #[test]
    fn test_envelope_serde_round_trip() {
        let envelope = sample_http_envelope();
        let json = serde_json::to_string(&envelope).unwrap_or_else(|e| panic!("{e}"));
        let parsed: ExecutionEnvelope =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.capability, envelope.capability);
        assert_eq!(parsed.metadata.agent_id, envelope.metadata.agent_id);
    }
}
