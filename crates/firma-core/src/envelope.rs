use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The core protocol unit wrapping each outbound agent call.
///
/// Built by the Sidecar when intercepting an agent's request. Contains the
/// typed action intent, the raw capability token, metadata, and provenance.
/// Immutable once created — any enrichment produces a derived structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEnvelope {
    /// Typed action parameters describing what the agent wants to do.
    pub intent: ExecutionIntent,
    /// Raw signed token string. Parsing happens in Stage 1 of the enforcement pipeline.
    pub capability: String,
    /// Session and runtime metadata for correlation and audit.
    pub metadata: ExecutionMetadata,
    /// Schema-reserved provenance field. V1 does not populate this.
    /// Intended for anchoring the envelope to the session's prior calls
    /// in future versions (causal chain, replay, attestation).
    pub provenance: Option<String>,
}

/// Typed description of the action an agent intends to perform.
///
/// Mirrors the proto `ExecutionIntent` message: a top-level `resource`
/// identifier plus a `oneof params` for the typed action kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionIntent {
    /// Target resource identifier (e.g., URL, table name, tool name).
    pub resource: String,
    /// Typed action parameters — exactly one action kind per intent.
    pub params: ActionParams,
}

/// Typed action parameters (maps to the proto `oneof params`).
///
/// Uses an enum with typed variants to prevent injection via untyped maps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionParams {
    /// Outbound HTTP request.
    Http(HttpParams),
    /// Database query.
    DbQuery(DbQueryParams),
    /// Tool/function invocation.
    ToolUse(ToolUseParams),
}

/// HTTP methods that can appear in an outbound request.
///
/// Restricts the method to known values so that invalid strings
/// (e.g., `"WHATEVER"`) are rejected at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
}

/// Parameters for an outbound HTTP request.
///
/// The target URL lives on `ExecutionIntent.resource`, not here —
/// matching the proto where `HttpParams` carries method, headers, body, and query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpParams {
    /// HTTP method.
    pub method: HttpMethod,
    /// HTTP headers — allowlisted keys only.
    pub headers: HashMap<String, String>,
    /// Request body as raw bytes (empty for GET/DELETE).
    pub body: Option<Vec<u8>>,
    /// Query parameters.
    pub query: HashMap<String, String>,
}

/// Parameters for a database query.
///
/// Uses a named query plus bindings instead of a raw SQL statement,
/// aligning with the intent-003 proto definition and preventing
/// raw SQL injection at the type level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbQueryParams {
    /// Registered query name (looked up in a query registry).
    pub query_name: String,
    /// Bound parameters — scalar values only, keyed by placeholder name.
    pub bindings: HashMap<String, String>,
    /// Target database name.
    pub db_name: String,
    /// Hint for policy: is this a read-only query?
    pub read_only: bool,
}

/// Parameters for a tool/function invocation.
///
/// Input is a flat `String → String` map (scalar values only),
/// schema-validated against the tool registry. Aligns with the
/// intent-003 proto definition and keeps the core→proto conversion trivial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseParams {
    /// Name of the tool to invoke.
    pub tool_name: String,
    /// Scalar tool inputs, validated against the tool registry schema.
    pub input: HashMap<String, String>,
}

/// Session and runtime context attached to every execution envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetadata {
    /// Session this request belongs to.
    pub session_id: String,
    /// Agent that initiated this request.
    pub agent_id: String,
    /// When the request was intercepted.
    pub timestamp: DateTime<Utc>,
    /// Optional distributed tracing correlation ID.
    pub trace_id: Option<String>,
    /// Cumulative budget consumed in this session (e.g., API cost in USD).
    /// Schema-reserved; populated when budget tracking is implemented.
    pub budget_consumed: f64,
    /// Static or pre-computed risk attribute. Defaults to None.
    /// Schema-reserved; populated when risk scoring is implemented.
    pub risk_score: Option<f64>,
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
            intent: ExecutionIntent {
                resource: "https://api.example.com/data".to_string(),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::from([("Authorization".to_string(), "Bearer tok".to_string())]),
                    body: None,
                    query: HashMap::new(),
                }),
            },
            capability: "v4.public.eyJ0...".to_string(),
            metadata: ExecutionMetadata {
                session_id: "sess_001".to_string(),
                agent_id: "agent_abc".to_string(),
                timestamp: Utc::now(),
                trace_id: Some("trace_123".to_string()),
                budget_consumed: 0.0,
                risk_score: None,
            },
            provenance: None,
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
        let intent = ExecutionIntent {
            resource: "https://api.example.com".to_string(),
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::POST,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
        };
        assert!(matches!(intent.params, ActionParams::Http(_)));
    }

    #[test]
    fn test_execution_intent_db_query() {
        let intent = ExecutionIntent {
            resource: "main".to_string(),
            params: ActionParams::DbQuery(DbQueryParams {
                query_name: "get_user_by_id".to_string(),
                bindings: HashMap::from([("id".to_string(), "42".to_string())]),
                db_name: "main".to_string(),
                read_only: true,
            }),
        };
        assert!(matches!(intent.params, ActionParams::DbQuery(_)));
    }

    #[test]
    fn test_execution_intent_tool_use() {
        let intent = ExecutionIntent {
            resource: "calculator".to_string(),
            params: ActionParams::ToolUse(ToolUseParams {
                tool_name: "calculator".to_string(),
                input: HashMap::from([("expression".to_string(), "2+2".to_string())]),
            }),
        };
        assert!(matches!(intent.params, ActionParams::ToolUse(_)));
    }

    #[test]
    fn test_execution_metadata_optional_trace_id() {
        let meta = ExecutionMetadata {
            session_id: "sess_001".to_string(),
            agent_id: "agent_abc".to_string(),
            timestamp: Utc::now(),
            trace_id: None,
            budget_consumed: 0.0,
            risk_score: None,
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
