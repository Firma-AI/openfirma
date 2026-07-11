use std::collections::{BTreeMap, HashMap};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{HeaderName, Method, agent::AgentId, session::SessionId, token::TokenId};

/// The core protocol unit wrapping each outbound agent call.
///
/// Built by the Sidecar when intercepting an agent's request. Contains the
/// typed action intent, the raw capability token, metadata, and provenance.
/// Immutable once created — any enrichment produces a derived structure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionEnvelope {
    /// Typed action parameters describing what the agent wants to do.
    pub intent: ExecutionIntent,
    /// Raw signed token string. Parsing happens in Stage 1 of the enforcement pipeline.
    pub capability: String,
    /// Session and runtime metadata for correlation and audit.
    pub metadata: ExecutionMetadata,
    /// Tamper-evident provenance chain anchor (AARM R2 G2). Populated by
    /// the sidecar for admitted (Allow/Modify) actions as
    /// `hex(SHA256(prev || context_hash || action || resource))`, chaining
    /// this action to the session's prior admitted calls. `None` for
    /// denied/deferred actions which carry no envelope.
    pub provenance: Option<String>,
}

impl ExecutionEnvelope {
    /// Constructs a new `ExecutionEnvelope`.
    #[must_use]
    pub fn new(
        intent: ExecutionIntent,
        capability: String,
        metadata: ExecutionMetadata,
        provenance: Option<String>,
    ) -> Self {
        Self {
            intent,
            capability,
            metadata,
            provenance,
        }
    }

    /// Gets the typed action parameters describing what the agent wants to do.
    #[must_use]
    pub fn intent(&self) -> &ExecutionIntent {
        &self.intent
    }

    /// Gets the raw signed token string.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Gets the session and runtime metadata for correlation and audit.
    #[must_use]
    pub fn metadata(&self) -> &ExecutionMetadata {
        &self.metadata
    }

    /// Gets the schema-reserved provenance field.
    #[must_use]
    pub fn provenance(&self) -> Option<&str> {
        self.provenance.as_deref()
    }
}

/// Typed description of the action an agent intends to perform.
///
/// Contains five canonical intent sub-fields: `action_class`, `resource`,
/// `params`, `raw_transport`, and `raw_action_ref`. The `action_class` is
/// the canonical class from the v0.1 Action Class Registry, set by the
/// Sidecar's intent normalizer after mapping the raw intercepted request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionIntent {
    /// Canonical action class from the v0.1 registry (e.g.,
    /// `"communication.external.send"`, `"filesystem.read"`). Set by the
    /// intent normalizer. See FEP §2.3.5 and
    /// `docs/markdown/firma_action_class_registry.md`.
    pub action_class: String,
    /// Target resource identifier as a structured attribute map.
    ///
    /// Conventional keys:
    /// - `host` — request host (always present for HTTP intents).
    /// - `path` — request path (always present for HTTP intents).
    /// - `provider` — logical provider when detectable (e.g., `"github"`).
    ///
    /// `BTreeMap` (not `HashMap`) so audit serialization and hashing are
    /// deterministic. Implementations MAY add free-form keys without
    /// schema churn. No other keys are reserved by the protocol.
    pub resource: BTreeMap<String, String>,
    /// Typed action parameters — exactly one action kind per intent.
    pub params: ActionParams,
    /// Original transport protocol (e.g., `"http"`, `"https"`).
    pub raw_transport: String,
    /// Original request signature for traceability (e.g., `"POST /v1/chat/completions"`).
    pub raw_action_ref: String,
}

impl ExecutionIntent {
    /// Derive a display / scope-check string from the resource map.
    ///
    /// Returns `format!("{host}{path}")` where missing keys resolve to
    /// an empty string. Consumed by scope prefix matching, Cedar
    /// `resource` string attributes, and connector URL construction
    /// (`scheme://{resource_display}`).
    #[must_use]
    pub fn resource_display(&self) -> String {
        let host = self.resource.get("host").map_or("", String::as_str);
        let path = self.resource.get("path").map_or("", String::as_str);
        format!("{host}{path}")
    }

    /// Build a resource map from a display-form string `host[/path]`.
    ///
    /// Strips a leading `https://` / `http://` if present, then splits
    /// the remainder at the first `/` into `host` and `path` keys.
    /// Convenience constructor for tests and synthetic envelopes
    /// (passthrough, deny-only). Production normalization uses the
    /// `IntentNormalizer` which fills the map field-by-field including
    /// the optional `provider` tag.
    #[must_use]
    pub fn resource_map_from(host_path: &str) -> BTreeMap<String, String> {
        let stripped = host_path
            .strip_prefix("https://")
            .or_else(|| host_path.strip_prefix("http://"))
            .unwrap_or(host_path);
        let (host, path) = stripped
            .find('/')
            .map_or((stripped, ""), |i| (&stripped[..i], &stripped[i..]));
        let mut m = BTreeMap::new();
        m.insert("host".to_string(), host.to_string());
        m.insert("path".to_string(), path.to_string());
        m
    }
}

/// Typed action parameters (maps to the proto `oneof params`).
///
/// Uses an enum with typed variants to prevent injection via untyped maps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    CONNECT,
}

impl HttpMethod {
    /// Stable static label used by structured logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::PATCH => "PATCH",
            Self::HEAD => "HEAD",
            Self::OPTIONS => "OPTIONS",
            Self::CONNECT => "CONNECT",
        }
    }
}

impl<'a> TryFrom<&'a Method> for HttpMethod {
    type Error = InvalidMethod<'a>;

    fn try_from(value: &'a Method) -> Result<Self, Self::Error> {
        match *value {
            Method::GET => Ok(Self::GET),
            Method::POST => Ok(Self::POST),
            Method::PUT => Ok(Self::PUT),
            Method::DELETE => Ok(Self::DELETE),
            Method::PATCH => Ok(Self::PATCH),
            Method::HEAD => Ok(Self::HEAD),
            Method::OPTIONS => Ok(Self::OPTIONS),
            Method::CONNECT => Ok(Self::CONNECT),
            _ => Err(InvalidMethod(value)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid method {0}")]
pub struct InvalidMethod<'a>(&'a Method);

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Parameters for an outbound HTTP request.
///
/// The target URL lives on `ExecutionIntent.resource`, not here —
/// matching the proto where `HttpParams` carries method, headers, body, and query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpParams {
    /// HTTP method.
    pub method: HttpMethod,
    /// HTTP headers — allowlisted keys only.
    pub headers: HashMap<HeaderName, String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolUseParams {
    /// Name of the tool to invoke.
    pub tool_name: String,
    /// Scalar tool inputs, validated against the tool registry schema.
    pub input: HashMap<String, String>,
}

/// Session and runtime context attached to every execution envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionMetadata {
    /// Session this request belongs to.
    pub session_id: SessionId,
    /// Agent that initiated this request.
    pub agent_id: AgentId,
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
    /// Server-derived conversation thread identity (AARM R2 G2). Groups
    /// admitted actions within a session into a causal thread. Derived
    /// by the sidecar from the session — one thread per session in V1.
    pub thread_id: Option<String>,
    /// Server-derived parent action identity (AARM R2 G2). The provenance
    /// anchor of the prior admitted action in this thread, linking the
    /// causal chain. `None` for the first admitted action.
    pub parent_action_id: Option<String>,
}

/// Flattened attribute set consumed by policy evaluation (Stage 2).
///
/// Built from `ExecutionEnvelope` fields plus Sidecar-local state.
/// The derivation of `action` and `resource` from the envelope's intent
/// is Sidecar-specific logic (added in intent 006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Agent identity, from envelope metadata.
    pub agent_id: AgentId,
    /// Derived action string (e.g., `http:GET`, `tool:execute`).
    pub action: String,
    /// Target resource derived from intent (e.g., URL, DB name, tool name).
    pub resource: String,
    /// Session ID, from envelope metadata.
    pub session_id: SessionId,
    /// Token ID, from parsed capability claims.
    pub token_id: TokenId,
    /// Allowed actions from capability claims, for scope checks.
    pub token_actions: Vec<String>,
    /// Allowed resources from capability claims, for scope checks.
    pub token_resources: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pretty_assertions::assert_eq;

    #[test]
    fn envelope_payload_backward_compat() {
        let json = r#"{
            "intent": {
                "action_class": "filesystem.read",
                "resource": {"host": "api.example.com", "path": "/data"},
                "params": {
                    "Http": {
                        "method": "GET",
                        "headers": {"Authorization": "Bearer tok"},
                        "body": null,
                        "query": {}
                    }
                },
                "raw_transport": "https",
                "raw_action_ref": "GET /data"
            },
            "capability": "v4.public.golden",
            "metadata": {
                "session_id": "golden-sess",
                "agent_id": "golden-agent",
                "timestamp": "2024-01-01T00:00:00Z",
                "trace_id": "golden-trace",
                "budget_consumed": 0.0,
                "risk_score": null
            },
            "provenance": null
        }"#;
        let envelope: ExecutionEnvelope = serde_json::from_str(json).unwrap();

        let expected = ExecutionEnvelope {
            intent: ExecutionIntent {
                action_class: "filesystem.read".to_string(),
                resource: BTreeMap::from([
                    ("host".to_string(), "api.example.com".to_string()),
                    ("path".to_string(), "/data".to_string()),
                ]),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::from([(
                        HeaderName::from_static("authorization"),
                        "Bearer tok".to_string(),
                    )]),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "GET /data".to_string(),
            },
            capability: "v4.public.golden".to_string(),
            metadata: ExecutionMetadata {
                session_id: "golden-sess".parse().unwrap(),
                agent_id: "golden-agent".parse().unwrap(),
                timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .expect("fixed date")
                    .with_timezone(&Utc),
                trace_id: Some("golden-trace".to_string()),
                budget_consumed: 0.0,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            provenance: None,
        };

        assert_eq!(envelope, expected);
    }

    #[test]
    fn resource_display_concats_host_and_path() {
        let mut resource = BTreeMap::new();
        resource.insert("host".to_string(), "api.github.com".to_string());
        resource.insert("path".to_string(), "/repos/x/y".to_string());
        let intent = ExecutionIntent {
            action_class: "code.read".to_string(),
            resource,
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::GET,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "https".to_string(),
            raw_action_ref: "GET /repos/x/y".to_string(),
        };
        assert_eq!(intent.resource_display(), "api.github.com/repos/x/y");
    }

    #[test]
    fn resource_display_missing_keys_yields_empty_string() {
        let intent = ExecutionIntent {
            action_class: "filesystem.read".to_string(),
            resource: BTreeMap::new(),
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::GET,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "https".to_string(),
            raw_action_ref: "GET /".to_string(),
        };
        assert_eq!(intent.resource_display(), "");
    }

    #[test]
    fn resource_map_serializes_in_sorted_key_order() {
        let mut resource = BTreeMap::new();
        resource.insert("provider".to_string(), "github".to_string());
        resource.insert("host".to_string(), "api.github.com".to_string());
        resource.insert("path".to_string(), "/repos/x/y".to_string());
        let intent = ExecutionIntent {
            action_class: "code.read".to_string(),
            resource,
            params: ActionParams::Http(HttpParams {
                method: HttpMethod::GET,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: "https".to_string(),
            raw_action_ref: "GET /repos/x/y".to_string(),
        };
        let json = serde_json::to_string(&intent).expect("serialize");
        let host_idx = json.find("\"host\"").expect("host");
        let path_idx = json.find("\"path\"").expect("path");
        let provider_idx = json.find("\"provider\"").expect("provider");
        assert!(host_idx < path_idx);
        assert!(path_idx < provider_idx);
    }

    #[test]
    fn action_params_db_query_backward_compat() {
        let json = r#"{
            "DbQuery": {
                "query_name": "get_user_by_id",
                "bindings": {"id": "42"},
                "db_name": "main",
                "read_only": true
            }
        }"#;

        let params: ActionParams = serde_json::from_str(json).unwrap();
        let expected = ActionParams::DbQuery(DbQueryParams {
            query_name: "get_user_by_id".to_string(),
            bindings: HashMap::from([("id".to_string(), "42".to_string())]),
            db_name: "main".to_string(),
            read_only: true,
        });

        assert_eq!(params, expected);
    }

    #[test]
    fn action_params_tool_use_backward_compat() {
        let json = r#"{
            "ToolUse": {
                "tool_name": "calculator",
                "input": {"expression": "2+2"}
            }
        }"#;

        let params: ActionParams = serde_json::from_str(json).unwrap();
        let expected = ActionParams::ToolUse(ToolUseParams {
            tool_name: "calculator".to_string(),
            input: HashMap::from([("expression".to_string(), "2+2".to_string())]),
        });

        assert_eq!(params, expected);
    }

    #[test]
    fn http_method_display_covers_connect() {
        assert_eq!(HttpMethod::GET.to_string(), "GET");
        assert_eq!(HttpMethod::CONNECT.to_string(), "CONNECT");
    }
}
