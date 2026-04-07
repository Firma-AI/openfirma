//! Intent Normalizer / Envelope Builder.
//!
//! Runs in the Sidecar hot path immediately after interception and before
//! token validation. Deterministically maps the raw intercepted event into a
//! canonical `ExecutionEnvelope` with a normalized `intent.action_class`.
//!
//! This step performs deterministic rule-based canonicalization only — no
//! language model, SLM, probabilistic classifier, or similarity-based
//! inference is permitted on the hot path. It makes no policy decisions.
//!
//! Intent sub-fields produced: `action_class` (canonical semantic type),
//! `resource` (normalized target resource identifier), `params`
//! (action-specific parameters), `raw_transport` (original transport form —
//! observational, not used by policy), `raw_action_ref` (original tool name /
//! route / method — observational only).
//!
//! Failure behaviour: if classification fails or yields an ambiguous action
//! class for a protected operation, the normalizer returns
//! `DENY: UNCLASSIFIED_INTENT` and no Connector dispatch occurs (fail-closed).
//! Conforms to the FEP \[I-N1\] enforcement invariant.

mod mapping;

use std::collections::HashMap;

use firma_core::{
    ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams,
};

pub use self::mapping::{MappingTable, MatchResult};
use crate::enforcement::decision::{EnforcementDecision, EnforcementStage};
use crate::enforcement::error::EnforcementError;

/// Headers that must never leak into the `ExecutionEnvelope` (and therefore
/// into logs / audit trail). Compared case-insensitively.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
];

/// Raw intercepted request — the input to the enforcement pipeline.
/// Constructed by proxy-core from Pingora request data.
#[derive(Debug)]
pub struct RawRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub is_https: bool,
}

/// Maps raw intercepted requests to canonical `ExecutionEnvelope` instances.
///
/// Uses the `MappingTable` to find the matching action class, then builds
/// an immutable `ExecutionEnvelope` with all five intent sub-fields.
#[derive(Debug)]
pub struct IntentNormalizer {
    mapping_table: MappingTable,
}

impl IntentNormalizer {
    #[must_use]
    pub fn new(mapping_table: MappingTable) -> Self {
        Self { mapping_table }
    }

    /// Normalize a raw request into an `ExecutionEnvelope`.
    ///
    /// Returns `Err(EnforcementDecision::Deny)` with `UNCLASSIFIED_INTENT`
    /// if the request is protected but cannot be mapped.
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` if the request cannot be classified
    /// to a known action class, or if the host is not protected.
    #[allow(clippy::result_large_err)]
    pub fn normalize(
        &self,
        request: &RawRequest,
    ) -> Result<ExecutionEnvelope, EnforcementDecision> {
        let match_result =
            self.mapping_table
                .find_match(&request.method, &request.host, &request.path);

        match match_result {
            MatchResult::Matched(rule) => {
                let raw_action_ref = format!("{} {}", request.method.to_uppercase(), request.path);
                let raw_transport = if request.is_https { "https" } else { "http" };
                let resource = format!("{}{}", request.host, request.path);

                let http_method = parse_http_method(&request.method);

                let envelope = ExecutionEnvelope {
                    intent: ExecutionIntent {
                        action_class: rule.action_class.clone(),
                        resource,
                        params: ActionParams::Http(HttpParams {
                            method: http_method,
                            headers: sanitize_headers(&request.headers),
                            body: request.body.clone(),
                            query: HashMap::new(),
                        }),
                        raw_transport: raw_transport.to_string(),
                        raw_action_ref,
                    },
                    capability: String::new(), // filled after token selection
                    metadata: ExecutionMetadata {
                        session_id: String::new(), // filled by pipeline caller
                        agent_id: String::new(),   // filled from token claims
                        timestamp: chrono::Utc::now(),
                        trace_id: None,
                        budget_consumed: 0.0,
                        risk_score: None,
                    },
                    provenance: None,
                };

                Ok(envelope)
            }
            MatchResult::UnclassifiedProtected => {
                let detail = format!(
                    "protected action could not be classified: {} {} (host: {})",
                    request.method, request.path, request.host
                );
                Err(EnforcementError::NormalizationFailed { detail }
                    .into_deny(EnforcementStage::Normalization))
            }
            MatchResult::NotProtected => {
                // For now, treat non-protected as an error at the pipeline level.
                // The proxy-core caller should handle passthrough before calling enforce().
                let detail = format!("non-protected host: {} (not enforced)", request.host);
                Err(EnforcementError::NormalizationFailed { detail }
                    .into_deny(EnforcementStage::Normalization))
            }
        }
    }
}

fn sanitize_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !SENSITIVE_HEADERS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn parse_http_method(method: &str) -> HttpMethod {
    match method.to_uppercase().as_str() {
        "GET" => HttpMethod::GET,
        "PUT" => HttpMethod::PUT,
        "DELETE" => HttpMethod::DELETE,
        "PATCH" => HttpMethod::PATCH,
        "HEAD" => HttpMethod::HEAD,
        "OPTIONS" => HttpMethod::OPTIONS,
        // "POST" and unrecognised methods default to POST (fail-safe in enforcement)
        _ => HttpMethod::POST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::registry::ActionClassRegistry;

    fn test_normalizer() -> IntentNormalizer {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some("POST".to_string()),
                    host: "api.openai.com".to_string(),
                    path: Some("/v1/chat/completions".to_string()),
                    action_class: "llm.inference".to_string(),
                },
                MappingRuleConfig {
                    method: Some("GET".to_string()),
                    host: "*".to_string(),
                    path: None,
                    action_class: "http.get".to_string(),
                },
            ],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));
        IntentNormalizer::new(table)
    }

    #[test]
    fn test_normalize_openai_chat() {
        let normalizer = test_normalizer();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let result = normalizer.normalize(&request);
        assert!(result.is_ok());
        let envelope = result.unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(envelope.intent.action_class, "llm.inference");
        assert_eq!(envelope.intent.raw_transport, "https");
        assert_eq!(envelope.intent.raw_action_ref, "POST /v1/chat/completions");
    }

    #[test]
    fn test_normalize_strips_sensitive_headers() {
        let normalizer = test_normalizer();
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer secret".to_string());
        headers.insert("X-Api-Key".to_string(), "sk-123".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Cookie".to_string(), "session=abc".to_string());

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: None,
            is_https: true,
        };

        let envelope = normalizer.normalize(&request).unwrap();
        if let ActionParams::Http(ref params) = envelope.intent.params {
            assert!(
                !params
                    .headers
                    .keys()
                    .any(|k| SENSITIVE_HEADERS.contains(&k.to_lowercase().as_str())),
                "sensitive headers leaked into envelope"
            );
            assert_eq!(
                params.headers.get("Content-Type").unwrap(),
                "application/json"
            );
        } else {
            panic!("expected Http params");
        }
    }

    #[test]
    fn test_normalize_unclassified_protected() {
        let normalizer = test_normalizer();
        let request = RawRequest {
            method: "DELETE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/files/abc".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let result = normalizer.normalize(&request);
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_deny());
        assert_eq!(
            decision.deny_reason(),
            Some(firma_core::DenyReason::UnclassifiedIntent)
        );
    }
}
