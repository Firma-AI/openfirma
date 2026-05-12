//! Intent Normalizer / Envelope Builder.
//!
//! Runs in the Sidecar hot path immediately after interception and before
//! token validation. Deterministically maps the raw intercepted event into a
//! canonical [`NormalizedEnvelope`] with a normalized `intent.action_class`.
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

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use firma_core::{ActionParams, ExecutionIntent, HttpMethod, HttpParams};

/// Hosts whose traffic earns the `provider = "github"` resource tag.
/// Exact match, not glob — typo-squat hostnames must not be tagged.
const GITHUB_HOSTS: &[&str] = &["api.github.com", "github.com"];

/// Hosts whose traffic earns the `provider = "stripe"` resource tag.
/// Exact match, not glob.
const STRIPE_HOSTS: &[&str] = &["api.stripe.com"];

/// Hosts whose traffic earns the `provider = "gmail"` resource tag.
/// Only `gmail.googleapis.com` qualifies — the legacy `www.googleapis.com`
/// host serves many non-Gmail Google APIs (Drive, Calendar, ...) and would
/// mis-tag traffic if added here.
const GMAIL_HOSTS: &[&str] = &["gmail.googleapis.com"];

/// Resolve a request host to a logical provider tag, if any. Used to populate
/// `intent.resource["provider"]`. Returns `None` for hosts outside the known
/// allowlist; downstream Cedar policies can still discriminate on
/// `host`/`path` directly.
fn provider_for_host(host: &str) -> Option<&'static str> {
    if GITHUB_HOSTS.contains(&host) {
        Some("github")
    } else if STRIPE_HOSTS.contains(&host) {
        Some("stripe")
    } else if GMAIL_HOSTS.contains(&host) {
        Some("gmail")
    } else {
        None
    }
}

pub use self::mapping::{MappingTable, MatchResult};
pub use crate::enforcement::decision::{EnforcementDecision, EnforcementStage};
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

/// Output of the intent normalizer — contains only the fields the normalizer can fill.
///
/// Missing fields (`capability`, `agent_id`, `session_id`) are populated by the pipeline
/// after Stage 1 validation when constructing the full `ExecutionEnvelope`.
#[derive(Debug, Clone)]
pub struct NormalizedEnvelope {
    pub intent: ExecutionIntent,
    pub timestamp: DateTime<Utc>,
}

/// Raw intercepted request — the input to the enforcement pipeline.
///
/// Produced by an [`Interceptor`](crate::interceptor::Interceptor) from
/// transport-specific input and consumed by [`IntentNormalizer`] to build a
/// canonical [`NormalizedEnvelope`]. All three interception modes (HTTP proxy,
/// gRPC hook, Unix socket) produce an identical `RawRequest`, keeping
/// downstream stages transport-agnostic.
///
/// Sensitive headers (`authorization`, `cookie`, `x-api-key`) are stripped
/// during normalization and never reach policy evaluation.
#[derive(Debug)]
pub struct RawRequest {
    /// HTTP method verb (e.g. `GET`, `POST`, `DELETE`).
    ///
    /// Together with `host` and `path`, determines the canonical
    /// `action_class` via the mapping table.
    pub method: String,
    /// Target host or domain (e.g. `api.stripe.com`).
    ///
    /// Maps to the `resource` sub-field of the normalized intent.
    pub host: String,
    /// Request path including any query string (e.g. `/v1/charges`).
    pub path: String,
    /// HTTP headers as key-value pairs.
    ///
    /// May contain sensitive headers at this stage; the normalizer filters
    /// them before building the [`NormalizedEnvelope`].
    pub headers: HashMap<String, String>,
    /// Optional request body as raw bytes.
    ///
    /// Used by the normalizer to extract `parameters` for the intent
    /// sub-field. `None` for bodiless methods like `GET` or `DELETE`.
    pub body: Option<Vec<u8>>,
    /// Whether the original request used HTTPS.
    ///
    /// Preserved as the `raw_transport` observational field in the
    /// [`NormalizedEnvelope`]; not used for policy evaluation.
    pub is_https: bool,
}

/// Maps raw intercepted requests to canonical [`NormalizedEnvelope`] instances.
///
/// Uses the `MappingTable` to find the matching action class, then builds
/// a `NormalizedEnvelope` with the five intent sub-fields and a timestamp.
/// Fields that depend on token validation (`capability`, `session_id`,
/// `agent_id`) are populated later by the pipeline.
#[derive(Debug)]
pub struct IntentNormalizer {
    mapping_table: MappingTable,
}

#[cfg(not(miri))]
fn runtime_timestamp() -> DateTime<Utc> {
    Utc::now()
}

#[cfg(miri)]
fn runtime_timestamp() -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap_or_else(|_| panic!("failed to build fixed miri timestamp"))
        .with_timezone(&Utc)
}

impl IntentNormalizer {
    #[must_use]
    pub const fn new(mapping_table: MappingTable) -> Self {
        Self { mapping_table }
    }

    /// Normalize a raw request into a [`NormalizedEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns `EnforcementDecision::Deny` with `UNCLASSIFIED_INTENT` if:
    /// - The request is protected but cannot be mapped to a known action class.
    /// - The HTTP method is not a recognized standard method (fail-closed).
    ///
    /// Returns `EnforcementDecision::Passthrough` if the host is not protected.
    #[expect(
        clippy::result_large_err,
        reason = "domain decision carries denial context"
    )]
    pub fn normalize(
        &self,
        request: &RawRequest,
    ) -> Result<NormalizedEnvelope, EnforcementDecision> {
        let match_result =
            self.mapping_table
                .find_match(&request.method, &request.host, &request.path);

        match match_result {
            MatchResult::Matched(rule) => {
                let raw_action_ref = format!("{} {}", request.method.to_uppercase(), request.path);
                let raw_transport = if request.is_https { "https" } else { "http" };
                let mut resource = BTreeMap::new();
                resource.insert("host".to_string(), request.host.clone());
                resource.insert("path".to_string(), request.path.clone());
                if let Some(provider) = provider_for_host(&request.host) {
                    resource.insert("provider".to_string(), provider.to_string());
                }

                let Some(http_method) = parse_http_method(&request.method) else {
                    let detail = format!(
                        "unrecognized HTTP method: {} {} (host: {})",
                        request.method, request.path, request.host
                    );
                    return Err(EnforcementError::NormalizationFailed { detail }
                        .into_deny(EnforcementStage::Normalization));
                };

                let envelope = NormalizedEnvelope {
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
                    timestamp: runtime_timestamp(),
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
                let detail = format!("non-protected host: {} (not enforced)", request.host);
                Err(EnforcementDecision::Passthrough { detail })
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

fn parse_http_method(method: &str) -> Option<HttpMethod> {
    match method.to_uppercase().as_str() {
        "GET" => Some(HttpMethod::GET),
        "POST" => Some(HttpMethod::POST),
        "PUT" => Some(HttpMethod::PUT),
        "DELETE" => Some(HttpMethod::DELETE),
        "PATCH" => Some(HttpMethod::PATCH),
        "HEAD" => Some(HttpMethod::HEAD),
        "OPTIONS" => Some(HttpMethod::OPTIONS),
        "CONNECT" => Some(HttpMethod::CONNECT),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::registry::ActionClassRegistry;

    fn test_normalizer() -> IntentNormalizer {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: Some("POST".to_string()),
                    host: "api.openai.com".to_string(),
                    path: Some("/v1/chat/completions".to_string()),
                    action_class: "communication.external.send".to_string(),
                },
                MappingRuleConfig {
                    method: Some("GET".to_string()),
                    host: "*".to_string(),
                    path: None,
                    action_class: "filesystem.read".to_string(),
                },
                MappingRuleConfig {
                    method: Some("GET".to_string()),
                    host: "api.github.com".to_string(),
                    path: Some("/repos/*/*".to_string()),
                    action_class: "code.read".to_string(),
                },
            ],
        };
        let table =
            MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"));
        IntentNormalizer::new(table)
    }

    fn make_request(method: &str, host: &str, path: &str) -> RawRequest {
        RawRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        }
    }

    fn load_mapping_file(filename: &str) -> MappingRulesFile {
        let path = format!(
            "{}/config/mappings/{}",
            env!("CARGO_MANIFEST_DIR"),
            filename
        );
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {filename}: {e}"));
        let file: MappingRulesFile =
            toml::from_str(&src).unwrap_or_else(|e| panic!("parse {filename}: {e}"));
        file.validate().unwrap_or_else(|e| panic!("validate: {e}"));
        file
    }

    fn normalizer_from_file(filename: &str) -> IntentNormalizer {
        let registry = ActionClassRegistry::v0_1();
        let file = load_mapping_file(filename);
        let table = MappingTable::from_config(&file, &registry, true)
            .unwrap_or_else(|e| panic!("from_config: {e}"));
        IntentNormalizer::new(table)
    }

    fn github_normalizer() -> IntentNormalizer {
        normalizer_from_file("github.toml")
    }

    fn stripe_normalizer() -> IntentNormalizer {
        normalizer_from_file("stripe.toml")
    }

    fn gmail_normalizer() -> IntentNormalizer {
        normalizer_from_file("gmail.toml")
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
        assert_eq!(envelope.intent.action_class, "communication.external.send");
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
    fn test_normalize_not_protected_returns_passthrough() {
        let registry = ActionClassRegistry::v0_1();
        let file = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&file, &registry, false).unwrap_or_else(|e| panic!("{e}"));
        let normalizer = IntentNormalizer::new(table);

        let request = RawRequest {
            method: "GET".to_string(),
            host: "not-protected.example.com".to_string(),
            path: "/any".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let result = normalizer.normalize(&request);
        assert!(result.is_err());
        let decision = result.unwrap_err();
        assert!(decision.is_passthrough());
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

    #[test]
    fn test_normalize_unrecognized_method_denied() {
        let normalizer = test_normalizer();
        let request = RawRequest {
            method: "FROBNICATE".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
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

    #[test]
    fn test_normalize_strips_set_cookie_header() {
        let normalizer = test_normalizer();
        let mut headers = HashMap::new();
        headers.insert("Set-Cookie".to_string(), "session=abc".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: None,
            is_https: true,
        };

        let envelope = normalizer
            .normalize(&request)
            .unwrap_or_else(|_| panic!("expected Ok"));
        if let ActionParams::Http(ref params) = envelope.intent.params {
            assert!(
                !params.headers.contains_key("Set-Cookie"),
                "set-cookie header must be stripped"
            );
            assert!(params.headers.contains_key("Content-Type"));
        } else {
            panic!("expected Http params");
        }
    }

    #[test]
    fn test_normalize_strips_proxy_authorization_header() {
        let normalizer = test_normalizer();
        let mut headers = HashMap::new();
        headers.insert(
            "Proxy-Authorization".to_string(),
            "Basic abc123".to_string(),
        );
        headers.insert("Accept".to_string(), "application/json".to_string());

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: None,
            is_https: true,
        };

        let envelope = normalizer
            .normalize(&request)
            .unwrap_or_else(|_| panic!("expected Ok"));
        if let ActionParams::Http(ref params) = envelope.intent.params {
            assert!(
                !params.headers.contains_key("Proxy-Authorization"),
                "proxy-authorization header must be stripped"
            );
            assert!(params.headers.contains_key("Accept"));
        } else {
            panic!("expected Http params");
        }
    }

    #[test]
    fn test_normalize_body_passthrough() {
        let normalizer = test_normalizer();
        let body_bytes = b"{\"model\":\"gpt-4\"}".to_vec();

        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: Some(body_bytes.clone()),
            is_https: true,
        };

        let envelope = normalizer
            .normalize(&request)
            .unwrap_or_else(|_| panic!("expected Ok"));
        if let ActionParams::Http(ref params) = envelope.intent.params {
            assert_eq!(
                params.body.as_ref(),
                Some(&body_bytes),
                "body bytes must be preserved"
            );
        } else {
            panic!("expected Http params");
        }
    }

    #[test]
    fn test_normalize_http_transport() {
        let normalizer = test_normalizer();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: false,
        };

        let envelope = normalizer
            .normalize(&request)
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(envelope.intent.raw_transport, "http");
    }

    #[test]
    fn test_normalize_resource_format() {
        let normalizer = test_normalizer();
        let request = RawRequest {
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let envelope = normalizer
            .normalize(&request)
            .unwrap_or_else(|_| panic!("expected Ok"));
        assert_eq!(
            envelope.intent.resource.get("host"),
            Some(&"api.openai.com".to_string())
        );
        assert_eq!(
            envelope.intent.resource.get("path"),
            Some(&"/v1/chat/completions".to_string())
        );
        assert_eq!(
            envelope.intent.resource_display(),
            "api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn test_normalize_github_tags_provider() {
        let normalizer = test_normalizer();
        let envelope = normalizer
            .normalize(&make_request("GET", "api.github.com", "/repos/acme/widget"))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(envelope.intent.action_class, "code.read");
        assert_eq!(
            envelope.intent.resource.get("provider"),
            Some(&"github".to_string())
        );
        assert_eq!(
            envelope.intent.resource.get("host"),
            Some(&"api.github.com".to_string())
        );
    }

    #[test]
    fn test_normalize_non_github_host_has_no_provider_key() {
        let normalizer = test_normalizer();
        let envelope = normalizer
            .normalize(&make_request(
                "POST",
                "api.openai.com",
                "/v1/chat/completions",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert!(!envelope.intent.resource.contains_key("provider"));
    }

    #[test]
    fn test_normalize_github_typosquat_no_provider() {
        let normalizer = test_normalizer();
        if let Ok(envelope) = normalizer.normalize(&make_request(
            "GET",
            "api.github.com.evil.example",
            "/repos/x/y",
        )) {
            assert!(!envelope.intent.resource.contains_key("provider"));
        }
    }

    #[test]
    fn test_github_mapping_file_loads_and_has_44_rules() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config/mappings/github.toml");
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read: {e}"));
        let file: MappingRulesFile = toml::from_str(&src).unwrap_or_else(|e| panic!("parse: {e}"));
        file.validate().unwrap_or_else(|e| panic!("validate: {e}"));
        assert_eq!(file.rules.len(), 44);
        let registry = ActionClassRegistry::v0_1();
        let _table = MappingTable::from_config(&file, &registry, true)
            .unwrap_or_else(|e| panic!("from_config: {e}"));
    }

    #[test]
    fn test_github_get_pulls_is_code_review_read() {
        let normalizer = github_normalizer();
        let env = normalizer
            .normalize(&make_request("GET", "api.github.com", "/repos/x/y/pulls"))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "code.review.read");
    }

    #[test]
    fn test_github_post_pulls_is_code_write() {
        let normalizer = github_normalizer();
        let env = normalizer
            .normalize(&make_request("POST", "api.github.com", "/repos/x/y/pulls"))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "code.write");
    }

    #[test]
    fn test_github_put_merge_is_code_merge() {
        let normalizer = github_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "PUT",
                "api.github.com",
                "/repos/x/y/pulls/1/merge",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "code.merge");
    }

    #[test]
    fn test_github_delete_contents_is_code_destructive() {
        let normalizer = github_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "DELETE",
                "api.github.com",
                "/repos/x/y/contents/foo.txt",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "code.destructive");
    }

    #[test]
    fn test_github_branch_protection_matches_repo_admin() {
        let normalizer = github_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "GET",
                "api.github.com",
                "/repos/x/y/branches/main/protection/restrictions",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "repo.admin");
    }

    // --- Stripe mapping coverage --------------------------------------------

    #[test]
    fn test_stripe_mapping_file_loads_and_has_88_rules() {
        let file = load_mapping_file("stripe.toml");
        assert_eq!(file.rules.len(), 88);
        let registry = ActionClassRegistry::v0_1();
        let _table = MappingTable::from_config(&file, &registry, true)
            .unwrap_or_else(|e| panic!("from_config: {e}"));
    }

    #[test]
    fn test_normalize_stripe_tags_provider() {
        let normalizer = stripe_normalizer();
        let envelope = normalizer
            .normalize(&make_request("GET", "api.stripe.com", "/v1/balance"))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(envelope.intent.action_class, "payment.read");
        assert_eq!(
            envelope.intent.resource.get("provider"),
            Some(&"stripe".to_string())
        );
    }

    #[test]
    fn test_stripe_post_payment_intent_is_payment_transfer() {
        let normalizer = stripe_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "api.stripe.com",
                "/v1/payment_intents",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "payment.transfer");
    }

    #[test]
    fn test_stripe_post_payment_intent_cancel_is_payment_cancel() {
        let normalizer = stripe_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "api.stripe.com",
                "/v1/payment_intents/pi_123/cancel",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "payment.cancel");
    }

    #[test]
    fn test_stripe_post_refund_is_payment_refund() {
        let normalizer = stripe_normalizer();
        let env = normalizer
            .normalize(&make_request("POST", "api.stripe.com", "/v1/refunds"))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "payment.refund");
    }

    #[test]
    fn test_stripe_post_payout_is_payment_payout() {
        let normalizer = stripe_normalizer();
        let env = normalizer
            .normalize(&make_request("POST", "api.stripe.com", "/v1/payouts"))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "payment.payout");
    }

    #[test]
    fn test_stripe_get_customers_search_is_customer_read() {
        let normalizer = stripe_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "GET",
                "api.stripe.com",
                "/v1/customers/search",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "customer.read");
    }

    #[test]
    fn test_stripe_post_webhook_endpoint_is_account_permission_change() {
        let normalizer = stripe_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "api.stripe.com",
                "/v1/webhook_endpoints",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "account.permission.change");
    }

    // --- Gmail mapping coverage ---------------------------------------------

    #[test]
    fn test_gmail_mapping_file_loads_and_has_41_rules() {
        let file = load_mapping_file("gmail.toml");
        assert_eq!(file.rules.len(), 41);
        let registry = ActionClassRegistry::v0_1();
        let _table = MappingTable::from_config(&file, &registry, true)
            .unwrap_or_else(|e| panic!("from_config: {e}"));
    }

    #[test]
    fn test_normalize_gmail_tags_provider() {
        let normalizer = gmail_normalizer();
        let envelope = normalizer
            .normalize(&make_request(
                "GET",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/profile",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(envelope.intent.action_class, "communication.external.read");
        assert_eq!(
            envelope.intent.resource.get("provider"),
            Some(&"gmail".to_string())
        );
    }

    #[test]
    fn test_gmail_messages_send_is_communication_send() {
        let normalizer = gmail_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/messages/send",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "communication.external.send");
    }

    #[test]
    fn test_gmail_post_drafts_is_communication_draft() {
        let normalizer = gmail_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/drafts",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "communication.external.draft");
    }

    #[test]
    fn test_gmail_messages_modify_is_communication_manage() {
        let normalizer = gmail_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/messages/abc123/modify",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "communication.external.manage");
    }

    #[test]
    fn test_gmail_delete_message_is_communication_delete() {
        let normalizer = gmail_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "DELETE",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/messages/abc123",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "communication.external.delete");
    }

    #[test]
    fn test_gmail_settings_filters_post_is_communication_filter() {
        let normalizer = gmail_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/settings/filters",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "communication.external.filter");
    }

    #[test]
    fn test_gmail_delegates_post_is_account_permission_change() {
        let normalizer = gmail_normalizer();
        let env = normalizer
            .normalize(&make_request(
                "POST",
                "gmail.googleapis.com",
                "/gmail/v1/users/me/settings/delegates",
            ))
            .unwrap_or_else(|_| panic!("ok"));
        assert_eq!(env.intent.action_class, "account.permission.change");
    }

    #[test]
    fn test_gmail_typosquat_no_provider() {
        let normalizer = test_normalizer();
        if let Ok(envelope) = normalizer.normalize(&make_request(
            "GET",
            "gmail.googleapis.com.evil.example",
            "/gmail/v1/users/me/profile",
        )) {
            assert!(!envelope.intent.resource.contains_key("provider"));
        }
    }

    #[test]
    fn test_normalize_none_body_for_get() {
        let normalizer = test_normalizer();
        let request = RawRequest {
            method: "GET".to_string(),
            host: "api.example.com".to_string(),
            path: "/data".to_string(),
            headers: HashMap::new(),
            body: None,
            is_https: true,
        };

        let envelope = normalizer
            .normalize(&request)
            .unwrap_or_else(|_| panic!("expected Ok"));
        if let ActionParams::Http(ref params) = envelope.intent.params {
            assert!(params.body.is_none());
            assert_eq!(params.method, HttpMethod::GET);
        } else {
            panic!("expected Http params");
        }
    }
}
