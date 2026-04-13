//! gRPC hook interceptor.
//!
//! Implements the [`Interceptor`](super::Interceptor) trait as a Tonic gRPC
//! server. The agent process registers this interceptor programmatically and
//! calls the `Intercept` RPC for every outbound action — no port binding or
//! proxy environment variable is required.
//!
//! The service converts each `InterceptRequest` proto message into a
//! [`RawRequest`](crate::normalizer::RawRequest), runs it through the
//! [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline), and returns
//! an `InterceptResponse` with the ALLOW / DENY decision.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tonic::transport::Server;

use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::{EnforcementDecision, EnforcementPipeline, RawRequest};
use firma_grpc_interceptor_proto::interceptor_hook_server::{
    InterceptorHook, InterceptorHookServer,
};
use firma_grpc_interceptor_proto::{InterceptRequest, InterceptResponse};

/// Tonic-based gRPC hook interceptor.
///
/// Exposes an `InterceptorHook` gRPC service that agent code calls directly
/// from within the same process or over a local connection. Each inbound
/// `InterceptRequest` is converted into a
/// [`RawRequest`](crate::normalizer::RawRequest) and enforced through the
/// [`EnforcementPipeline`]. The resulting
/// [`EnforcementDecision`] is mapped to an `InterceptResponse` returned to the
/// agent.
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct GrpcInterceptor {
    /// Listen address for the gRPC server.
    address: SocketAddr,
    /// Enforcement pipeline shared across all requests.
    pipeline: Option<Arc<EnforcementPipeline>>,
}

impl GrpcInterceptor {
    /// Creates a new [`GrpcInterceptor`] that listens on the specified address.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            pipeline: None,
        }
    }
}

impl From<SocketAddr> for GrpcInterceptor {
    fn from(address: SocketAddr) -> Self {
        Self::new(address)
    }
}

#[tonic::async_trait]
impl InterceptorHook for GrpcInterceptor {
    async fn intercept(
        &self,
        request: tonic::Request<InterceptRequest>,
    ) -> Result<tonic::Response<InterceptResponse>, tonic::Status> {
        let pipeline = self
            .pipeline
            .as_ref()
            .ok_or_else(|| tonic::Status::internal("pipeline not initialized"))?;

        let metadata = request.metadata();
        let metadata_session_id = metadata
            .get("x-firma-session-id")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        let req = request.into_inner();

        // Prefer the proto field; fall back to gRPC metadata.
        let session_id = if req.session_id.is_empty() {
            metadata_session_id.unwrap_or_default()
        } else {
            req.session_id.clone()
        };

        // Fail-closed: reject requests without a resolvable host.
        if req.host.is_empty() {
            return Ok(tonic::Response::new(InterceptResponse {
                allowed: false,
                reason: "MALFORMED_REQUEST: missing host".to_string(),
            }));
        }

        let raw = RawRequest {
            method: req.method,
            host: req.host,
            path: req.path,
            headers: req.headers,
            body: if req.body.is_empty() {
                None
            } else {
                Some(req.body)
            },
            is_https: req.is_https,
        };

        let decision = pipeline.enforce(&raw, &session_id);

        let response = match decision {
            EnforcementDecision::Allow { .. } | EnforcementDecision::Passthrough { .. } => {
                InterceptResponse {
                    allowed: true,
                    reason: String::new(),
                }
            }
            EnforcementDecision::Deny { reason, detail, .. } => InterceptResponse {
                allowed: false,
                reason: format!("{reason}: {detail}"),
            },
        };

        Ok(tonic::Response::new(response))
    }
}

impl Interceptor for GrpcInterceptor {
    async fn run(
        mut self,
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        let address = self.address;
        self.pipeline = Some(pipeline);

        let svc = InterceptorHookServer::new(self);
        Server::builder()
            .add_service(svc)
            .serve_with_shutdown(address, cancel.cancelled())
            .await
            .map_err(|e| InterceptorError::ServerError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use chrono::Utc;
    use firma_core::*;
    use firma_grpc_interceptor_proto::interceptor_hook_client::InterceptorHookClient;

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile};
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, IntentNormalizer,
        MappingTable,
    };

    /// Returns an available localhost address by binding to port 0.
    fn free_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|l| l.local_addr().ok());
        // SAFETY: this is test-only code; binding port 0 always succeeds
        #[allow(clippy::unwrap_used)]
        listener.unwrap()
    }

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<bool, String> {
            Ok(true)
        }
        fn is_fresh(&self) -> bool {
            true
        }
        fn version(&self) -> Option<String> {
            Some("test-v1".to_string())
        }
    }

    struct MockVerifier {
        claims: CapabilityClaims,
    }
    impl TokenVerifier for MockVerifier {
        fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
            Ok(self.claims.clone())
        }
    }

    struct NoRevocations;
    impl RevocationStore for NoRevocations {
        fn is_revoked(&self, _token_id: &str) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &str) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "tok_001".to_string(),
            agent_id: "agent_test".to_string(),
            session_id: String::new(),
            action_set: vec!["llm.inference".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
        }
    }

    fn test_pipeline_allow() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "v4.public.test_token".to_string(),
                claims: claims.clone(),
            }]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(
            normalizer,
            capability_validator,
            constraint_enforcer,
        ))
    }

    fn test_pipeline_deny_all() -> Arc<EnforcementPipeline> {
        // Empty capability map — every classified request fails at token selection
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some("POST".to_string()),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "llm.inference".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            Box::new(NoRevocations),
            Duration::from_secs(0),
        );
        let constraint_enforcer = ConstraintEnforcer::new(Box::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(
            normalizer,
            capability_validator,
            constraint_enforcer,
        ))
    }

    #[tokio::test]
    async fn test_intercept_allows_valid_request() {
        let addr = free_addr();
        let pipeline = test_pipeline_allow();
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        #[allow(clippy::unwrap_used)]
        let client = client.as_mut().unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: "api.openai.com".to_owned(),
                path: "/v1/chat/completions".to_owned(),
                headers,
                body: b"{}".to_vec(),
                is_https: true,
                session_id: String::new(),
            })
            .await;
        #[allow(clippy::unwrap_used)]
        let response = response.unwrap().into_inner();

        assert!(response.allowed);
        assert!(response.reason.is_empty());

        cancel.cancel();
        #[allow(clippy::unwrap_used)]
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_denies_when_no_capability() {
        let addr = free_addr();
        let pipeline = test_pipeline_deny_all();
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        #[allow(clippy::unwrap_used)]
        let client = client.as_mut().unwrap();

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: "api.openai.com".to_owned(),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
                is_https: true,
                session_id: String::new(),
            })
            .await;
        #[allow(clippy::unwrap_used)]
        let response = response.unwrap().into_inner();

        assert!(!response.allowed);
        assert!(!response.reason.is_empty());

        cancel.cancel();
        #[allow(clippy::unwrap_used)]
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_empty_body_becomes_none() {
        let addr = free_addr();
        let pipeline = test_pipeline_allow();
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        #[allow(clippy::unwrap_used)]
        let client = client.as_mut().unwrap();

        // POST to a mapped endpoint with empty body — should still allow
        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: "api.openai.com".to_owned(),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
                is_https: true,
                session_id: String::new(),
            })
            .await;
        #[allow(clippy::unwrap_used)]
        let response = response.unwrap().into_inner();

        assert!(response.allowed);

        cancel.cancel();
        #[allow(clippy::unwrap_used)]
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_denies_malformed_request_missing_host() {
        let addr = free_addr();
        let pipeline = test_pipeline_allow();
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(pipeline, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        #[allow(clippy::unwrap_used)]
        let client = client.as_mut().unwrap();

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: String::new(),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
                is_https: true,
                session_id: String::new(),
            })
            .await;
        #[allow(clippy::unwrap_used)]
        let response = response.unwrap().into_inner();

        assert!(!response.allowed);
        assert!(response.reason.contains("MALFORMED_REQUEST"));

        cancel.cancel();
        #[allow(clippy::unwrap_used)]
        server_handle.await.unwrap().unwrap();
    }
}
