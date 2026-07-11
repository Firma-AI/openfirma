//! gRPC hook interceptor.
//!
//! Implements the [`Interceptor`] trait as a Tonic gRPC
//! server. The agent process registers this interceptor programmatically and
//! calls the `Intercept` RPC for every outbound action — no port binding or
//! proxy environment variable is required.
//!
//! The service converts each `InterceptRequest` proto message into a
//! [`RawRequest`], passes it to the shared
//! [`RequestHandler`], and returns an
//! `InterceptResponse` with the ALLOW / DENY result.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use firma_http::{HeaderName, Method};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;

use crate::handler::{HandledResponse, RequestHandler};
use crate::interceptor::{Interceptor, InterceptorError};
use crate::pipeline::RawRequest;
use firma_grpc_interceptor_proto::interceptor_hook_server::{
    InterceptorHook, InterceptorHookServer,
};
use firma_grpc_interceptor_proto::{InterceptRequest, InterceptResponse};

/// Tonic-based gRPC hook interceptor.
///
/// Exposes an `InterceptorHook` gRPC service that agent code calls directly
/// from within the same process or over a local connection. Each inbound
/// `InterceptRequest` is converted into a
/// [`RawRequest`] and handled through the
/// [`RequestHandler`]. The resulting
/// [`HandledResponse`] is mapped to an
/// `InterceptResponse` returned to the
/// agent.
///
/// Malformed requests that cannot be parsed into a valid `RawRequest` are
/// rejected with a structured DENY carrying reason `MALFORMED_REQUEST`
/// (fail-closed).
pub struct GrpcInterceptor {
    /// Listen address for the gRPC server.
    address: SocketAddr,
    /// Request handler shared across all requests.
    handler: Option<Arc<RequestHandler>>,
}

impl GrpcInterceptor {
    /// Creates a new [`GrpcInterceptor`] that listens on the specified address.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            handler: None,
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
        let handler = self
            .handler
            .as_ref()
            .ok_or_else(|| tonic::Status::internal("request handler not initialized"))?;

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
            method: Method(http::Method::from_str(&req.method).map_err(|err| {
                tonic::Status::invalid_argument(format!("Invalid method {}: {err}", req.method))
            })?),
            host: req.host,
            path: req.path,
            headers: req
                .headers
                .into_iter()
                .map(|(k, v)| {
                    HeaderName::from_str(&k).map(|k| (k, v)).map_err(|err| {
                        tonic::Status::invalid_argument(format!("Invalid header {k}: {err}"))
                    })
                })
                .collect::<Result<_, _>>()?,
            body: if req.body.is_empty() {
                None
            } else {
                Some(req.body)
            },
            is_https: req.is_https,
        };

        let outcome = handler.handle(raw, &session_id).await;

        let response = match outcome {
            HandledResponse::Ok(_) | HandledResponse::Passthrough(_) => InterceptResponse {
                allowed: true,
                reason: String::new(),
            },
            HandledResponse::Deny {
                reason,
                detail,
                context: _,
            } => InterceptResponse {
                // V1: gRPC hook reports denial as a reason string
                // regardless of DenialContext. The context field exists
                // for future tool-call transports.
                allowed: false,
                reason: format!("{reason}: {detail}"),
            },
            HandledResponse::Aborted { reason, detail } => InterceptResponse {
                allowed: false,
                reason: format!("ABORT:{}: {detail}", reason.code()),
            },
        };

        Ok(tonic::Response::new(response))
    }
}

impl Interceptor for GrpcInterceptor {
    async fn run(
        mut self,
        handler: Arc<RequestHandler>,
        cancel: CancellationToken,
    ) -> Result<(), InterceptorError> {
        let address = self.address;
        self.handler = Some(handler);

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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::config::{MappingRuleConfig, MappingRulesFile, TenancyMode};
    use crate::credential::NullCredentialInjector;
    use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;
    use crate::pipeline::{
        ActionClassRegistry, CapabilityValidator, ConstraintEnforcer, EnforcementPipeline,
        IntentNormalizer, MappingTable, PipelineArgs,
    };

    /// Returns an available localhost address by binding to port 0.
    fn free_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|l| l.local_addr().ok());
        // SAFETY: this is test-only code; binding port 0 always succeeds
        listener.unwrap()
    }

    struct AllowAllPolicy;
    impl PolicyEvaluation for AllowAllPolicy {
        fn evaluate(
            &self,
            _: &AgentId,
            _: &str,
            _: &str,
            _: serde_json::Value,
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
        fn is_revoked(&self, _token_id: &TokenId) -> Result<bool, TokenError> {
            Ok(false)
        }
        fn add_revocation(&self, _token_id: &TokenId) -> Result<(), TokenError> {
            Ok(())
        }
    }

    fn test_claims() -> CapabilityClaims {
        CapabilityClaims {
            token_id: "3713c5fc-b569-650c-c780-c64051473370"
                .parse()
                .expect("literal token id"),
            agent_id: "agent_test".parse().expect("literal agent id"),
            session_id: "_test_".parse().expect("literal session id"),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "*".to_string(),
            issued_at: Utc::now(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            context_hash: String::new(),
            budget_ceiling: None,
        }
    }

    fn test_pipeline_allow() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
                host: "*".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
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
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    fn test_handler(pipeline: Arc<EnforcementPipeline>) -> Arc<RequestHandler> {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        Arc::new(RequestHandler::new(
            pipeline,
            crate::handler::tests::test_connector_registry(),
            tx,
        ))
    }

    async fn mock_upstream() -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok();
        let listener = listener.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((mut stream, _)) = accepted {
                            let mut buf = vec![0u8; 4096];
                            let _ = stream.read(&mut buf).await;
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                    }
                    () = cancel_clone.cancelled() => break,
                }
            }
        });

        (addr, cancel)
    }

    fn test_pipeline_deny_all() -> Arc<EnforcementPipeline> {
        // Empty capability map — every classified request fails at token selection
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
                host: "api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
            }],
        };
        let table =
            MappingTable::from_config(&rules, &registry, true).unwrap_or_else(|e| panic!("{e}"));

        let normalizer = IntentNormalizer::new(table);
        let capability_validator = CapabilityValidator::new(
            CapabilityMap::new(vec![]),
            Box::new(MockVerifier { claims }),
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(NullCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    struct FailingCredentialInjector;

    #[async_trait::async_trait]
    impl crate::credential::CredentialInjector for FailingCredentialInjector {
        async fn inject(
            &self,
            _envelope: &ExecutionEnvelope,
            connector_id: &str,
            _target: &str,
        ) -> Result<InjectedCredentials, crate::credential::CredentialInjectionError> {
            Err(crate::credential::CredentialInjectionError::FetchFailed {
                connector_id: connector_id.to_string(),
                reason: "vault unavailable".to_string(),
            })
        }
    }

    /// Builds an ALLOW pipeline whose credential injection always fails,
    /// so `enforce()` returns ABORT after the call is authorized.
    fn test_pipeline_abort() -> Arc<EnforcementPipeline> {
        let claims = test_claims();
        let registry = ActionClassRegistry::v0_1();
        let rules = MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::POST),
                host: "*".to_string(),
                path: Some("/v1/chat/completions".to_string()),
                action_class: "communication.external.send".to_string(),
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
            std::sync::Arc::new(NoRevocations),
            Duration::from_secs(0),
            TenancyMode::SingleAgent,
        );
        let constraint_enforcer = ConstraintEnforcer::new(std::sync::Arc::new(AllowAllPolicy));

        Arc::new(EnforcementPipeline::new(PipelineArgs {
            normalizer,
            capability_validator,
            constraint_enforcer,
            credential_injector: Box::new(FailingCredentialInjector),
            session_state_store: std::sync::Arc::new(
                crate::enforcement::LruSessionStateStore::new(16),
            ),
        }))
    }

    #[tokio::test]
    async fn test_intercept_aborts_reports_abort_reason() {
        let addr = free_addr();
        let handler = test_handler(test_pipeline_abort());
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        let client = client.as_mut().unwrap();

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: "api.openai.com".to_owned(),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: b"{}".to_vec(),
                is_https: true,
                session_id: "_test_".parse().expect("literal session id"),
            })
            .await;
        let response = response.unwrap().into_inner();

        assert!(!response.allowed, "abort must not allow the call");
        assert!(
            response
                .reason
                .starts_with("ABORT:CREDENTIAL_INJECTION_FAILED"),
            "gRPC abort reason should carry the ABORT: prefix and code, got {:?}",
            response.reason
        );

        cancel.cancel();
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_allows_valid_request() {
        let addr = free_addr();
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_allow());
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        let client = client.as_mut().unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: format!("127.0.0.1:{}", upstream_addr.port()),
                path: "/v1/chat/completions".to_owned(),
                headers,
                body: b"{}".to_vec(),
                is_https: false,
                session_id: "_test_".parse().expect("literal session id"),
            })
            .await;
        let response = response.unwrap().into_inner();

        assert!(response.allowed);
        assert!(response.reason.is_empty());

        cancel.cancel();
        upstream_cancel.cancel();
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_denies_when_no_capability() {
        let addr = free_addr();
        let handler = test_handler(test_pipeline_deny_all());
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        let client = client.as_mut().unwrap();

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: "api.openai.com".to_owned(),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
                is_https: true,
                session_id: "_test_".parse().expect("literal session id"),
            })
            .await;
        let response = response.unwrap().into_inner();

        assert!(!response.allowed);
        assert!(!response.reason.is_empty());

        cancel.cancel();
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_empty_body_becomes_none() {
        let addr = free_addr();
        let (upstream_addr, upstream_cancel) = mock_upstream().await;
        let handler = test_handler(test_pipeline_allow());
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        let client = client.as_mut().unwrap();

        // POST to a mapped endpoint with empty body — should still allow
        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: format!("127.0.0.1:{}", upstream_addr.port()),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
                is_https: false,
                session_id: "_test_".parse().expect("literal session id"),
            })
            .await;
        let response = response.unwrap().into_inner();

        assert!(response.allowed);

        cancel.cancel();
        upstream_cancel.cancel();
        server_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_intercept_denies_malformed_request_missing_host() {
        let addr = free_addr();
        let handler = test_handler(test_pipeline_allow());
        let cancel = CancellationToken::new();

        let interceptor = GrpcInterceptor::new(addr);
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { interceptor.run(handler, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = InterceptorHookClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| format!("connect failed: {e}"));
        let client = client.as_mut().unwrap();

        let response = client
            .intercept(InterceptRequest {
                method: "POST".to_owned(),
                host: String::new(),
                path: "/v1/chat/completions".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
                is_https: true,
                session_id: "_test_".parse().expect("literal session id"),
            })
            .await;
        let response = response.unwrap().into_inner();

        assert!(!response.allowed);
        assert!(response.reason.contains("MALFORMED_REQUEST"));

        cancel.cancel();
        server_handle.await.unwrap().unwrap();
    }
}
