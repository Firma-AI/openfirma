use chrono::Utc;
use firma_core::{
    decision::DenyReason,
    token::{CapabilityClaims, RevocationStore, TokenError, TokenVerifier},
};
use firma_sidecar::pipeline::{
    ActionClassRegistry, CapabilityEntry, CapabilityMap, CapabilityValidator, ConstraintEnforcer,
    EnforcementDecision, EnforcementPipeline, MappingRuleConfig, MappingRulesFile, MappingTable,
    PolicyEvaluation, RawRequest,
};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, thread, time::Duration};

struct AllowAllPolicy;
impl PolicyEvaluation for AllowAllPolicy {
    fn evaluate(&self, _: &str, _: &str, _: &str, _: &serde_json::Value) -> Result<bool, String> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        Some("stress-test-v1".to_string())
    }
}

struct PolicyUnavailable;
impl PolicyEvaluation for PolicyUnavailable {
    fn evaluate(&self, _: &str, _: &str, _: &str, _: &serde_json::Value) -> Result<bool, String> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        None
    }
}

struct SlowPolicy;
impl PolicyEvaluation for SlowPolicy {
    fn evaluate(&self, _: &str, _: &str, _: &str, _: &serde_json::Value) -> Result<bool, String> {
        Ok(true)
    }

    fn evaluate_async<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(true)
        })
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        Some("slow-policy-v1".to_string())
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
        token_id: "tok_stress_001".to_string(),
        agent_id: "agent_stress".to_string(),
        session_id: "sess_stress".to_string(),
        action_set: vec!["llm.inference".to_string()],
        resource_scope: "*".to_string(),
        issued_at: Utc::now(),
        expiry: Utc::now() + chrono::Duration::hours(1),
        context_hash: String::new(),
    }
}

fn test_mapping_table() -> MappingTable {
    let registry = ActionClassRegistry::v0_1();
    let file = MappingRulesFile {
        rules: vec![MappingRuleConfig {
            method: Some("POST".to_string()),
            host: "api.openai.com".to_string(),
            path: Some("/v1/chat/completions".to_string()),
            action_class: "llm.inference".to_string(),
        }],
    };

    MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"))
}

fn build_pipeline(
    policy: Box<dyn PolicyEvaluation>,
    stage2_timeout: Duration,
) -> EnforcementPipeline {
    let claims = test_claims();
    let stage1 = CapabilityValidator::new(
        CapabilityMap::new(vec![
            CapabilityEntry::from_raw_token(
                "v4.public.stress",
                &MockVerifier {
                    claims: claims.clone(),
                },
            )
            .unwrap_or_else(|e| panic!("{e}")),
        ]),
        Box::new(MockVerifier { claims }),
        Box::new(NoRevocations),
    );

    EnforcementPipeline::with_stage2_timeout(
        firma_sidecar::pipeline::IntentNormalizer::new(test_mapping_table()),
        stage1,
        ConstraintEnforcer::new(policy),
        stage2_timeout,
    )
}

fn protected_request() -> RawRequest {
    RawRequest {
        method: "POST".to_string(),
        host: "api.openai.com".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: HashMap::new(),
        body: None,
        is_https: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_100_concurrent_requests_no_passthrough() {
    let pipeline = Arc::new(build_pipeline(
        Box::new(AllowAllPolicy),
        Duration::from_millis(50),
    ));

    let mut tasks = Vec::with_capacity(100);
    for _ in 0..100 {
        let pipeline = Arc::clone(&pipeline);
        tasks.push(tokio::spawn(async move {
            pipeline
                .enforce_async(&protected_request(), "sess_stress")
                .await
        }));
    }

    for task in tasks {
        let decision = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("task timed out")
            .expect("task panicked");

        assert!(
            !decision.is_passthrough(),
            "protected traffic must never bypass enforcement"
        );
        assert!(
            decision.is_allow(),
            "expected allow under healthy policy evaluator"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn stage2_timeout_denies_with_enforcement_timeout() {
    let pipeline = build_pipeline(Box::new(SlowPolicy), Duration::from_secs(2));
    let request = protected_request();

    let decision_future = pipeline.enforce_async(&request, "sess_stress");
    tokio::pin!(decision_future);

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(3)).await;

    let decision = decision_future.await;
    assert!(decision.is_deny());
    assert_eq!(decision.deny_reason(), Some(DenyReason::EnforcementTimeout));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_unavailable_denies_policy_bundle_stale() {
    let pipeline = build_pipeline(Box::new(PolicyUnavailable), Duration::from_millis(50));

    let decision = pipeline
        .enforce_async(&protected_request(), "sess_stress")
        .await;

    assert!(decision.is_deny());
    assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    assert!(!matches!(decision, EnforcementDecision::Passthrough { .. }));
}

#[test]
fn threaded_reads_do_not_panic_or_passthrough() {
    let pipeline = Arc::new(build_pipeline(
        Box::new(AllowAllPolicy),
        Duration::from_millis(50),
    ));

    let mut workers = Vec::new();
    for _ in 0..16 {
        let pipeline = Arc::clone(&pipeline);
        workers.push(thread::spawn(move || {
            for _ in 0..50 {
                let decision = pipeline.enforce(&protected_request(), "sess_stress");
                assert!(
                    decision.is_allow(),
                    "expected allow in read-only threaded path"
                );
                assert!(
                    !decision.is_passthrough(),
                    "protected traffic must not bypass enforcement"
                );
            }
        }));
    }

    for worker in workers {
        worker.join().unwrap_or_else(|_| panic!("worker panicked"));
    }
}
