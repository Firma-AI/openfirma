#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use chrono::Utc;
use firma_core::{
    AgentId, SessionId, TokenId,
    decision::DenyReason,
    token::{CapabilityClaims, RevocationStore, TokenError, TokenVerifier},
};
use firma_sidecar::pipeline::{
    ActionClassRegistry, CapabilityEntry, CapabilityMap, CapabilityValidator, CedarEvaluatorError,
    ConstraintEnforcer, EnforcementDecision, EnforcementPipeline, MappingRuleConfig,
    MappingRulesFile, MappingTable, PolicyEvaluation, RawRequest,
};
use std::{collections::HashMap, sync::Arc, thread, time::Duration};
use std::{
    collections::HashSet,
    sync::{
        RwLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::watch;

struct AllowAllPolicy;
impl PolicyEvaluation for AllowAllPolicy {
    fn evaluate(
        &self,
        _: &AgentId,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
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
    fn evaluate(
        &self,
        _: &AgentId,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn is_available(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        None
    }
}

struct SlowPolicy;
impl PolicyEvaluation for SlowPolicy {
    fn evaluate(
        &self,
        _: &AgentId,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
        thread::sleep(Duration::from_millis(200));
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        Some("slow-policy-v1".to_string())
    }
}

struct StalePolicy;
impl PolicyEvaluation for StalePolicy {
    fn evaluate(
        &self,
        _: &AgentId,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        false
    }

    fn version(&self) -> Option<String> {
        Some("stale-policy-v1".to_string())
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

#[derive(Debug, Clone)]
struct SharedPolicySet {
    version: u64,
    allow: bool,
}

#[derive(Debug)]
struct SharedPolicyState {
    available: AtomicBool,
    fresh: AtomicBool,
    policy_set: RwLock<SharedPolicySet>,
}

struct SharedPolicyEvaluator {
    state: Arc<SharedPolicyState>,
    session_counters: Arc<RwLock<HashMap<AgentId, u64>>>,
}

impl PolicyEvaluation for SharedPolicyEvaluator {
    fn evaluate(
        &self,
        principal: &AgentId,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
        {
            let mut counters = self
                .session_counters
                .write()
                .unwrap_or_else(|_| panic!("session counter lock poisoned"));
            let next = counters.get(principal).copied().unwrap_or(0) + 1;
            counters.insert(principal.clone(), next);
        }

        let allow = self
            .state
            .policy_set
            .read()
            .unwrap_or_else(|_| panic!("policy set lock poisoned"))
            .allow;

        Ok(allow)
    }

    fn is_fresh(&self) -> bool {
        self.state.fresh.load(Ordering::SeqCst)
    }

    fn is_available(&self) -> bool {
        self.state.available.load(Ordering::SeqCst)
    }

    fn version(&self) -> Option<String> {
        let version = self
            .state
            .policy_set
            .read()
            .unwrap_or_else(|_| panic!("policy set lock poisoned"))
            .version;
        Some(format!("shared-v{version}"))
    }
}

#[derive(Clone)]
struct SharedRevocationStore {
    revoked: Arc<RwLock<HashSet<TokenId>>>,
}

impl RevocationStore for SharedRevocationStore {
    fn is_revoked(&self, token_id: &TokenId) -> Result<bool, TokenError> {
        let revoked = self
            .revoked
            .read()
            .unwrap_or_else(|_| panic!("revocation lock poisoned"));
        Ok(revoked.contains(token_id))
    }

    fn add_revocation(&self, token_id: &TokenId) -> Result<(), TokenError> {
        let mut revoked = self
            .revoked
            .write()
            .unwrap_or_else(|_| panic!("revocation lock poisoned"));
        revoked.insert(*token_id);
        Ok(())
    }
}

fn test_claims() -> CapabilityClaims {
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap_or_else(|_| panic!("failed to build fixed issued_at timestamp"))
        .with_timezone(&Utc);
    CapabilityClaims {
        token_id: TokenId::new(),
        agent_id: "agent_stress".parse().unwrap(),
        session_id: "sess_stress".parse().unwrap(),
        action_set: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        issued_at,
        expiry: issued_at + chrono::Duration::hours(1),
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
            action_class: "communication.external.send".to_string(),
        }],
    };

    MappingTable::from_config(&file, &registry, true).unwrap_or_else(|e| panic!("{e}"))
}

fn build_pipeline(
    policy: Box<dyn PolicyEvaluation>,
    stage2_timeout: Duration,
) -> EnforcementPipeline {
    build_pipeline_with_revocation(policy, stage2_timeout, Box::new(NoRevocations))
}

fn build_pipeline_with_revocation(
    policy: Box<dyn PolicyEvaluation>,
    stage2_timeout: Duration,
    revocation: Box<dyn RevocationStore + Send + Sync>,
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
        revocation,
    );

    let (_, rx) = watch::channel(Arc::from(policy) as Arc<dyn PolicyEvaluation>);
    EnforcementPipeline::with_stage2_timeout(
        firma_sidecar::pipeline::IntentNormalizer::new(test_mapping_table()),
        stage1,
        ConstraintEnforcer::new(rx),
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
                .enforce_async(&protected_request(), "sess_stress".parse().unwrap())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stage2_timeout_denies_with_enforcement_timeout() {
    let pipeline = build_pipeline(Box::new(SlowPolicy), Duration::from_millis(20));
    let request = protected_request();

    let decision = pipeline
        .enforce_async(&request, "sess_stress".parse().unwrap())
        .await;
    assert!(decision.is_deny());
    assert_eq!(decision.deny_reason(), Some(DenyReason::EnforcementTimeout));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_unavailable_denies_fail_closed() {
    let pipeline = build_pipeline(Box::new(PolicyUnavailable), Duration::from_millis(50));

    let decision = pipeline
        .enforce_async(&protected_request(), "sess_stress".parse().unwrap())
        .await;

    assert!(decision.is_deny());
    assert_eq!(decision.deny_reason(), Some(DenyReason::FailClosed));
    assert!(!matches!(decision, EnforcementDecision::Passthrough { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_stale_denies_policy_bundle_stale() {
    let pipeline = build_pipeline(Box::new(StalePolicy), Duration::from_millis(50));

    let decision = pipeline
        .enforce_async(&protected_request(), "sess_stress".parse().unwrap())
        .await;

    assert!(decision.is_deny());
    assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyBundleStale));
    assert!(!matches!(decision, EnforcementDecision::Passthrough { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_shared_state_mutation_produces_only_valid_decisions() {
    let state = Arc::new(SharedPolicyState {
        available: AtomicBool::new(true),
        fresh: AtomicBool::new(true),
        policy_set: RwLock::new(SharedPolicySet {
            version: 1,
            allow: true,
        }),
    });
    let session_counters = Arc::new(RwLock::new(HashMap::new()));
    let revocations = Arc::new(RwLock::new(HashSet::new()));

    let evaluator = SharedPolicyEvaluator {
        state: Arc::clone(&state),
        session_counters: Arc::clone(&session_counters),
    };
    let pipeline = Arc::new(build_pipeline_with_revocation(
        Box::new(evaluator),
        Duration::from_millis(50),
        Box::new(SharedRevocationStore {
            revoked: Arc::clone(&revocations),
        }),
    ));

    let state_writer = Arc::clone(&state);
    let revocation_writer = Arc::clone(&revocations);
    let mutator = tokio::spawn(async move {
        let token = TokenId::new();
        for i in 0..400 {
            state_writer.available.store(i % 7 != 0, Ordering::SeqCst);
            state_writer.fresh.store(i % 5 != 0, Ordering::SeqCst);

            {
                let mut policy = state_writer
                    .policy_set
                    .write()
                    .unwrap_or_else(|_| panic!("policy set lock poisoned"));
                policy.version += 1;
                policy.allow = i % 11 != 0;
            }

            {
                let mut revoked = revocation_writer
                    .write()
                    .unwrap_or_else(|_| panic!("revocation lock poisoned"));
                if i % 13 == 0 {
                    revoked.insert(token);
                } else {
                    revoked.remove(&token);
                }
            }

            tokio::task::yield_now().await;
        }
    });

    let mut tasks = Vec::with_capacity(100);
    for _ in 0..100 {
        let pipeline = Arc::clone(&pipeline);
        tasks.push(tokio::spawn(async move {
            let session_id: SessionId = "ses_stress".parse().unwrap();
            pipeline
                .enforce_async(&protected_request(), session_id)
                .await
        }));
    }

    let mut saw_shared_state_deny = false;
    for task in tasks {
        let decision = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("task timed out")
            .expect("task panicked");

        assert!(
            !decision.is_passthrough(),
            "protected traffic must never bypass enforcement"
        );

        match decision {
            EnforcementDecision::Allow { .. } => {}
            EnforcementDecision::Deny { reason, .. } => {
                let allowed = matches!(
                    reason,
                    DenyReason::FailClosed
                        | DenyReason::PolicyBundleStale
                        | DenyReason::PolicyDenied
                        | DenyReason::TokenRevoked
                        | DenyReason::EnforcementTimeout
                        | DenyReason::UnclassifiedIntent
                );
                assert!(allowed, "unexpected deny reason under shared-state stress");
                saw_shared_state_deny = true;
            }
            EnforcementDecision::Passthrough { .. } => {
                panic!("protected traffic must not bypass enforcement")
            }
        }
    }

    mutator.await.expect("mutator panicked");

    assert!(
        saw_shared_state_deny,
        "shared state stress should exercise at least one deny path"
    );
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
            let session_id: SessionId = "session".parse().unwrap();
            for _ in 0..50 {
                let decision = pipeline.enforce(&protected_request(), session_id.clone());
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
