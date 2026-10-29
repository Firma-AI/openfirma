#![allow(clippy::expect_used, reason = "test fixture locks and live handles")]

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use firma_core::{CapabilityClaims, DenyReason, RevocationStore, TokenError, TokenVerifier};
use firma_http::{Authority, HeaderMap, Method};
use firma_identifiers::{AgentId, TokenId};
use firma_sidecar::audit::{AuditPayload, ExecutionEvent};
use firma_sidecar::authority_client::swappable_policy::{
    RuntimeSnapshot, SwappablePolicyEvaluation,
};
use firma_sidecar::authority_tls::AuthorityTls;
use firma_sidecar::composio::{ComposioAction, ComposioCatalogs, DecodeResult, decode};
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::credential::{
    CredentialInjectionError, CredentialInjector, NullCredentialInjector,
};
use firma_sidecar::enforcement::LruSessionStateStore;
use firma_sidecar::enforcement::capability_map::CapabilityEntry;
use firma_sidecar::pipeline::{
    ActionClassRegistry, CapabilityMap, CapabilityValidator, CompositeDisposition,
    ConstraintEnforcer, EnforcementDecision, EnforcementPipeline, IntentNormalizer, MappingTable,
    PipelineArgs, PolicyEvaluation, RawRequest,
};
use firma_sidecar::startup::{load_audit_event_builder, spawn_audit_sink};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use tokio_util::sync::CancellationToken;

type Hook = Mutex<Option<Box<dyn FnOnce() + Send>>>;

struct ActionPolicy {
    action: &'static str,
    hook: Hook,
}

impl PolicyEvaluation for ActionPolicy {
    fn evaluate(
        &self,
        _: &AgentId,
        action: &str,
        _: &str,
        _: serde_json::Value,
    ) -> Result<bool, String> {
        let callback = self.hook.lock().expect("hook lock").take();
        if let Some(callback) = callback {
            callback();
        }
        Ok(action == self.action)
    }

    fn is_fresh(&self) -> bool {
        false // The published snapshot, not this inner clock, owns freshness.
    }

    fn version(&self) -> Option<String> {
        Some("inner-version".to_string())
    }
}

struct Verifier {
    claims: CapabilityClaims,
    hook: Hook,
}

impl TokenVerifier for Verifier {
    fn verify(&self, _: &str) -> Result<CapabilityClaims, TokenError> {
        let callback = self.hook.lock().expect("hook lock").take();
        if let Some(callback) = callback {
            callback();
        }
        Ok(self.claims.clone())
    }
}

struct NoRevocations;

impl RevocationStore for NoRevocations {
    fn is_revoked(&self, _: &TokenId) -> Result<bool, TokenError> {
        Ok(false)
    }

    fn add_revocation(&self, _: &TokenId) -> Result<(), TokenError> {
        Ok(())
    }
}

fn policy(action: &'static str) -> Arc<ActionPolicy> {
    Arc::new(ActionPolicy {
        action,
        hook: Mutex::new(None),
    })
}

/// Every snapshot also classifies the Composio transport, as the shipped
/// Composio mapping does, so catalog-classified requests pass admission.
fn normalizer(action: &str) -> anyhow::Result<IntentNormalizer> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![
                MappingRuleConfig {
                    method: None,
                    host: "example.test".to_string(),
                    path: None,
                    action_class: action.to_string(),
                },
                MappingRuleConfig {
                    method: Some(firma_http::Method::POST),
                    host: "app.composio.dev".to_string(),
                    path: Some("/tool_router/v3/*/mcp".to_string()),
                    action_class: "communication.external.send".to_string(),
                },
            ],
        },
        &ActionClassRegistry::v0_1(),
    )?;
    Ok(IntentNormalizer::new(table))
}

fn snapshot(action: &'static str, version: &str, ttl: u32) -> anyhow::Result<RuntimeSnapshot> {
    Ok(RuntimeSnapshot::new(
        normalizer(action)?,
        policy(action),
        ttl,
        Some(version.to_string()),
    ))
}

fn pipeline(
    handle: &Arc<SwappablePolicyEvaluation>,
    hook: Option<Box<dyn FnOnce() + Send>>,
) -> anyhow::Result<EnforcementPipeline> {
    pipeline_with_injector(handle, hook, Box::new(NullCredentialInjector))
}

fn pipeline_with_injector(
    handle: &Arc<SwappablePolicyEvaluation>,
    hook: Option<Box<dyn FnOnce() + Send>>,
    injector: Box<dyn CredentialInjector>,
) -> anyhow::Result<EnforcementPipeline> {
    let claims = CapabilityClaims {
        token_id: "ctok_01j0000000e008000000000001".parse()?,
        agent_id: "agt_01j0000000e008000000000001".parse()?,
        session_id: "session".parse()?,
        action_set: vec![
            "code.read".to_string(),
            "code.write".to_string(),
            "communication.external.read".to_string(),
        ],
        resource_scope: "*".to_string(),
        issued_at: Utc::now(),
        expiry: Utc::now() + chrono::Duration::hours(1),
        context_hash: String::new(),
    };
    Ok(EnforcementPipeline::new(PipelineArgs {
        normalizer: normalizer("filesystem.read")?,
        capability_validator: CapabilityValidator::new(
            CapabilityMap::new(vec![CapabilityEntry {
                raw_token: "test-token".to_string(),
                claims: claims.clone(),
            }]),
            Arc::new(Verifier {
                claims,
                hook: Mutex::new(hook),
            }),
            Arc::new(NoRevocations),
        ),
        constraint_enforcer: ConstraintEnforcer::new(policy("filesystem.read")),
        credential_injector: injector,
        session_state_store: Arc::new(LruSessionStateStore::new(
            const { NonZeroUsize::new(16).unwrap() },
        )),
    })
    .with_runtime_snapshot(Arc::clone(handle)))
}

fn request() -> RawRequest {
    RawRequest {
        method: Method::GET,
        host: Authority::from_static("example.test"),
        path: "/resource".to_string(),
        headers: HeaderMap::new(),
        body: None,
        is_https: true,
    }
}

async fn emitted(payloads: Vec<AuditPayload>) -> anyhow::Result<Vec<ExecutionEvent>> {
    let directory = tempfile::tempdir()?;
    let key_path = directory.path().join("key.pem");
    let key = p256::SecretKey::from_slice(&[1; 32])?;
    std::fs::write(&key_path, key.to_pkcs8_pem(LineEnding::LF)?.as_bytes())?;
    let log_path = directory.path().join("audit.jsonl");
    let audit = firma_config_schema::sidecar::audit::AuditConfig {
        sink: firma_config_schema::sidecar::AuditSink::File,
        file_path: Some(log_path.clone()),
        signing_key_path: Some(key_path),
        ..Default::default()
    };
    let section = toml::to_string(&toml::Table::from_iter([(
        "audit".to_string(),
        toml::Value::try_from(&audit)?,
    )]))?;
    let mut schema: firma_config_schema::sidecar::SidecarConfig = toml::from_str(&section)?;
    schema.authority.url = Some("http://127.0.0.1:50051".to_string());
    let config = firma_sidecar::config::SidecarConfig::resolve(
        schema,
        &firma_runtime_state::RuntimeLayout::from_root(directory.path()),
    )
    .map_err(anyhow::Error::msg)?;
    let builder = load_audit_event_builder(&config.audit)?;
    let count = payloads.len();
    let (sender, receiver) = tokio::sync::mpsc::channel(payloads.len().max(1));
    let exit = CancellationToken::new();
    let task = spawn_audit_sink(
        &config,
        &AuthorityTls::read(&config.authority)?,
        receiver,
        builder,
        exit.clone(),
    )?;
    for payload in payloads {
        sender.send(payload).await?;
    }
    drop(sender);
    let events = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let content = tokio::fs::read_to_string(&log_path).await?;
            if content.ends_with('\n') && content.lines().count() == count {
                return content
                    .lines()
                    .map(|line| serde_json::from_str(line).map_err(anyhow::Error::from))
                    .collect::<anyhow::Result<Vec<ExecutionEvent>>>();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    exit.cancel();
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    Ok(events)
}

#[tokio::test]
async fn swap_during_validation_keeps_mapping_policy_and_audit_on_one_generation()
-> anyhow::Result<()> {
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(snapshot(
        "code.read",
        "1",
        60,
    )?));
    let replacement = snapshot("code.write", "2", 60)?;
    let writer = Arc::clone(&handle);
    let pipeline = pipeline(
        &handle,
        Some(Box::new(move || writer.swap_snapshot(replacement))),
    )?;

    let (decision, audit) = pipeline.enforce(&request(), "session").await;
    std::assert_matches!(decision, EnforcementDecision::Allow { envelope, .. } if envelope.intent().action_class == "code.read");
    let mut payloads = vec![audit];

    let (decision, audit) = pipeline.enforce(&request(), "session").await;
    std::assert_matches!(decision, EnforcementDecision::Allow { envelope, .. } if envelope.intent().action_class == "code.write");
    payloads.push(audit);
    let events = emitted(payloads).await?;
    assert_eq!(
        events
            .iter()
            .map(|event| (event.action.as_str(), event.bundle_version.as_str()))
            .collect::<Vec<_>>(),
        [("code.read", "1"), ("code.write", "2")]
    );

    let mut unmatched = request();
    unmatched.host = Authority::from_static("unmatched.test");
    let (decision, _) = pipeline.enforce(&unmatched, "session").await;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            ..
        }
    );
    Ok(())
}

fn composite() -> anyhow::Result<(RawRequest, Vec<ComposioAction>)> {
    let mut request = request();
    request.method = Method::POST;
    request.host = Authority::from_static("app.composio.dev");
    request.path = "/tool_router/v3/trs_batch/mcp".to_string();
    request.body = Some(serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "COMPOSIO_MULTI_EXECUTE_TOOL", "arguments": {"tools": [
            {"tool_slug": "GMAIL_FETCH_EMAILS", "arguments": {}},
            {"tool_slug": "GMAIL_FETCH_EMAILS", "arguments": {}}
        ]}}
    }))?);
    let catalogs = ComposioCatalogs::from_json_pairs([(
        r#"{"toolkit":"gmail","version":"1","tools":[{"toolkit":"gmail","version":"1","slug":"GMAIL_FETCH_EMAILS","name":"Read","description":"Read"}]}"#,
        r#"{"toolkit":"gmail","version":"1","mappings":{"GMAIL_FETCH_EMAILS":"communication.external.read"}}"#,
    )])?;
    let DecodeResult::Actions(actions) = decode(&request, &catalogs) else {
        anyhow::bail!("expected composite actions");
    };
    Ok((request, actions))
}

#[tokio::test]
async fn composite_children_keep_the_pin_when_first_child_publishes_a_replacement()
-> anyhow::Result<()> {
    let old_policy = policy("communication.external.read");
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(
        RuntimeSnapshot::new(
            normalizer("code.read")?,
            old_policy.clone(),
            60,
            Some("1".to_string()),
        ),
    ));
    let replacement = snapshot("code.write", "2", 60)?;
    let writer = Arc::downgrade(&handle);
    *old_policy.hook.lock().expect("hook lock") = Some(Box::new(move || {
        writer
            .upgrade()
            .expect("live handle")
            .swap_snapshot(replacement);
    }));
    let pipeline = pipeline(&handle, None)?;
    let (request, actions) = composite()?;
    let result = pipeline
        .enforce_composite(&request, "session", &actions)
        .await;
    std::assert_matches!(result.disposition, CompositeDisposition::Dispatch { .. });
    assert_eq!(result.children.len(), 2);
    for child in &result.children {
        std::assert_matches!(child.decision, EnforcementDecision::Allow { .. });
    }
    let events = emitted(
        result
            .children
            .into_iter()
            .map(|child| child.audit_payload)
            .collect(),
    )
    .await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        ["1", "1"]
    );
    let result = pipeline
        .enforce_composite(&request, "session", &actions)
        .await;
    std::assert_matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 0 }
    );
    for child in &result.children {
        std::assert_matches!(
            child.decision,
            EnforcementDecision::Deny {
                reason: DenyReason::PolicyDenied,
                ..
            }
        );
    }
    let events = emitted(
        result
            .children
            .into_iter()
            .map(|child| child.audit_payload)
            .collect(),
    )
    .await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        ["2", "2"]
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_deadline_overrides_inner_freshness_and_is_not_renewed_by_reads()
-> anyhow::Result<()> {
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(snapshot(
        "code.read",
        "1",
        60,
    )?));
    let pipeline = pipeline(&handle, None)?;
    let (decision, _) = pipeline.enforce(&request(), "session").await;
    std::assert_matches!(decision, EnforcementDecision::Allow { .. });
    handle.swap_snapshot(snapshot("code.read", "2", 0)?);
    for _ in 0..2 {
        let (decision, _) = pipeline.enforce(&request(), "session").await;
        std::assert_matches!(
            decision,
            EnforcementDecision::Deny {
                reason: DenyReason::PolicyBundleStale,
                ..
            }
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_publication_never_exposes_mixed_mapping_policy_or_version() -> anyhow::Result<()>
{
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(snapshot(
        "code.read",
        "1",
        60,
    )?));
    let pipeline = pipeline(&handle, None)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let writer = Arc::clone(&handle);
    let writer_barrier = Arc::clone(&barrier);
    let publisher = std::thread::spawn(move || -> anyhow::Result<()> {
        writer_barrier.wait();
        for _ in 0..1000 {
            writer.swap_snapshot(snapshot("code.write", "2", 60)?);
            std::thread::yield_now();
            writer.swap_snapshot(snapshot("code.read", "1", 60)?);
        }
        Ok(())
    });
    barrier.wait();
    let mut payloads = Vec::new();
    for _ in 0..100 {
        let (decision, payload) = pipeline.enforce(&request(), "session").await;
        std::assert_matches!(decision, EnforcementDecision::Allow { .. });
        payloads.push(payload);
        tokio::task::yield_now().await;
    }
    publisher.join().expect("publisher thread")?;
    let events = emitted(payloads).await?;
    assert_eq!(events.len(), 100);
    for event in events {
        std::assert_matches!(
            (event.action.as_str(), event.bundle_version.as_str()),
            ("code.read", "1") | ("code.write", "2")
        );
    }
    Ok(())
}

#[tokio::test]
async fn expired_composite_pin_cannot_borrow_a_replacement_deadline() -> anyhow::Result<()> {
    let old_policy = policy("communication.external.read");
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(
        RuntimeSnapshot::new(
            normalizer("code.read")?,
            old_policy.clone(),
            1,
            Some("1".to_string()),
        ),
    ));
    let replacement = RuntimeSnapshot::new(
        normalizer("code.read")?,
        policy("communication.external.read"),
        60,
        Some("2".to_string()),
    );
    let writer = Arc::downgrade(&handle);
    *old_policy.hook.lock().expect("hook lock") = Some(Box::new(move || {
        writer
            .upgrade()
            .expect("live handle")
            .swap_snapshot(replacement);
        std::thread::sleep(Duration::from_millis(1100));
    }));
    let pipeline = pipeline(&handle, None)?;
    let (request, actions) = composite()?;
    let result = pipeline
        .enforce_composite(&request, "session", &actions)
        .await;
    std::assert_matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 0 }
    );
    std::assert_matches!(
        result.children[1].decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    let events = emitted(
        result
            .children
            .into_iter()
            .map(|child| child.audit_payload)
            .collect(),
    )
    .await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        ["1", "1"]
    );
    let result = pipeline
        .enforce_composite(&request, "session", &actions)
        .await;
    std::assert_matches!(result.disposition, CompositeDisposition::Dispatch { .. });
    let events = emitted(
        result
            .children
            .into_iter()
            .map(|child| child.audit_payload)
            .collect(),
    )
    .await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        ["2", "2"]
    );
    Ok(())
}

#[tokio::test]
async fn normalization_failure_audit_carries_the_pinned_generation() -> anyhow::Result<()> {
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(snapshot(
        "code.read",
        "7",
        60,
    )?));
    let pipeline = pipeline(&handle, None)?;
    let mut unmatched = request();
    unmatched.host = Authority::from_static("unmatched.test");
    let (decision, payload) = pipeline.enforce(&unmatched, "session").await;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::UnclassifiedIntent,
            ..
        }
    );
    let events = emitted(vec![payload]).await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        ["7"]
    );
    Ok(())
}

struct DelayedInjector {
    hook: Hook,
    calls: std::sync::atomic::AtomicUsize,
    delay_at: usize,
}

#[async_trait::async_trait]
impl CredentialInjector for DelayedInjector {
    async fn inject(
        &self,
        _: &firma_core::ExecutionEnvelope,
        _: &str,
        _: &str,
    ) -> Result<firma_core::InjectedCredentials, CredentialInjectionError> {
        let call = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let callback = if call == self.delay_at {
            self.hook.lock().expect("hook lock").take()
        } else {
            None
        };
        if let Some(callback) = callback {
            callback();
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        Ok(firma_core::InjectedCredentials::empty())
    }
}

fn delayed_pipeline(action: &'static str, delay_at: usize) -> anyhow::Result<EnforcementPipeline> {
    let handle = Arc::new(SwappablePolicyEvaluation::from_snapshot(snapshot(
        action, "1", 1,
    )?));
    let replacement = snapshot(action, "2", 60)?;
    let writer = Arc::clone(&handle);
    pipeline_with_injector(
        &handle,
        None,
        Box::new(DelayedInjector {
            hook: Mutex::new(Some(Box::new(move || writer.swap_snapshot(replacement)))),
            calls: std::sync::atomic::AtomicUsize::new(0),
            delay_at,
        }),
    )
}

#[tokio::test]
async fn credential_wait_cannot_admit_an_expired_pin_or_borrow_the_new_deadline()
-> anyhow::Result<()> {
    let pipeline = delayed_pipeline("code.read", 1)?;
    let (decision, payload) = pipeline.enforce(&request(), "session").await;
    std::assert_matches!(
        decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            identity: Some(_),
            ..
        }
    );
    let events = emitted(vec![payload]).await?;
    assert_eq!(events[0].decision, firma_sidecar::audit::Decision::Deny);
    assert_eq!(events[0].bundle_version, "1");
    assert_eq!(events[0].action, "code.read");
    assert_eq!(events[0].agent_id, "agt_01j0000000e008000000000001");

    let (decision, payload) = pipeline.enforce(&request(), "session").await;
    std::assert_matches!(decision, EnforcementDecision::Allow { .. });
    assert_eq!(emitted(vec![payload]).await?[0].bundle_version, "2");
    Ok(())
}

#[tokio::test]
async fn composite_credential_wait_blocks_dispatch_when_the_pin_expires() -> anyhow::Result<()> {
    let pipeline = delayed_pipeline("communication.external.read", 2)?;
    let (request, actions) = composite()?;
    let result = pipeline
        .enforce_composite(&request, "session", &actions)
        .await;
    std::assert_matches!(
        result.disposition,
        CompositeDisposition::Block { blocker_index: 1 }
    );
    assert_eq!(result.children.len(), 2);
    std::assert_matches!(
        result.children[0].decision,
        EnforcementDecision::Abort {
            reason: firma_core::AbortReason::BatchAtomicity,
            ..
        }
    );
    std::assert_matches!(
        result.children[1].decision,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    let events = emitted(
        result
            .children
            .into_iter()
            .map(|child| child.audit_payload)
            .collect(),
    )
    .await?;
    assert_eq!(events[0].decision, firma_sidecar::audit::Decision::Abort);
    assert_eq!(events[1].decision, firma_sidecar::audit::Decision::Deny);
    for event in events {
        assert_eq!(event.bundle_version, "1");
        assert_eq!(event.action, "communication.external.read");
    }
    let result = pipeline
        .enforce_composite(&request, "session", &actions)
        .await;
    std::assert_matches!(result.disposition, CompositeDisposition::Dispatch { .. });
    let events = emitted(
        result
            .children
            .into_iter()
            .map(|child| child.audit_payload)
            .collect(),
    )
    .await?;
    for event in events {
        assert_eq!(event.bundle_version, "2");
    }
    Ok(())
}
