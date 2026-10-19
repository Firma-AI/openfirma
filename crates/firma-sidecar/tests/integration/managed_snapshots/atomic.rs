use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use firma_core::DenyReason;
use firma_http::{Authority, HeaderMap, Method};
use firma_sidecar::composio::{ComposioCatalogs, DecodeResult, decode};
use firma_sidecar::pipeline::{CompositeDisposition, EnforcementDecision, RawRequest};
use pretty_assertions::assert_matches;
use tokio::sync::oneshot;
use tracing_subscriber::{Layer, layer::SubscriberExt};

use super::fixture::{ACTION_A, ACTION_B, Harness, SESSION, bundle, request};

struct StageBarrier {
    arrival: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
    remaining: AtomicUsize,
}

impl<S: tracing::Subscriber> Layer<S> for StageBarrier {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != "firma_sidecar::pipeline"
            || event.metadata().fields().field("action_class").is_none()
            || self.remaining.fetch_sub(1, Ordering::SeqCst) != 1
        {
            return;
        }
        if let Some(arrival) = self
            .arrival
            .lock()
            .ok()
            .and_then(|mut sender| sender.take())
        {
            let _ = arrival.send(());
            // A failed assertion must not leave a blocking worker behind.
            let _ = self
                .release
                .lock()
                .map(|receiver| receiver.recv_timeout(Duration::from_secs(20)));
        }
    }
}

struct Gate(Option<mpsc::SyncSender<()>>);

impl Drop for Gate {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

fn barrier(nth: usize) -> (StageBarrier, oneshot::Receiver<()>, Gate) {
    let (arrival, arrived) = oneshot::channel();
    let (release, receiver) = mpsc::sync_channel(1);
    (
        StageBarrier {
            arrival: Mutex::new(Some(arrival)),
            release: Mutex::new(receiver),
            remaining: AtomicUsize::new(nth),
        },
        arrived,
        Gate(Some(release)),
    )
}

#[tokio::test]
async fn policy_remediations_retain_their_snapshot_in_signed_audits() -> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let mut payloads = Vec::new();
    for (version, annotation) in [
        ("step-up", "step_up(\"approval\")"),
        ("defer", "defer(\"100\")"),
    ] {
        let mut candidate = bundle(version, ACTION_A, ACTION_A);
        candidate.policies =
            format!("@{annotation}\nforbid(principal, action, resource);").into_bytes();
        harness.publish(&subscription, candidate).await?;
        let (decision, payload) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
        match version {
            "step-up" => assert_matches!(decision, EnforcementDecision::StepUp { .. }),
            _ => assert_matches!(decision, EnforcementDecision::Defer { .. }),
        }
        payloads.push(payload);
    }
    let events = harness.audit(payloads).await?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.bundle_version.as_str())
            .collect::<Vec<_>>(),
        vec!["step-up", "defer"]
    );
    Ok(())
}

#[tokio::test]
async fn update_between_normalization_and_policy_cannot_mix_snapshot_components()
-> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    harness
        .publish(&subscription, bundle("old", ACTION_A, ACTION_B))
        .await?;
    let (barrier, arrival, gate) = barrier(1);
    let pipeline = Arc::clone(&harness.runtime.pipeline);
    let handle = tokio::runtime::Handle::current();
    let pending = tokio::task::spawn_blocking(move || {
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(barrier));
        handle.block_on(pipeline.enforce(&request(), SESSION))
    });
    tokio::time::timeout(Duration::from_secs(10), arrival).await??;
    harness
        .publish(&subscription, bundle("new", ACTION_B, ACTION_A))
        .await?;
    drop(gate);
    let (old, old_payload) = pending.await?;
    assert_matches!(old, EnforcementDecision::Deny {
        reason: DenyReason::PolicyDenied, envelope: Some(ref envelope), ..
    } if envelope.intent().action_class == ACTION_A);
    let (new, new_payload) = harness.runtime.pipeline.enforce(&request(), SESSION).await;
    assert_matches!(new, EnforcementDecision::Deny {
        reason: DenyReason::PolicyDenied, envelope: Some(ref envelope), ..
    } if envelope.intent().action_class == ACTION_B);
    let events = harness.audit(vec![old_payload, new_payload]).await?;
    assert_eq!(
        events
            .iter()
            .map(|event| (event.action.as_str(), event.bundle_version.as_str()))
            .collect::<Vec<_>>(),
        vec![(ACTION_A, "old"), (ACTION_B, "new")]
    );
    Ok(())
}

#[tokio::test]
async fn in_flight_request_cannot_borrow_a_replacements_deadline() -> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let mut old = bundle("old", ACTION_A, ACTION_A);
    old.ttl_seconds = 60;
    harness.publish(&subscription, old).await?;
    tokio::time::pause();
    let (barrier, arrival, gate) = barrier(1);
    let pipeline = Arc::clone(&harness.runtime.pipeline);
    let handle = tokio::runtime::Handle::current();
    let pending = tokio::task::spawn_blocking(move || {
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(barrier));
        handle.block_on(pipeline.enforce(&request(), SESSION))
    });
    arrival.await?;
    tokio::time::advance(Duration::from_secs(61)).await;
    harness
        .publish(&subscription, bundle("fresh", ACTION_A, ACTION_A))
        .await?;
    drop(gate);
    assert_matches!(
        pending.await?.0,
        EnforcementDecision::Deny {
            reason: DenyReason::PolicyBundleStale,
            ..
        }
    );
    assert_matches!(
        harness
            .runtime
            .pipeline
            .enforce(&request(), SESSION)
            .await
            .0,
        EnforcementDecision::Allow { .. }
    );
    Ok(())
}

#[tokio::test]
async fn composite_children_keep_the_same_snapshot_across_replacement() -> anyhow::Result<()> {
    let mut harness = Harness::new(true)?;
    let subscription = harness.subscription().await?;
    let mut old = bundle("old", ACTION_A, ACTION_A);
    old.policies = b"permit(principal, action, resource);".to_vec();
    let request = RawRequest {
        method: Method::POST,
        host: Authority::from_static("app.composio.dev"),
        path: "/tool_router/v3/trs_snapshot/mcp".into(),
        headers: HeaderMap::new(),
        is_https: true,
        body: Some(
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"COMPOSIO_MULTI_EXECUTE_TOOL","arguments":{"tools":[
                    {"tool_slug":"GMAIL_FETCH_EMAILS","arguments":{}},
                    {"tool_slug":"GMAIL_SEND_EMAIL","arguments":{}}
                ]}
            }})
            .to_string()
            .into_bytes(),
        ),
    };
    old.mappings
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("mappings"))?
        .rules
        .push(firma_protobuf::v1::ActionMappingRule {
            host: request.host.to_string(),
            method: Some(request.method.to_string()),
            path: Some(request.path.clone()),
            action_class: ACTION_A.into(),
        });
    harness.publish(&subscription, old).await?;
    let DecodeResult::Actions(actions) = decode(&request, &ComposioCatalogs::builtin()?) else {
        anyhow::bail!("expected two logical Composio actions");
    };
    assert_eq!(actions.len(), 2);
    let (barrier, arrival, gate) = barrier(2);
    let pipeline = Arc::clone(&harness.runtime.pipeline);
    let handle = tokio::runtime::Handle::current();
    let pending = tokio::task::spawn_blocking(move || {
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(barrier));
        handle.block_on(pipeline.enforce_composite(&request, SESSION, &actions))
    });
    tokio::time::timeout(Duration::from_secs(10), arrival).await??;
    let mut replacement = bundle("new", ACTION_A, ACTION_A);
    replacement.policies = b"forbid(principal, action, resource);".to_vec();
    harness.publish(&subscription, replacement).await?;
    drop(gate);
    let composite = pending.await?;
    assert_matches!(composite.disposition, CompositeDisposition::Dispatch { .. });
    for child in &composite.children {
        assert_matches!(&child.decision, EnforcementDecision::Allow { .. });
    }
    let events = harness
        .audit(
            composite
                .children
                .into_iter()
                .map(|child| child.audit_payload)
                .collect(),
        )
        .await?;
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.bundle_version == "old"));
    Ok(())
}
