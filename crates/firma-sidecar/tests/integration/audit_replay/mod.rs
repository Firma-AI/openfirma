mod fixture;
mod legacy_routes;

use std::time::Duration;

use firma_protobuf::v1::StreamEventsResponse;
use fixture::{Collector, Fixture, TestResult, event, finish};
use tonic::Status;

#[tokio::test]
async fn lost_receipt_retains_evidence_across_credential_rotation() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let original = event("run-a-event", Some(b"original-run-proof"));
    let bytes = fixture.seed(std::slice::from_ref(&original))?;
    let (tx, task, cancel) = fixture.start()?;
    let received = collector.next().await?;
    assert_eq!(received.key, "original-key");
    assert_eq!(
        received.event.run_evidence.as_deref(),
        Some(b"original-run-proof".as_slice())
    );
    assert_eq!(
        std::fs::read(&fixture.wal)?,
        bytes,
        "channel and RPC receipt are not persistence"
    );
    cancel.cancel();
    drop(tx);
    received.respond(Err(Status::unavailable("commit response lost")));
    finish(task).await?;
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);

    std::fs::write(&fixture.key, "rotated-key")?;
    let (tx, task, cancel) = fixture.start()?;
    let replayed = collector.next().await?;
    assert_eq!(replayed.key, "rotated-key");
    assert_eq!(replayed.event.session_id, original.session_id);
    assert_eq!(replayed.event.agent_id, original.agent_id);
    assert_eq!(
        replayed.event.run_evidence,
        original.run_evidence.map(|value| value.0)
    );
    assert_eq!(replayed.event.signature, original.signature);
    cancel.cancel();
    drop(tx);
    replayed.persist();
    finish(task).await?;
    assert_eq!(std::fs::read(&fixture.wal)?, b"");
    Ok(())
}

#[tokio::test]
async fn invalid_run_is_archived_before_later_run_is_delivered() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let invalid = event("invalid", Some(b"invalid-proof"));
    let valid = event("later", None);
    fixture.seed(&[invalid.clone(), valid.clone()])?;
    std::fs::write(fixture.archive(), b"{\"torn\":")?;
    let (tx, task, cancel) = fixture.start()?;
    let rejected = collector.next().await?;
    assert_eq!(rejected.event.event_id, invalid.event_id);
    rejected.respond(Err(Status::invalid_argument(
        "run evidence verification is not supported",
    )));
    let delivered = collector.next().await?;
    let archive = std::fs::read_to_string(fixture.archive())?;
    let mut lines = archive.lines();
    assert_eq!(lines.next(), Some("{\"torn\":"));
    let rejected: serde_json::Value = serde_json::from_str(lines.next().ok_or("archive missing")?)?;
    let bytes: Vec<u8> = serde_json::from_value(rejected["record"].clone())?;
    assert_eq!(
        serde_json::from_slice::<firma_audit_schema::ExecutionEvent>(&bytes)?,
        invalid
    );
    assert_eq!(rejected["code"], "invalid_argument");
    assert_eq!(
        rejected["reason"],
        "run evidence verification is not supported"
    );
    assert_eq!(delivered.event.event_id, valid.event_id);
    assert_eq!(delivered.event.run_evidence, None);
    cancel.cancel();
    drop(tx);
    delivered.persist();
    finish(task).await?;
    assert_eq!(std::fs::read(&fixture.wal)?, b"");
    Ok(())
}

#[tokio::test]
async fn incomplete_receipts_and_unsupported_rpc_do_not_reclaim() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let bytes = fixture.seed(&[event("retained", Some(b"proof"))])?;
    let outcomes = [
        Ok(StreamEventsResponse {
            last_event_id: "retained".into(),
            events_received: 1,
            durably_persisted: false,
        }),
        Ok(StreamEventsResponse {
            last_event_id: "different".into(),
            events_received: 1,
            durably_persisted: true,
        }),
        Ok(StreamEventsResponse {
            last_event_id: "retained".into(),
            events_received: 0,
            durably_persisted: true,
        }),
        Err(Status::unimplemented("collector has no SubmitEvent")),
        Err(Status::unauthenticated("credentials expired")),
    ];
    for result in outcomes {
        let (tx, task, cancel) = fixture.start()?;
        let pending = collector.next().await?;
        cancel.cancel();
        drop(tx);
        pending.respond(result);
        finish(task).await?;
        assert_eq!(std::fs::read(&fixture.wal)?, bytes);
        assert!(!fixture.archive().exists());
        assert_eq!(
            collector
                .legacy_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    Ok(())
}

#[tokio::test]
async fn scope_mismatch_and_unscoped_legacy_queue_are_left_intact() -> TestResult {
    let collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let bytes = fixture.seed(&[event("original", None)])?;
    let scope = fixture.scope_path();
    let mut different: serde_json::Value = serde_json::from_slice(&std::fs::read(&scope)?)?;
    different["sidecar"][0] = "foreign-workspace".into();
    std::fs::write(&scope, serde_json::to_vec(&different)?)?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    let error = task.await?.expect_err("wrong scope");
    assert_eq!(
        error.to_string(),
        "server error: audit WAL destination does not match its stored scope"
    );
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    std::fs::remove_file(scope)?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    let error = task.await?.expect_err("unscoped queue");
    assert_eq!(
        error.to_string(),
        "server error: nonempty legacy audit WAL has no scope; explicit migration is required"
    );
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    Ok(())
}

#[tokio::test]
async fn failed_rejection_archive_keeps_both_runs_pending() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let bytes = fixture.seed(&[event("bad", Some(b"bad")), event("later", None)])?;
    std::fs::create_dir(fixture.archive())?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    collector
        .next()
        .await?
        .respond(Err(Status::invalid_argument("invalid evidence")));
    let error = task.await?.expect_err("archive failure");
    assert!(matches!(
        error,
        firma_sidecar::audit::AuditSinkError::ServerError(_)
    ));
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    Ok(())
}

#[tokio::test]
async fn torn_tail_never_absorbs_a_newly_journaled_event() -> TestResult {
    for complete_tail in [false, true] {
        let mut collector = Collector::start()?;
        let fixture = Fixture::new(&collector.url).await?;
        let mut original = fixture.seed(&[event("head", None)])?;
        let tail = if complete_tail {
            serde_json::to_vec(&event("unterminated", Some(b"original-tail-proof")))?
        } else {
            b"{\"event_id\":\"partial".to_vec()
        };
        original.extend_from_slice(&tail);
        std::fs::write(&fixture.wal, &original)?;
        let payload = fixture.payload().await?;
        let (tx, mut task, _) = fixture.start()?;
        tx.send(payload).await?;
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    result = &mut task => { result??; break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()); }
                    received = collector.next() => received?.respond(Err(Status::unavailable("offline"))),
                }
            }
        }).await??;
        let retained = std::fs::read(&fixture.wal)?;
        let lines: Vec<&[u8]> = retained.split_inclusive(|byte| *byte == b'\n').collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], [tail.as_slice(), b"\n"].concat());
        let signed: firma_audit_schema::ExecutionEvent = serde_json::from_slice(lines[2])?;
        assert_eq!(signed.session_id, "new-run");
        assert_eq!(signed.run_evidence, None);
        assert_ne!(signed.signature, [] as [u8; 0]);

        let (tx, task, cancel) = fixture.start()?;
        let head = collector.next().await?;
        assert_eq!(head.event.event_id, "head");
        head.persist();
        if complete_tail {
            let tail = collector.next().await?;
            assert_eq!(tail.event.event_id, "unterminated");
            assert_eq!(
                tail.event.run_evidence.as_deref(),
                Some(b"original-tail-proof".as_slice())
            );
            tail.persist();
        }
        let newest = collector.next().await?;
        assert_eq!(newest.event.event_id, signed.event_id);
        assert_eq!(newest.event.session_id, signed.session_id);
        assert_eq!(newest.event.signature, signed.signature);
        cancel.cancel();
        drop(tx);
        newest.persist();
        finish(task).await?;
        assert_eq!(std::fs::read(&fixture.wal)?, b"");
        if !complete_tail {
            let rejected: serde_json::Value =
                serde_json::from_slice(&std::fs::read(fixture.archive())?)?;
            let bytes: Vec<u8> = serde_json::from_value(rejected["record"].clone())?;
            assert_eq!(bytes, [tail.as_slice(), b"\n"].concat());
        }
    }
    Ok(())
}

#[tokio::test]
async fn capacity_exhaustion_preserves_pending_records() -> TestResult {
    let mut collector = Collector::start()?;
    let mut fixture = Fixture::new(&collector.url).await?;
    let bytes = fixture.seed(&[event("pending", None)])?;
    let config_path = fixture.config_path();
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    config["audit"]["wal_max_size"] = format!("{} B", bytes.len() + 1).into();
    std::fs::write(&config_path, toml::to_string(&config)?)?;
    fixture.reload_config()?;
    let payload = fixture.payload().await?;
    let (tx, mut task, _) = fixture.start()?;
    tx.send(payload).await?;
    drop(tx);
    let error = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            tokio::select! {
                result = &mut task => break result.expect("sink task").expect_err("capacity exhausted"),
                received = collector.next() => received.expect("collector").respond(Err(Status::unavailable("offline"))),
            }
        }
    }).await?;
    assert_eq!(
        error.to_string(),
        "server error: audit WAL capacity exhausted; pending records retained"
    );
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    Ok(())
}

#[tokio::test]
async fn concurrent_writer_cannot_replace_an_inflight_queue() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let bytes = fixture.seed(&[event("inflight", None)])?;
    let (tx, task, cancel) = fixture.start()?;
    let pending = collector.next().await?;
    let (other_tx, other_task, _) = fixture.start()?;
    drop(other_tx);
    let error = other_task.await?.expect_err("writer lock");
    assert_eq!(
        error.to_string(),
        "server error: audit WAL is already in use"
    );
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    cancel.cancel();
    drop(tx);
    pending.persist();
    finish(task).await?;
    assert_eq!(std::fs::read(&fixture.wal)?, b"");
    Ok(())
}

#[tokio::test]
async fn legacy_only_collector_never_receives_a_fallback_stream() -> TestResult {
    let mut collector = Collector::start_legacy()?;
    let fixture = Fixture::new(&collector.url).await?;
    let retained = fixture.seed(&[event("legacy-destination", Some(b"original-proof"))])?;
    let (tx, task, cancel) = fixture.start()?;
    collector.unsupported_request().await?;
    cancel.cancel();
    drop(tx);
    finish(task).await?;
    assert_eq!(std::fs::read(&fixture.wal)?, retained);
    assert!(!fixture.archive().exists());
    assert_eq!(
        collector
            .legacy_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}

#[tokio::test]
async fn stalled_collector_retries_without_traffic_and_shutdown_retains_pending() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::with_audit(&collector.url, r#"wal_request_timeout = "500ms""#).await?;
    let bytes = fixture.seed(&[event("stalled", Some(b"original-proof"))])?;
    let (tx, task, cancel) = fixture.start()?;
    let first = collector.next().await?;
    // Keep both response senders alive: only the client deadline may end either RPC.
    // The retry follows the configured deadline and the next retry tick; the
    // 5 s default could not arrive within this bound.
    let second = tokio::time::timeout(Duration::from_secs(3), collector.next()).await??;
    assert_eq!(first.event, second.event);
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    cancel.cancel();
    drop(tx);
    finish(task).await?;
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    assert!(!fixture.archive().exists());
    drop((first, second));
    Ok(())
}

#[tokio::test]
async fn a_foreign_run_scope_is_refused_but_an_empty_journal_is_reused() -> TestResult {
    let collector = Collector::start()?;
    let run = "run_01j0000000e008000000000001";
    let fixture = Fixture::for_run(&collector.url, run).await?;
    let scope = fixture.scope_path();
    let mut stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&scope)?)?;
    assert_eq!(stored["run"], run, "{stored}");
    let bytes = fixture.seed(&[event("original", None)])?;

    // Even at a run-qualified path, a foreign scope must be refused.
    stored["run"] = "run_01j0000000e008000000000002".into();
    std::fs::write(&scope, serde_json::to_vec(&stored)?)?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    let error = task.await?.expect_err("another run's records");
    assert_eq!(
        error.to_string(),
        "server error: audit WAL destination does not match its stored scope"
    );
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);

    // With nothing left to deliver, the scope can be reclaimed.
    std::fs::write(&fixture.wal, b"")?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    finish(task).await?;
    let rewritten: serde_json::Value = serde_json::from_slice(&std::fs::read(&scope)?)?;
    assert_eq!(rewritten["run"], run, "{rewritten}");
    Ok(())
}

#[tokio::test]
async fn a_scope_written_before_runs_existed_still_matches() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    fixture.seed(&[event("original", None)])?;
    let scope = fixture.scope_path();
    let mut stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&scope)?)?;
    stored.as_object_mut().unwrap().remove("run");
    std::fs::write(&scope, serde_json::to_vec(&stored)?)?;

    let (tx, task, cancel) = fixture.start()?;
    let replayed = collector.next().await?;
    cancel.cancel();
    drop(tx);
    replayed.persist();
    finish(task).await?;
    assert_eq!(
        std::fs::read(&fixture.wal)?,
        b"",
        "the record was delivered"
    );
    Ok(())
}

/// Points `fixture` at the runtime credential of `run`, served by
/// `sidecar` as activation names it: every run gets a fresh Sidecar
/// identity. The credential is read from a variable cargo already sets, so
/// no test mutates the process environment.
fn serve_run(fixture: &mut Fixture, sidecar: &str, run: &str) -> TestResult {
    let config_path = fixture.root.path().join("sidecar.toml");
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    let credentials = config["authority"]["credentials"]
        .as_table_mut()
        .ok_or("credentials table")?;
    credentials.remove("pre_shared_key_path");
    credentials.insert("runtime_credential_env".into(), "CARGO_PKG_NAME".into());
    credentials.insert("sidecar_id".into(), sidecar.into());
    credentials.insert("run_id".into(), run.into());
    std::fs::write(&config_path, toml::to_string(&config)?)?;
    fixture.config = firma_sidecar::config::SidecarConfig::load_from_path(
        &config_path,
        &firma_runtime_state::RuntimeLayout::from_root(fixture.root.path()),
    )?;
    fixture.wal = fixture.root.path().join(format!("audit.jsonl.{run}"));
    Ok(())
}

/// Shutdown retains undelivered records, and the run that journaled
/// them can never authenticate again once its `firma run` is gone. The next
/// run's Sidecar must still start, and must not send those records
/// under its own credential.
#[tokio::test]
async fn a_finished_run_pending_records_do_not_block_the_next_run() -> TestResult {
    let mut collector = Collector::start()?;
    let mut fixture = Fixture::new(&collector.url).await?;
    serve_run(&mut fixture, "sidecar-a", "run_01j0000000e008000000000001")?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    finish(task).await?;
    let retained = fixture.seed(&[event("run-a-record", None)])?;
    let old_wal = fixture.wal.clone();

    serve_run(&mut fixture, "sidecar-b", "run_01j0000000e008000000000002")?;
    let payload = fixture.payload().await?;
    let (tx, mut task, cancel) = fixture.start()?;
    tx.send(payload).await?;
    let received = tokio::select! {
        received = collector.next() => received?,
        result = &mut task => panic!("run-b's audit sink stopped: {:?}", result?),
    };
    assert_ne!(received.event.event_id, "run-a-record");
    cancel.cancel();
    drop(tx);
    received.persist();
    finish(task).await?;
    assert_ne!(fixture.wal, old_wal);
    assert_eq!(std::fs::read(old_wal)?, retained);
    Ok(())
}

/// An empty journal holds nothing another run could deliver, so the
/// next run's Sidecar starts with its own run-qualified sibling.
#[tokio::test]
async fn an_empty_journal_serves_the_next_run_sidecar() -> TestResult {
    let collector = Collector::start()?;
    let mut fixture = Fixture::new(&collector.url).await?;
    serve_run(&mut fixture, "sidecar-a", "run_01j0000000e008000000000001")?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    finish(task).await?;
    assert_eq!(std::fs::metadata(&fixture.wal)?.len(), 0);
    let old_wal = fixture.wal.clone();

    serve_run(&mut fixture, "sidecar-b", "run_01j0000000e008000000000002")?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    finish(task).await?;
    let scope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{}.scope", fixture.wal.display()))?)?;
    assert_eq!(scope["run"], "run_01j0000000e008000000000002");
    assert_ne!(old_wal, fixture.wal);
    assert_eq!(std::fs::metadata(old_wal)?.len(), 0);
    Ok(())
}

/// A queue whose scope does not match is refused without being touched,
/// including a torn final record that only its own destination may repair.
#[tokio::test]
async fn scope_mismatch_leaves_a_torn_tail_intact() -> TestResult {
    let collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let mut bytes = fixture.seed(&[event("original", None)])?;
    bytes.extend_from_slice(b"{\"event_id\":\"partial");
    std::fs::write(&fixture.wal, &bytes)?;
    let scope = fixture.root.path().join("audit.jsonl.scope");
    let mut different: serde_json::Value = serde_json::from_slice(&std::fs::read(&scope)?)?;
    different["sidecar"][0] = "foreign-workspace".into();
    std::fs::write(&scope, serde_json::to_vec(&different)?)?;
    let (tx, task, _) = fixture.start()?;
    drop(tx);
    let error = task.await?.expect_err("wrong scope");
    assert_eq!(
        error.to_string(),
        "server error: audit WAL destination does not match its stored scope"
    );
    assert_eq!(
        String::from_utf8(std::fs::read(&fixture.wal)?)?,
        String::from_utf8(bytes)?
    );
    Ok(())
}

/// A pre-shared-key Sidecar's scope file stays readable by the previous
/// release, whose scope rejects unknown fields, so rolling the binary back
/// does not strand its journal.
#[tokio::test]
async fn pre_shared_key_scope_remains_readable_by_the_previous_release() -> TestResult {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[expect(dead_code, reason = "only the accepted shape matters")]
    struct PreviousScope {
        version: u8,
        endpoint: String,
        sidecar: Option<(String, String)>,
    }

    let collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let scope = std::fs::read(fixture.root.path().join("audit.jsonl.scope"))?;
    serde_json::from_slice::<PreviousScope>(&scope)?;
    Ok(())
}

#[tokio::test]
async fn a_rejected_run_stops_the_sidecar_and_journals_what_it_holds() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::for_run(&collector.url, "run_01j0000000e008000000000001").await?;
    let bytes = fixture.seed(&[event("before-rejection", None)])?;
    let (tx, task, cancel, readiness) = fixture.start_with_readiness()?;
    let submitted = collector.next().await?;
    // Decided while the submission was in flight, so still buffered.
    tx.send(fixture.payload().await?).await?;

    submitted.respond(Err(Status::unauthenticated("authentication failed")));
    drop(tx);

    finish(task).await?;
    assert!(cancel.is_cancelled(), "the sidecar kept running");
    assert!(readiness.snapshot().run_rejected);
    let journal = std::fs::read(&fixture.wal)?;
    assert!(
        journal.starts_with(&bytes),
        "the rejected record was dropped"
    );
    assert_eq!(
        std::str::from_utf8(&journal)?.lines().count(),
        2,
        "the buffered decision was not journaled"
    );
    Ok(())
}

#[tokio::test]
async fn a_pre_shared_key_keeps_retrying_an_unauthenticated_submission() -> TestResult {
    let mut collector = Collector::start()?;
    let fixture = Fixture::new(&collector.url).await?;
    let bytes = fixture.seed(&[event("retried", None)])?;
    let (tx, task, cancel, readiness) = fixture.start_with_readiness()?;

    collector
        .next()
        .await?
        .respond(Err(Status::unauthenticated("authentication failed")));
    let retried = collector.next().await?;

    assert!(!cancel.is_cancelled());
    assert!(!readiness.snapshot().run_rejected);
    assert_eq!(std::fs::read(&fixture.wal)?, bytes);
    cancel.cancel();
    drop(tx);
    retried.persist();
    finish(task).await
}
