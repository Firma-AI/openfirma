use std::path::Path;
use std::time::Duration;

pub(crate) use firma_audit_schema::{Decision as AuditDecision, ExecutionEvent as AuditEvent};

use crate::poll::wait_for;

/// Reads the JSONL audit log and returns its unique event for `session` and `nonce`.
///
/// This immediate lookup fails when no matching event exists. Use [`wait_for_correlated_event`]
/// while a concurrent audit writer may not have flushed the expected record yet.
pub(crate) fn correlated_event(path: &Path, session: &str, nonce: &str) -> AuditEvent {
    wait_for_correlated_event(path, session, nonce, Duration::ZERO)
}

/// Polls a JSONL audit log for its unique event matching `session` and `nonce`.
///
/// A final record without a newline may be temporarily incomplete and is retried when it is not
/// valid JSON. Every newline-terminated record is complete and therefore must deserialize; a
/// malformed completed record fails immediately rather than being mistaken for propagation delay.
pub(crate) fn wait_for_correlated_event(
    path: &Path,
    session: &str,
    nonce: &str,
    timeout: Duration,
) -> AuditEvent {
    wait_for(
        &format!("audit event correlated by session {session} and nonce {nonce}"),
        timeout,
        || find_correlated_event(path, session, nonce),
    )
}

fn find_correlated_event(path: &Path, session: &str, nonce: &str) -> Option<AuditEvent> {
    let Ok(audit) = std::fs::read_to_string(path) else {
        return None;
    };
    let mut events = Vec::new();
    for record in audit.split_inclusive('\n') {
        let completed = record.ends_with('\n');
        let line = record.strip_suffix('\n').unwrap_or(record);
        let event = match serde_json::from_str::<AuditEvent>(line) {
            Ok(event) => event,
            Err(_) if !completed => continue,
            Err(error) => panic!("malformed completed audit JSON record: {error}: {line:?}"),
        };
        if event.session_id == session && event.resource.contains(nonce) {
            events.push(event);
        }
    }
    match events.len() {
        0 => None,
        1 => events.pop(),
        _ => panic!("expected one audit event correlated by session and nonce: {events:#?}"),
    }
}

#[test]
fn correlated_audit_poll_tolerates_only_an_incomplete_trailing_record() {
    let event = audit_event("sess_test", "resource/nonce-test");
    let body = format!(
        "{}\n{{\"event_id\":",
        serde_json::to_string(&event).expect("serialize audit event")
    );
    let audit = tempfile::NamedTempFile::new().expect("audit fixture");
    std::fs::write(audit.path(), body).expect("write audit fixture");

    assert_eq!(
        wait_for_correlated_event(audit.path(), "sess_test", "nonce-test", Duration::ZERO,),
        event
    );
}

#[test]
#[should_panic(expected = "malformed completed audit JSON record")]
fn correlated_audit_poll_rejects_malformed_completed_records() {
    let audit = tempfile::NamedTempFile::new().expect("audit fixture");
    std::fs::write(audit.path(), "{malformed}\n").expect("write audit fixture");
    let _ = wait_for_correlated_event(audit.path(), "sess_test", "nonce-test", Duration::ZERO);
}

fn audit_event(session_id: &str, resource: &str) -> AuditEvent {
    AuditEvent {
        event_id: "event-test".to_string(),
        session_id: session_id.to_string(),
        token_id: "token-test".to_string(),
        agent_id: "agent-test".to_string(),
        action: "raw.http.GET".to_string(),
        resource: resource.to_string(),
        decision: AuditDecision::Allow,
        deny_reason: String::new(),
        enforcement_latency_us: 0,
        context_hash: String::new(),
        bundle_version: String::new(),
        timestamp: None,
        dispatch_status: 200,
        dispatch_latency_us: 0,
        response_size: 0,
        sandbox_id: "sandbox-test".to_string(),
        provenance: String::new(),
        thread_id: String::new(),
        parent_action_id: String::new(),
        signature: Vec::new(),
    }
}
