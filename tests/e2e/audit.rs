use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) use firma_audit_schema::{Decision as AuditDecision, ExecutionEvent as AuditEvent};

/// Reads the JSONL audit log and returns its unique event for `session` and `nonce`.
///
/// The nonce is matched within the event resource. The test fails if the log cannot be read,
/// contains malformed records, or does not contain exactly one matching event.
pub(crate) fn correlated_event(path: &Path, session: &str, nonce: &str) -> AuditEvent {
    wait_for_correlated_event(path, session, nonce, Duration::ZERO)
}

pub(crate) fn wait_for_correlated_event(
    path: &Path,
    session: &str,
    nonce: &str,
    timeout: Duration,
) -> AuditEvent {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(event) = find_correlated_event(path, session, nonce) {
            return event;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for audit event correlated by session {session} and nonce {nonce}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn find_correlated_event(path: &Path, session: &str, nonce: &str) -> Option<AuditEvent> {
    let Ok(audit) = std::fs::read_to_string(path) else {
        return None;
    };
    let mut events = audit
        .lines()
        .map(|line| serde_json::from_str::<AuditEvent>(line).expect("valid audit JSON record"))
        .filter(|event| event.session_id == session && event.resource.contains(nonce))
        .collect::<Vec<_>>();
    match events.len() {
        0 => None,
        1 => events.pop(),
        _ => panic!("expected one audit event correlated by session and nonce: {events:#?}"),
    }
}
