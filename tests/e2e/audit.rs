use std::path::Path;

pub(crate) use firma_audit_schema::{Decision as AuditDecision, ExecutionEvent as AuditEvent};

/// Reads the JSONL audit log and returns its unique event for `session` and `nonce`.
///
/// The nonce is matched within the event resource. The test fails if the log cannot be read,
/// contains malformed records, or does not contain exactly one matching event.
pub(crate) fn correlated_event(path: &Path, session: &str, nonce: &str) -> AuditEvent {
    let audit = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut events = audit
        .lines()
        .map(|line| serde_json::from_str::<AuditEvent>(line).expect("valid audit JSON record"))
        .filter(|event| event.session_id == session && event.resource.contains(nonce))
        .collect::<Vec<_>>();
    assert_eq!(
        events.len(),
        1,
        "expected one audit event correlated by session and nonce: {events:#?}"
    );
    events.pop().expect("correlated audit event")
}
