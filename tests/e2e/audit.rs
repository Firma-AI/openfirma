use std::path::Path;

use serde::Deserialize;
use serde_repr::Deserialize_repr;

#[derive(Debug, PartialEq, Eq, Deserialize_repr)]
#[repr(u8)]
pub(crate) enum AuditDecision {
    Allow = 1,
    Deny = 2,
    Abort = 3,
    Modify = 4,
    StepUp = 5,
    Defer = 6,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuditEvent {
    session_id: String,
    pub(crate) token_id: String,
    pub(crate) action: String,
    pub(crate) resource: String,
    pub(crate) decision: AuditDecision,
    pub(crate) deny_reason: String,
    pub(crate) dispatch_status: u16,
}

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
