use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct AuditEvent {
    pub(crate) session_id: String,
    pub(crate) token_id: String,
    pub(crate) action: String,
    pub(crate) resource: String,
    pub(crate) decision: u8,
    pub(crate) deny_reason: String,
    pub(crate) dispatch_status: u16,
}

pub(crate) fn matching_events(path: &Path, session: &str, nonce: &str) -> Vec<AuditEvent> {
    let audit = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    audit
        .lines()
        .map(|line| serde_json::from_str::<AuditEvent>(line).expect("valid audit JSON record"))
        .filter(|event| event.session_id == session && event.resource.contains(nonce))
        .collect()
}
