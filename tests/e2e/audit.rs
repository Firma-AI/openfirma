use std::path::Path;

use anyhow::Context;
pub use firma_sidecar::audit::ExecutionEvent;

pub fn parse_audit_log(path: &Path) -> Result<Vec<ExecutionEvent>, anyhow::Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs_err::read_to_string(path)?;
    content
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str(l)
                .with_context(|| format!("unexpected audit record in audit log at line {i}"))
        })
        .collect()
}

#[must_use]
pub fn allow_events(events: &[ExecutionEvent]) -> Vec<&ExecutionEvent> {
    events.iter().filter(|e| e.decision == 1).collect()
}

#[must_use]
pub fn deny_events(events: &[ExecutionEvent]) -> Vec<&ExecutionEvent> {
    events.iter().filter(|e| e.decision == 2).collect()
}
