use std::path::Path;

pub use firma_sidecar::audit::ExecutionEvent;

pub fn parse_audit_log(path: &Path) -> Result<Vec<ExecutionEvent>, anyhow::Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs_err::read_to_string(path)?;

    let mut events = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<ExecutionEvent>(line) {
            Ok(event) => events.push(event),
            Err(e) => {
                anyhow::bail!("unexpected non-audit line in audit log: {e}: {line}");
            }
        }
    }

    Ok(events)
}

#[must_use]
pub fn allow_events(events: &[ExecutionEvent]) -> Vec<&ExecutionEvent> {
    events.iter().filter(|e| e.decision == 1).collect()
}

#[must_use]
pub fn deny_events(events: &[ExecutionEvent]) -> Vec<&ExecutionEvent> {
    events.iter().filter(|e| e.decision == 2).collect()
}
