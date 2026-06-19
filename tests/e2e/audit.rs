use std::path::Path;

use anyhow::Context;
pub use firma_sidecar::audit::ExecutionEvent;

/// Sidecar audit events from the enforcement phase.
pub struct FirmaAuditTrail(Vec<ExecutionEvent>);

impl FirmaAuditTrail {
    pub fn try_new(path: &Path) -> Result<Self, anyhow::Error> {
        let content = fs_err::read_to_string(path)?;
        let events = content
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, l)| {
                serde_json::from_str(l)
                    .with_context(|| format!("unexpected audit record in audit log at line {i}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(events))
    }
    /// Audit events where the sidecar issued an ALLOW decision.
    #[must_use]
    pub fn allow_events(&self) -> Vec<&ExecutionEvent> {
        self.0.iter().filter(|e| e.decision == 1).collect()
    }

    /// Audit events where the sidecar issued a DENY decision.
    #[must_use]
    pub fn deny_events(&self) -> Vec<&ExecutionEvent> {
        self.0.iter().filter(|e| e.decision == 2).collect()
    }

    /// Audit events whose `action` contains `fragment`.
    #[must_use]
    pub fn events_for_action(&self, fragment: &str) -> Vec<&ExecutionEvent> {
        self.0
            .iter()
            .filter(|e| e.action.contains(fragment))
            .collect()
    }

    #[track_caller]
    pub fn assert_trail_snapshot(&self, snapshot_name: &str) {
        // Agents perform asynchronous calls, so we sort the trail by action and resource
        // to ensure a stable ordering for snapshot tests.
        let mut events = self.0.clone();
        events.sort_by(|a, b| a.action.cmp(&b.action).then(a.resource.cmp(&b.resource)));
        insta::assert_json_snapshot!(snapshot_name, &events, {
            "[].event_id"               => "[event_id]",
            "[].session_id"             => "[session_id]",
            "[].token_id"               => "[token_id]",
            "[].agent_id"               => "[agent_id]",
            "[].enforcement_latency_us" => "[latency_us]",
            "[].context_hash"           => "[context_hash]",
            "[].bundle_version"         => "[bundle_version]",
            "[].timestamp"              => "[timestamp]",
            "[].dispatch_latency_us"    => "[dispatch_latency_us]",
            "[].response_size"          => "[response_size]",
            "[].sandbox_id"             => "[sandbox_id]",
            "[].signature"              => "[signature]",
        });
    }
}
