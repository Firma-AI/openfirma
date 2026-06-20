use std::path::Path;

use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum Decision {
    Allow = 1,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct AuditEvent {
    action: String,
    resource: String,
    decision: Decision,
    deny_reason: String,
    dispatch_status: u16,
}

/// Sidecar audit events from the enforcement phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmaAuditTrail(BTreeSet<AuditEvent>);

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
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self(events))
    }
    /// Audit events where the sidecar issued an ALLOW decision.
    #[must_use]
    pub fn allow_events(&self) -> Vec<&AuditEvent> {
        self.0
            .iter()
            .filter(|e| e.decision == Decision::Allow)
            .collect()
    }

    /// Audit events where the sidecar issued a DENY decision.
    #[must_use]
    pub fn deny_events(&self) -> Vec<&AuditEvent> {
        self.0
            .iter()
            .filter(|e| e.decision == Decision::Deny)
            .collect()
    }
}
