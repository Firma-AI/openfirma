use std::path::Path;

use anyhow::Context;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize_repr)]
#[repr(u8)]
pub enum Decision {
    Allow = 1,
    Deny = 2,
    Abort = 3,
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
            .zip(1..)
            .filter(|(l, _)| !l.trim().is_empty())
            .map(|(l, line)| {
                serde_json::from_str(l)
                    .with_context(|| format!("unexpected audit record in audit log at line {line}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self(events))
    }
}
