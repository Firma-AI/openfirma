use std::path::Path;

use anyhow::Context;
use firma_sidecar::audit::Decision;
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::agent::AgentKind;

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

    /// Drops allowed requests to the agent's own provider; denials are kept.
    ///
    /// An agent must reach its provider to function, so allowed provider
    /// traffic is already implied by a successful run and only adds
    /// platform-dependent noise to snapshots (e.g. codex dials
    /// `files.openai.com` on macOS but not Linux). Denials to those same hosts
    /// still signal enforcement behavior, so they are preserved.
    #[must_use]
    pub fn exclude_provider_allow_events(mut self, agent: AgentKind) -> Self {
        let domains = agent.provider_domains();
        self.0.retain(|event| {
            // Resources are `host/path`; match the host segment.
            let host = event
                .resource
                .split_once('/')
                .map_or_else(|| event.resource.as_str(), |v| v.0);
            let is_provider = domains.iter().any(|domain| {
                host.strip_suffix(domain)
                    .is_some_and(|d| d.is_empty() || d.ends_with('.'))
            });
            !(event.decision == Decision::Allow && is_provider)
        });
        self
    }
}
