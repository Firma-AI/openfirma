use std::path::Path;

use anyhow::Context;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use std::collections::BTreeSet;

use crate::{agent::AgentKind, setup::ScenarioSetup};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize_repr)]
#[repr(u8)]
pub enum Decision {
    Allow = 1,
    Deny = 2,
    Abort = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct AuditEvent {
    pub action: String,
    pub resource: String,
    pub decision: Decision,
    pub deny_reason: String,
    pub dispatch_status: u16,
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

    #[must_use]
    pub fn allow_events(&self) -> Vec<&AuditEvent> {
        self.0
            .iter()
            .filter(|event| event.decision == Decision::Allow)
            .collect()
    }

    #[must_use]
    pub fn deny_events(&self) -> Vec<&AuditEvent> {
        self.0
            .iter()
            .filter(|event| event.decision == Decision::Deny)
            .collect()
    }

    #[track_caller]
    pub fn assert_snapshot(&self, scenario_name: &str, ctx: &ScenarioSetup) {
        let name = format!("{}_{}", ctx.agent.kind.as_ref(), scenario_name);
        let mock_port = ctx.mock_server.address().port().to_string();
        let mock_port_filter = regex::escape(&mock_port);
        insta::with_settings!({
            filters => vec![
                (mock_port_filter.as_str(), "<mock-port>"),
            ],
        }, {
            insta::assert_debug_snapshot!(name, self);
        });
    }
}
