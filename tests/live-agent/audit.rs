use std::path::Path;

use anyhow::Context;
use firma_audit_schema::Decision;
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::{agent::AgentKind, setup::ScenarioSetup};

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

    /// Drops allowed requests caused by agent startup; denials are kept.
    ///
    /// Startup traffic is incidental to the scenario and varies by platform
    /// and agent version. Denials to those same hosts still signal enforcement
    /// behavior, so they are preserved.
    #[must_use]
    pub fn exclude_incidental_allow_events(mut self, agent: AgentKind) -> Self {
        let domains = agent.incidental_allow_domains();
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

    #[track_caller]
    pub fn assert_snapshot(&self, scenario_name: &str, ctx: &ScenarioSetup) {
        // Keep existing snapshot names stable when the Cargo test target is
        // renamed. Otherwise insta derives the filename prefix from the target.
        let name = format!("e2e__audit__{}_{}", ctx.agent.kind.as_ref(), scenario_name);
        let mock_port = ctx.mock_server.address().port().to_string();
        let mock_port_filter = regex::escape(&mock_port);
        let tcp_port = ctx.raw_tcp.address().port().to_string();
        let tcp_port_filter = regex::escape(&tcp_port);
        insta::with_settings!({
            prepend_module_to_snapshot => false,
            filters => vec![
                (mock_port_filter.as_str(), "<mock-port>"),
                (tcp_port_filter.as_str(), "<tcp-port>"),
            ],
        }, {
            insta::assert_debug_snapshot!(name, self);
        });
    }
}
