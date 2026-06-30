//! Cross-crate wire types for out-of-band egress enforcement reports.
//!
//! Some egress decisions are made *outside* the Sidecar's enforcement hot
//! path. The canonical example is a wrapped agent's direct connection to a
//! loopback address: such a call never traverses `HTTP_PROXY`, so the
//! `firma run` egress guard blocks it at the sandbox boundary and reports the
//! attempt to the Sidecar after the fact. The Sidecar turns the report into a
//! signed audit event so it surfaces in `firma monitor` alongside hot-path
//! decisions.
//!
//! This module holds only the wire contract shared by the producer
//! (`firma-run`) and the consumer (`firma-sidecar`); neither the guard nor the
//! audit pipeline lives here.

use serde::{Deserialize, Serialize};

/// Canonical action class for a blocked loopback connection attempt.
///
/// Registered in `docs/markdown/firma_action_class_registry.md`. Mirrors the
/// `action_class` convention used by [`crate::envelope::ExecutionIntent`].
pub const NETWORK_LOOPBACK_ACTION_CLASS: &str = "network.loopback";

/// A single blocked loopback connection attempt, reported by the `firma run`
/// egress guard to the Sidecar over a local control socket.
///
/// One report corresponds to one denied `connect(2)` to a loopback address
/// that is not a sanctioned Firma endpoint (the proxy bridge or DNS stub).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedLoopbackReport {
    /// Session that produced the attempt. Stamped onto the audit event so the
    /// block is attributable to a specific `firma run` invocation.
    pub session_id: String,
    /// Agent profile that produced the attempt.
    pub agent_id: String,
    /// Destination IP the agent tried to reach, rendered canonically
    /// (e.g. `127.0.0.1` or `::1`).
    pub dst_ip: String,
    /// Destination TCP port the agent tried to reach.
    pub dst_port: u16,
}

impl BlockedLoopbackReport {
    /// Renders the blocked destination as an audit `resource` string.
    ///
    /// IPv6 destinations are bracketed so the `host:port` form stays
    /// unambiguous (`[::1]:9000`); IPv4 destinations are left bare
    /// (`127.0.0.1:9000`). The `tcp://` scheme marks the transport.
    #[must_use]
    pub fn resource(&self) -> String {
        if self.dst_ip.contains(':') {
            format!("tcp://[{}]:{}", self.dst_ip, self.dst_port)
        } else {
            format!("tcp://{}:{}", self.dst_ip, self.dst_port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_resource_is_bare_host_port() {
        let report = BlockedLoopbackReport {
            session_id: "s".to_string(),
            agent_id: "a".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 9000,
        };
        assert_eq!(report.resource(), "tcp://127.0.0.1:9000");
    }

    #[test]
    fn ipv6_resource_is_bracketed() {
        let report = BlockedLoopbackReport {
            session_id: "s".to_string(),
            agent_id: "a".to_string(),
            dst_ip: "::1".to_string(),
            dst_port: 53,
        };
        assert_eq!(report.resource(), "tcp://[::1]:53");
    }

    #[test]
    fn round_trips_through_json() {
        let report = BlockedLoopbackReport {
            session_id: "sess".to_string(),
            agent_id: "claude-code".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 6379,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: BlockedLoopbackReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }
}
