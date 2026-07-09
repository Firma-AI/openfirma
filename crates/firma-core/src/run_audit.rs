//! Wire contract for the `firma run` → Sidecar audit channel.
//!
//! Some enforcement happens *outside* the Sidecar's request pipeline and so
//! never flows through an [`crate::envelope::ExecutionEnvelope`]. The canonical
//! example is a wrapped agent's direct loopback connection: it bypasses
//! `HTTP_PROXY`, so the `firma run` egress guard blocks it at the sandbox
//! boundary and reports the fact to the Sidecar after the event. The Sidecar
//! turns each report into a signed audit event so it surfaces in
//! `firma monitor` alongside hot-path decisions.
//!
//! This module holds only the wire types shared by the producer (`firma-run`)
//! and the consumer (`firma-sidecar`). It is intentionally **semantics-free**:
//! a [`RunAuditEvent`] states an observation, and the Sidecar — which signs the
//! audit log — owns the mapping from observation to `(action_class, decision,
//! deny_reason, resource)`. That split keeps the signature meaningful: the
//! reporter can never assert an arbitrary audit record.

use serde::{Deserialize, Serialize};

/// One message on the `firma run` audit channel.
///
/// Carries the per-run identity once (so individual events stay pure) plus the
/// observed [`RunAuditEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAuditMessage {
    /// Session that produced the event. Stamped onto the audit record so the
    /// event is attributable to a specific `firma run` invocation.
    pub session_id: String,
    /// Agent profile that produced the event.
    pub agent_id: String,
    /// The observed enforcement fact.
    pub event: RunAuditEvent,
}

/// An enforcement fact observed by `firma run` outside the Sidecar pipeline.
///
/// Each variant is a bare observation; the Sidecar maps it to fixed audit
/// semantics. New out-of-band producers add variants here rather than inventing
/// new channels or asserting arbitrary audit fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunAuditEvent {
    /// A direct connection to a loopback address that is not a sanctioned Firma
    /// endpoint, blocked at the sandbox boundary by the egress guard before it
    /// could reach a local admin port, daemon, or MCP server.
    LoopbackBlocked {
        /// Destination IP, rendered canonically (e.g. `127.0.0.1` or `::1`).
        dst_ip: String,
        /// Destination TCP port.
        dst_port: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_loopback_message() {
        let msg = r#"{
            "session_id": "sess",
            "agent_id": "claude-code",
            "event": {
                "kind": "loopback_blocked",
                "dst_ip": "127.0.0.1",
                "dst_port": 6379
            }
        }"#;
        let actual: RunAuditMessage = serde_json::from_str(msg).expect("deserialize");
        assert_eq!(
            RunAuditMessage {
                session_id: "sess".to_string(),
                agent_id: "claude-code".to_string(),
                event: RunAuditEvent::LoopbackBlocked {
                    dst_ip: "127.0.0.1".to_string(),
                    dst_port: 6379,
                },
            },
            actual
        );
    }

    #[test]
    fn serialize_loopback_message_uses_stable_snake_case_tag() {
        let msg = RunAuditMessage {
            session_id: "sess".to_string(),
            agent_id: "vscode".to_string(),
            event: RunAuditEvent::LoopbackBlocked {
                dst_ip: "::1".to_string(),
                dst_port: 9443,
            },
        };

        let value = serde_json::to_value(&msg).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(value["session_id"], "sess");
        assert_eq!(value["agent_id"], "vscode");
        assert_eq!(value["event"]["kind"], "loopback_blocked");
        assert_eq!(value["event"]["dst_ip"], "::1");
        assert_eq!(value["event"]["dst_port"], 9443);
    }

    #[test]
    fn unknown_event_kind_is_rejected() {
        let msg = r#"{
            "session_id": "sess",
            "agent_id": "claude-code",
            "event": {
                "kind": "not_a_real_event"
            }
        }"#;

        let error = serde_json::from_str::<RunAuditMessage>(msg)
            .expect_err("unknown event kind must not deserialize");

        assert!(
            error.to_string().contains("not_a_real_event"),
            "unexpected error: {error}"
        );
    }
}
