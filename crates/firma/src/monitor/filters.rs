//! Post-parse filters for audit lines.
//!
//! Audit records are serialized as flat JSON by the sidecar's
//! `FileAuditSink` (`firma-sidecar::audit::sink::file`). This module
//! parses just the subset of fields the monitor filters need
//! (`agent_id`, `action`, `resource`, `decision`, `deny_reason`,
//! `timestamp`, `token_id`) and leaves the rest as opaque so format
//! additions on the sink side do not break the monitor.

use serde::Deserialize;

use crate::args::monitor::Decision;

/// Proto wire value for `ENFORCEMENT_DECISION_ALLOW`.
const PROTO_DECISION_ALLOW: i32 = 1;
/// Proto wire value for `ENFORCEMENT_DECISION_DENY`.
const PROTO_DECISION_DENY: i32 = 2;

/// Minimal projection of `ExecutionEvent` needed by the monitor
/// filters. Fields not listed here are silently ignored during
/// deserialization.
///
/// `resource`, `deny_reason`, and `timestamp` are captured for rendering
/// in later pipeline stages; the filter logic does not inspect them
/// directly but they are available on every parsed record.
#[derive(Debug, Deserialize)]
pub struct AuditLite {
    /// `agent_id` top-level field; empty string when the event is a
    /// passthrough (not classified through a capability).
    pub agent_id: Option<String>,
    /// `action` top-level field. Equivalent to the spec's `action_class`.
    pub action: Option<String>,
    /// `resource` top-level field, conventionally `host/path`.
    pub resource: Option<String>,
    /// `decision` top-level field, encoded as the proto enum int
    /// (1=ALLOW, 2=DENY, 3=ABORT).
    pub decision: Option<i32>,
    /// `deny_reason` top-level field; empty on ALLOW.
    pub deny_reason: Option<String>,
    /// `timestamp` top-level field, nanoseconds since the Unix epoch.
    pub timestamp: Option<u128>,
    /// `token_id` top-level field. Empty when the record was a
    /// passthrough.
    pub token_id: Option<String>,
    /// `sandbox_id` top-level field. Identifies the `firma run`
    /// invocation that produced the event. Empty / absent when the
    /// sidecar was not autostarted by `firma run`.
    pub sandbox_id: Option<String>,
}

/// Return `Some(parsed_audit)` if `raw` is a valid audit-record JSON
/// line AND passes the user-supplied `--decision`, `--action-class`
/// and `--agent` filters; return `None` otherwise.
#[must_use]
pub fn audit_passes(
    raw: &str,
    decision: Option<Decision>,
    action_class: Option<&str>,
    agent_id: Option<&str>,
    sandbox_id: Option<&str>,
) -> Option<AuditLite> {
    let parsed: AuditLite = serde_json::from_str(raw).ok()?;

    if let Some(want) = decision
        && !decision_matches(&parsed, want)
    {
        return None;
    }

    if let Some(want) = action_class
        && parsed.action.as_deref() != Some(want)
    {
        return None;
    }

    if let Some(want) = agent_id
        && parsed.agent_id.as_deref() != Some(want)
    {
        return None;
    }

    if let Some(want) = sandbox_id
        && parsed.sandbox_id.as_deref() != Some(want)
    {
        return None;
    }

    Some(parsed)
}

/// Map the user-facing `Decision` enum to the audit-record encoding
/// and check whether `parsed` matches.
///
/// `Passthrough` in the audit log is encoded as `decision = ALLOW`
/// AND `token_id` empty (see `firma_sidecar::audit::builder` tests).
fn decision_matches(parsed: &AuditLite, want: Decision) -> bool {
    let got = parsed.decision.unwrap_or(0);
    match want {
        Decision::Allow => got == PROTO_DECISION_ALLOW,
        Decision::Deny => got == PROTO_DECISION_DENY,
        Decision::Passthrough => {
            got == PROTO_DECISION_ALLOW && parsed.token_id.as_deref().is_some_and(str::is_empty)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic ALLOW event (`token_id` set, classified action).
    const ALLOW_LINE: &str = r#"{"event_id":"01900000-0000-7000-8000-000000000001","session_id":"sess_001","token_id":"tok_a","agent_id":"agent_codex","action":"github.issue.create","resource":"api.github.com/repos/x/y/issues","decision":1,"deny_reason":"","enforcement_latency_us":150,"context_hash":"ctx","bundle_version":"v1","timestamp":1715169751000000000,"dispatch_status":201,"dispatch_latency_us":42000,"response_size":128,"signature":[]}"#;

    /// Realistic DENY event.
    const DENY_LINE: &str = r#"{"event_id":"01900000-0000-7000-8000-000000000002","session_id":"sess_001","token_id":"tok_a","agent_id":"agent_codex","action":"stripe.payment.create","resource":"api.stripe.com/v1/charges","decision":2,"deny_reason":"scope_mismatch","enforcement_latency_us":80,"context_hash":"ctx","bundle_version":"v1","timestamp":1715169753000000000,"dispatch_status":0,"dispatch_latency_us":0,"response_size":0,"signature":[]}"#;

    /// Passthrough — decision=1 (ALLOW) AND `token_id`="".
    const PASSTHROUGH_LINE: &str = r#"{"event_id":"01900000-0000-7000-8000-000000000003","session_id":"sess_001","token_id":"","agent_id":"","action":"raw.http.GET","resource":"example.com/","decision":1,"deny_reason":"","enforcement_latency_us":5,"context_hash":"","bundle_version":"","timestamp":1715169754000000000,"dispatch_status":200,"dispatch_latency_us":1000,"response_size":0,"signature":[]}"#;

    #[test]
    fn parses_real_execution_event_shape() {
        let parsed: AuditLite = serde_json::from_str(ALLOW_LINE).expect("parse allow");
        assert_eq!(parsed.agent_id.as_deref(), Some("agent_codex"));
        assert_eq!(parsed.action.as_deref(), Some("github.issue.create"));
        assert_eq!(
            parsed.resource.as_deref(),
            Some("api.github.com/repos/x/y/issues")
        );
        assert_eq!(parsed.decision, Some(1));
        assert_eq!(parsed.deny_reason.as_deref(), Some(""));
        assert_eq!(parsed.timestamp, Some(1_715_169_751_000_000_000));
        assert_eq!(parsed.token_id.as_deref(), Some("tok_a"));
    }

    #[test]
    fn decision_allow_filter_matches_allow_line() {
        assert!(audit_passes(ALLOW_LINE, Some(Decision::Allow), None, None, None).is_some());
        assert!(audit_passes(DENY_LINE, Some(Decision::Allow), None, None, None).is_none());
    }

    #[test]
    fn decision_deny_filter_matches_deny_line() {
        assert!(audit_passes(DENY_LINE, Some(Decision::Deny), None, None, None).is_some());
        assert!(audit_passes(ALLOW_LINE, Some(Decision::Deny), None, None, None).is_none());
    }

    #[test]
    fn decision_passthrough_requires_empty_token_id() {
        assert!(
            audit_passes(
                PASSTHROUGH_LINE,
                Some(Decision::Passthrough),
                None,
                None,
                None
            )
            .is_some()
        );
        assert!(audit_passes(ALLOW_LINE, Some(Decision::Passthrough), None, None, None).is_none());
    }

    #[test]
    fn action_class_filter_matches_action_field() {
        assert!(audit_passes(ALLOW_LINE, None, Some("github.issue.create"), None, None).is_some());
        assert!(audit_passes(ALLOW_LINE, None, Some("other.class"), None, None).is_none());
    }

    #[test]
    fn agent_filter_matches_agent_id() {
        assert!(audit_passes(ALLOW_LINE, None, None, Some("agent_codex"), None).is_some());
        assert!(audit_passes(ALLOW_LINE, None, None, Some("agent_other"), None).is_none());
        assert!(audit_passes(PASSTHROUGH_LINE, None, None, Some("agent_codex"), None).is_none());
    }

    #[test]
    fn filters_compose() {
        assert!(
            audit_passes(
                DENY_LINE,
                Some(Decision::Deny),
                Some("stripe.payment.create"),
                Some("agent_codex"),
                None,
            )
            .is_some()
        );
        assert!(
            audit_passes(
                DENY_LINE,
                Some(Decision::Deny),
                Some("stripe.payment.create"),
                Some("wrong_agent"),
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn non_json_line_returns_none() {
        assert!(audit_passes("not a json line", None, None, None, None).is_none());
    }

    /// Realistic event carrying a `sandbox_id` from the autostarted sidecar.
    const ALLOW_LINE_WITH_SBX: &str = r#"{"event_id":"01900000-0000-7000-8000-000000000004","session_id":"sess_001","token_id":"tok_a","agent_id":"agent_codex","action":"github.issue.create","resource":"api.github.com/repos/x/y/issues","decision":1,"deny_reason":"","enforcement_latency_us":150,"context_hash":"ctx","bundle_version":"v1","timestamp":1715169755000000000,"dispatch_status":201,"dispatch_latency_us":42000,"response_size":128,"sandbox_id":"sbx_abc","signature":[]}"#;

    #[test]
    fn audit_lite_parses_sandbox_id() {
        let parsed: AuditLite =
            serde_json::from_str(ALLOW_LINE_WITH_SBX).expect("parse with sandbox");
        assert_eq!(parsed.sandbox_id.as_deref(), Some("sbx_abc"));
    }

    #[test]
    fn sandbox_id_filter_matches_exact() {
        assert!(audit_passes(ALLOW_LINE_WITH_SBX, None, None, None, Some("sbx_abc")).is_some());
        assert!(audit_passes(ALLOW_LINE_WITH_SBX, None, None, None, Some("other")).is_none());
    }

    #[test]
    fn sandbox_id_filter_rejects_missing_field() {
        assert!(audit_passes(ALLOW_LINE, None, None, None, Some("sbx_abc")).is_none());
    }
}
