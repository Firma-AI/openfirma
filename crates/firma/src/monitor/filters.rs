//! Post-parse filters for audit lines.
//!
//! Audit records are serialized as flat JSON by the sidecar's
//! `FileAuditSink` (`firma-sidecar::audit::sink::file`). This module
//! parses just the subset of fields the monitor filters need
//! (`agent_id`, `action`, `resource`, `decision`, `deny_reason`,
//! `timestamp`, `token_id`) and leaves the rest as opaque so format
//! additions on the sink side do not break the monitor.

use firma_sidecar::audit::Decision as AuditDecision;
use serde::Deserialize;

use crate::args::monitor::Decision as DecisionFilter;

/// Parsed `decision` field. Distinguishes a recognized outcome from a
/// present-but-unrecognized wire value (forward-compat or corruption), so
/// the two never collapse into the "absent" (`None`) case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLiteDecision {
    /// A recognized [`AuditDecision`].
    Known(AuditDecision),
    /// Present on the record but not a recognized code; carries the raw
    /// integer (`0` when the value was not even an integer).
    Unknown(i64),
}

impl std::fmt::Display for AuditLiteDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Known(AuditDecision::Allow) => "ALLOW",
            Self::Known(AuditDecision::Deny) => "DENY",
            Self::Known(AuditDecision::Abort) => "ABORT",
            Self::Known(AuditDecision::Modify) => "MODIFY",
            Self::Known(AuditDecision::StepUp) => "STEP_UP",
            Self::Known(AuditDecision::Defer) => "DEFER",
            Self::Unknown(_) => "UNKNOWN",
        };
        f.write_str(label)
    }
}

/// Decodes the numeric `decision` wire value, keeping the unknown / known
/// distinction. An unrecognized or non-integer value becomes
/// [`AuditLiteDecision::Unknown`] rather than failing, so a single off-range
/// code never drops the whole record from the monitor output. Absence is
/// handled by the surrounding `Option<AuditLiteDecision>` field (`None`).
impl<'de> Deserialize<'de> for AuditLiteDecision {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(de)?;
        Ok(AuditDecision::deserialize(&value).map_or_else(
            |_| Self::Unknown(value.as_i64().unwrap_or_default()),
            Self::Known,
        ))
    }
}

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
    /// `decision` top-level field. Serialized as the numeric wire value;
    /// [`AuditLiteDecision::Unknown`] when present but unrecognized.
    pub decision: Option<AuditLiteDecision>,
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
    decision: Option<DecisionFilter>,
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

/// Map the user-facing `--decision` filter to the audit-record encoding
/// and check whether `parsed` matches.
///
/// `Passthrough` in the audit log is encoded as `decision = ALLOW`
/// AND `token_id` empty (see `firma_sidecar::audit::builder` tests).
fn decision_matches(parsed: &AuditLite, want: DecisionFilter) -> bool {
    let Some(AuditLiteDecision::Known(decision)) = parsed.decision else {
        return false;
    };
    match want {
        DecisionFilter::Allow => decision == AuditDecision::Allow,
        DecisionFilter::Deny => decision == AuditDecision::Deny,
        DecisionFilter::Passthrough => {
            decision == AuditDecision::Allow
                && parsed.token_id.as_deref().is_some_and(str::is_empty)
        }
        DecisionFilter::Modify => decision == AuditDecision::Modify,
        DecisionFilter::StepUp => decision == AuditDecision::StepUp,
        DecisionFilter::Defer => decision == AuditDecision::Defer,
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
        assert_eq!(
            parsed.decision,
            Some(AuditLiteDecision::Known(AuditDecision::Allow))
        );
        assert_eq!(parsed.deny_reason.as_deref(), Some(""));
        assert_eq!(parsed.timestamp, Some(1_715_169_751_000_000_000));
        assert_eq!(parsed.token_id.as_deref(), Some("tok_a"));
    }

    /// Present but unrecognized decision code — kept, but classified
    /// `Unknown` (distinct from an absent field).
    const UNKNOWN_DECISION_LINE: &str = r#"{"agent_id":"agent_codex","action":"x.y","resource":"r","decision":7,"deny_reason":"","token_id":"tok_a"}"#;

    /// `decision` field absent entirely.
    const NO_DECISION_LINE: &str = r#"{"agent_id":"agent_codex","action":"x.y","resource":"r","deny_reason":"","token_id":"tok_a"}"#;

    #[test]
    fn unknown_decision_code_is_kept_and_classified_unknown() {
        let parsed: AuditLite = serde_json::from_str(UNKNOWN_DECISION_LINE).expect("parse unknown");
        assert_eq!(parsed.decision, Some(AuditLiteDecision::Unknown(7)));
        // No `--decision` filter selects an unknown code.
        assert!(
            audit_passes(
                UNKNOWN_DECISION_LINE,
                Some(DecisionFilter::Allow),
                None,
                None,
                None
            )
            .is_none()
        );
        // But the record still passes when no decision filter is set.
        assert!(audit_passes(UNKNOWN_DECISION_LINE, None, None, None, None).is_some());
    }

    #[test]
    fn absent_decision_field_is_none() {
        let parsed: AuditLite = serde_json::from_str(NO_DECISION_LINE).expect("parse no-decision");
        assert_eq!(parsed.decision, None);
    }

    #[test]
    fn decision_allow_filter_matches_allow_line() {
        assert!(audit_passes(ALLOW_LINE, Some(DecisionFilter::Allow), None, None, None).is_some());
        assert!(audit_passes(DENY_LINE, Some(DecisionFilter::Allow), None, None, None).is_none());
    }

    #[test]
    fn decision_deny_filter_matches_deny_line() {
        assert!(audit_passes(DENY_LINE, Some(DecisionFilter::Deny), None, None, None).is_some());
        assert!(audit_passes(ALLOW_LINE, Some(DecisionFilter::Deny), None, None, None).is_none());
    }

    #[test]
    fn decision_passthrough_requires_empty_token_id() {
        assert!(
            audit_passes(
                PASSTHROUGH_LINE,
                Some(DecisionFilter::Passthrough),
                None,
                None,
                None
            )
            .is_some()
        );
        assert!(
            audit_passes(
                ALLOW_LINE,
                Some(DecisionFilter::Passthrough),
                None,
                None,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn action_class_filter_matches_action_field() {
        assert!(audit_passes(ALLOW_LINE, None, Some("github.issue.create"), None, None).is_some());
        assert!(audit_passes(ALLOW_LINE, None, Some("other.class"), None, None).is_none());
    }

    /// AARM R4 remediation decisions on the wire: `4` = `MODIFY`, `5` = `STEP_UP`,
    /// `6` = `DEFER`. These are now recognized `Known` codes (not `Unknown`),
    /// and each `--decision` filter selects its own code.
    #[test]
    fn aarm_r4_decisions_are_known_and_filterable() {
        for (raw, expected, label) in [
            (4, AuditLiteDecision::Known(AuditDecision::Modify), "MODIFY"),
            (
                5,
                AuditLiteDecision::Known(AuditDecision::StepUp),
                "STEP_UP",
            ),
            (6, AuditLiteDecision::Known(AuditDecision::Defer), "DEFER"),
        ] {
            let line = format!(
                r#"{{"agent_id":"a","action":"x.y","resource":"r","decision":{raw},"deny_reason":"d","token_id":"t"}}"#
            );
            let parsed: AuditLite = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                parsed.decision,
                Some(expected),
                "code {raw} should be Known"
            );
            assert_eq!(parsed.decision.expect("present").to_string(), label);
        }

        // The forward-compat fallback still catches codes beyond the known
        // set; 7 remains Unknown (unchanged).
        let parsed: AuditLite =
            serde_json::from_str(UNKNOWN_DECISION_LINE).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.decision, Some(AuditLiteDecision::Unknown(7)));
    }

    #[test]
    fn decision_modify_step_up_defer_filters_select_their_codes() {
        let lines = [
            (
                4,
                r#"{"agent_id":"a","action":"x.y","resource":"r","decision":4,"deny_reason":"m","token_id":"t"}"#,
                DecisionFilter::Modify,
            ),
            (
                5,
                r#"{"agent_id":"a","action":"x.y","resource":"r","decision":5,"deny_reason":"s","token_id":"t"}"#,
                DecisionFilter::StepUp,
            ),
            (
                6,
                r#"{"agent_id":"a","action":"x.y","resource":"r","decision":6,"deny_reason":"d","token_id":"t"}"#,
                DecisionFilter::Defer,
            ),
        ];
        for (code, line, filter) in lines {
            // Its own filter selects it.
            assert!(
                audit_passes(line, Some(filter), None, None, None).is_some(),
                "code {code} should pass its own filter"
            );
            // A different remediation filter does not.
            let other = match filter {
                DecisionFilter::Modify => DecisionFilter::StepUp,
                _ => DecisionFilter::Modify,
            };
            assert!(
                audit_passes(line, Some(other), None, None, None).is_none(),
                "code {code} should not pass a different filter"
            );
        }
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
                Some(DecisionFilter::Deny),
                Some("stripe.payment.create"),
                Some("agent_codex"),
                None,
            )
            .is_some()
        );
        assert!(
            audit_passes(
                DENY_LINE,
                Some(DecisionFilter::Deny),
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
    const ALLOW_LINE_WITH_SANDBOX: &str = r#"{"event_id":"01900000-0000-7000-8000-000000000004","session_id":"sess_001","token_id":"tok_a","agent_id":"agent_codex","action":"github.issue.create","resource":"api.github.com/repos/x/y/issues","decision":1,"deny_reason":"","enforcement_latency_us":150,"context_hash":"ctx","bundle_version":"v1","timestamp":1715169755000000000,"dispatch_status":201,"dispatch_latency_us":42000,"response_size":128,"sandbox_id":"sbx_01j0000000e008000000000001","signature":[]}"#;

    #[test]
    fn audit_lite_parses_sandbox_id() {
        let parsed: AuditLite =
            serde_json::from_str(ALLOW_LINE_WITH_SANDBOX).expect("parse with sandbox");
        assert_eq!(
            parsed.sandbox_id.as_deref(),
            Some("sbx_01j0000000e008000000000001")
        );
    }

    #[test]
    fn sandbox_id_filter_matches_exact() {
        assert!(
            audit_passes(
                ALLOW_LINE_WITH_SANDBOX,
                None,
                None,
                None,
                Some("sbx_01j0000000e008000000000001")
            )
            .is_some()
        );
        assert!(
            audit_passes(
                ALLOW_LINE_WITH_SANDBOX,
                None,
                None,
                None,
                Some("sbx_01j0000000e008000000000002")
            )
            .is_none()
        );
    }

    #[test]
    fn sandbox_id_filter_rejects_missing_field() {
        assert!(
            audit_passes(
                ALLOW_LINE,
                None,
                None,
                None,
                Some("sbx_01j0000000e008000000000001")
            )
            .is_none()
        );
    }
}
