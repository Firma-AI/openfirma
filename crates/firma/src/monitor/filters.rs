//! Post-parse filters for audit lines.

use serde::Deserialize;

use crate::args::monitor::Decision;

/// Minimal projection of an audit record needed by the monitor filters.
///
/// Deliberately uses owned `String` and is decoupled from the canonical audit
/// record types in `firma-sidecar`; `firma monitor` reads audit lines as
/// opaque JSON and only requires two fields to filter on. Fields not listed
/// here are silently ignored during deserialization.
#[derive(Debug, Deserialize)]
pub struct AuditLite {
    /// `decision` field of the audit record, when present.
    pub decision: Option<String>,
    /// Nested `intent` object, when present.
    pub intent: Option<IntentLite>,
}

/// Subset of the `intent` block carried inside [`AuditLite`].
#[derive(Debug, Deserialize)]
pub struct IntentLite {
    /// `action_class` string used by the `--action-class` filter.
    pub action_class: Option<String>,
}

/// Return `Some(parsed_audit)` if `raw` is a valid audit-record JSON line
/// AND passes the user-supplied `--decision` and `--action-class` filters;
/// return `None` otherwise.
pub fn audit_passes(
    raw: &str,
    decision: Option<Decision>,
    action_class: Option<&str>,
) -> Option<AuditLite> {
    let parsed: AuditLite = serde_json::from_str(raw).ok()?;
    if let Some(want) = decision {
        let want_str = match want {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Passthrough => "passthrough",
        };
        match &parsed.decision {
            Some(got) if got.eq_ignore_ascii_case(want_str) => {}
            _ => return None,
        }
    }
    if let Some(want) = action_class {
        let got = parsed
            .intent
            .as_ref()
            .and_then(|intent| intent.action_class.as_deref());
        if got != Some(want) {
            return None;
        }
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_decision_and_class() {
        let line = r#"{"decision":"allow","intent":{"action_class":"github.issue.create"}}"#;
        assert!(audit_passes(line, Some(Decision::Allow), Some("github.issue.create")).is_some());
        assert!(audit_passes(line, Some(Decision::Deny), None).is_none());
        assert!(audit_passes(line, None, Some("other.class")).is_none());
    }
}
