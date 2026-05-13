//! Render monitor lines.
//!
//! Audit lines go through filter-then-encode; non-audit (authority,
//! sidecar) lines are wrapped untouched. Pretty rendering for audit
//! follows the v0.5 spec layout:
//!
//! ```text
//! <rfc3339-UTC-ts>  <DECISION>  <METHOD>  <resource>  class=<action>  agent=<agent_id>[  reason=<deny_reason>]
//! ```
//!
//! `<METHOD>` is best-effort: extracted from `action` when it has the
//! `raw.http.<METHOD>` form, otherwise rendered as `-`.

use std::io::{self, Write};

use chrono::{DateTime, SecondsFormat, Utc};

use crate::args::monitor::Format;
use crate::monitor::filters::{AuditLite, audit_passes};
use crate::monitor::tailer::{Line, Source};

const MISSING: &str = "?";

/// Render a single tailed line to `out`.
///
/// Audit lines are first parsed and filtered by `decision_filter`,
/// `action_class_filter`, and `agent_filter`. Authority and sidecar
/// lines are emitted unconditionally (filters do not apply).
pub fn render(
    line: &Line,
    format: Format,
    decision_filter: Option<crate::args::monitor::Decision>,
    action_class_filter: Option<&str>,
    agent_filter: Option<&str>,
    out: &mut dyn Write,
) -> io::Result<()> {
    match (line.source, format) {
        (Source::Audit, Format::Pretty) => {
            if let Some(parsed) = audit_passes(
                &line.raw,
                decision_filter,
                action_class_filter,
                agent_filter,
            ) {
                writeln!(out, "{}", render_audit_pretty(&parsed))?;
            }
        }
        (Source::Audit, Format::Json) => {
            if audit_passes(
                &line.raw,
                decision_filter,
                action_class_filter,
                agent_filter,
            )
            .is_some()
            {
                writeln!(out, "{}", line.raw)?;
            }
        }
        (Source::Authority, Format::Pretty) => {
            writeln!(out, "[authority] {}", line.raw)?;
        }
        (Source::Sidecar, Format::Pretty) => {
            writeln!(out, "[sidecar] {}", line.raw)?;
        }
        (Source::Authority, Format::Json) => {
            writeln!(
                out,
                "{{\"source\":\"authority\",\"raw\":{}}}",
                json_escape(&line.raw)
            )?;
        }
        (Source::Sidecar, Format::Json) => {
            writeln!(
                out,
                "{{\"source\":\"sidecar\",\"raw\":{}}}",
                json_escape(&line.raw)
            )?;
        }
    }
    Ok(())
}

fn render_audit_pretty(parsed: &AuditLite) -> String {
    let timestamp = parsed.timestamp.map_or_else(
        || MISSING.to_string(),
        |nanos| format_timestamp_nanos(nanos).unwrap_or_else(|| MISSING.to_string()),
    );
    let decision = format!("{:<7}", decision_label(parsed.decision));
    let method = method_from_action(parsed.action.as_deref());
    let resource = parsed.resource.as_deref().unwrap_or(MISSING);
    let action = parsed.action.as_deref().unwrap_or(MISSING);
    let agent = parsed.agent_id.as_deref().unwrap_or(MISSING);

    let mut line =
        format!("{timestamp}  {decision}  {method}  {resource}  class={action}  agent={agent}");
    if parsed.decision == Some(2)
        && let Some(reason) = parsed.deny_reason.as_deref()
        && !reason.is_empty()
    {
        line.push_str("  reason=");
        line.push_str(reason);
    }
    line
}

fn decision_label(decision: Option<i32>) -> &'static str {
    match decision {
        Some(1) => "ALLOW",
        Some(2) => "DENY",
        Some(3) => "ABORT",
        _ => MISSING,
    }
}

fn method_from_action(action: Option<&str>) -> &str {
    action
        .and_then(|value| value.strip_prefix("raw.http."))
        .unwrap_or("-")
}

fn format_timestamp_nanos(nanos: u128) -> Option<String> {
    let nanos: i64 = nanos.try_into().ok()?;
    let dt: DateTime<Utc> = DateTime::from_timestamp_nanos(nanos);
    Some(dt.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn json_escape(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::args::monitor::{Decision, Format};

    const ALLOW_LINE: &str = r#"{"event_id":"e1","session_id":"s","token_id":"t","agent_id":"demo-1","action":"github.issue.create","resource":"api.github.com/repos/x/y/issues","decision":1,"deny_reason":"","enforcement_latency_us":150,"context_hash":"","bundle_version":"","timestamp":1715177751000000000,"dispatch_status":201,"dispatch_latency_us":42000,"response_size":128,"signature":[]}"#;

    const DENY_LINE: &str = r#"{"event_id":"e2","session_id":"s","token_id":"t","agent_id":"demo-1","action":"stripe.payment.create","resource":"api.stripe.com/v1/charges","decision":2,"deny_reason":"scope_mismatch","enforcement_latency_us":80,"context_hash":"","bundle_version":"","timestamp":1715177753000000000,"dispatch_status":0,"dispatch_latency_us":0,"response_size":0,"signature":[]}"#;

    const RAW_HTTP_LINE: &str = r#"{"event_id":"e3","session_id":"s","token_id":"","agent_id":"","action":"raw.http.GET","resource":"example.com/","decision":1,"deny_reason":"","enforcement_latency_us":5,"context_hash":"","bundle_version":"","timestamp":1715177754000000000,"dispatch_status":200,"dispatch_latency_us":1000,"response_size":0,"signature":[]}"#;

    fn render_to_string(raw: &str, source: Source, format: Format) -> String {
        let line = Line {
            source,
            raw: raw.to_string(),
        };
        let mut buf: Vec<u8> = Vec::new();
        render(&line, format, None, None, None, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn pretty_audit_allow_includes_timestamp_decision_method_resource_class_agent() {
        let out = render_to_string(ALLOW_LINE, Source::Audit, Format::Pretty);
        assert!(out.starts_with("2024-05-08T14:15:51Z  ALLOW"), "got: {out}");
        assert!(
            out.contains("  -  api.github.com/repos/x/y/issues"),
            "got: {out}"
        );
        assert!(out.contains("class=github.issue.create"), "got: {out}");
        assert!(out.contains("agent=demo-1"), "got: {out}");
    }

    #[test]
    fn pretty_audit_deny_appends_reason() {
        let out = render_to_string(DENY_LINE, Source::Audit, Format::Pretty);
        assert!(out.contains("DENY"), "got: {out}");
        assert!(out.contains("reason=scope_mismatch"), "got: {out}");
    }

    #[test]
    fn pretty_audit_raw_http_extracts_method() {
        let out = render_to_string(RAW_HTTP_LINE, Source::Audit, Format::Pretty);
        assert!(out.contains("  GET  example.com/"), "got: {out}");
    }

    #[test]
    fn json_audit_pass_through_is_byte_equal_to_input_plus_newline() {
        let out = render_to_string(ALLOW_LINE, Source::Audit, Format::Json);
        assert_eq!(out, format!("{ALLOW_LINE}\n"));
    }

    #[test]
    fn pretty_authority_keeps_bracketed_prefix() {
        let line = Line {
            source: Source::Authority,
            raw: "authority booted".into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        render(&line, Format::Pretty, None, None, None, &mut buf).expect("render");
        assert_eq!(buf, b"[authority] authority booted\n");
    }

    #[test]
    fn filter_skips_non_matching_audit_line() {
        let line = Line {
            source: Source::Audit,
            raw: ALLOW_LINE.into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        render(
            &line,
            Format::Pretty,
            Some(Decision::Deny),
            None,
            None,
            &mut buf,
        )
        .expect("render");
        assert!(
            buf.is_empty(),
            "expected filtered line to produce no output"
        );
    }
}
