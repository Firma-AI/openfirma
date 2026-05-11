//! Render monitor lines.

use std::io::{self, Write};

use crate::args::monitor::Format;
use crate::monitor::filters::{AuditLite, audit_passes};
use crate::monitor::tailer::{Line, Source};

pub fn render(
    line: &Line,
    format: Format,
    decision_filter: Option<crate::args::monitor::Decision>,
    action_class_filter: Option<&str>,
    out: &mut dyn Write,
) -> io::Result<()> {
    match (line.source, format) {
        (Source::Audit, Format::Pretty) => {
            if let Some(parsed) = audit_passes(&line.raw, decision_filter, action_class_filter) {
                writeln!(out, "[audit] {}", render_audit_pretty(&parsed, &line.raw))?;
            }
        }
        (Source::Audit, Format::Json) => {
            if audit_passes(&line.raw, decision_filter, action_class_filter).is_some() {
                writeln!(
                    out,
                    "{{\"source\":\"audit\",\"raw\":{}}}",
                    json_escape(&line.raw)
                )?;
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

fn render_audit_pretty(parsed: &AuditLite, raw: &str) -> String {
    let decision = parsed
        .decision
        .clone()
        .unwrap_or_else(|| "?".into())
        .to_uppercase();
    let class = parsed
        .intent
        .as_ref()
        .and_then(|intent| intent.action_class.as_deref())
        .unwrap_or("?");
    format!("{decision:<7} class={class} raw={raw}")
}

fn json_escape(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}
