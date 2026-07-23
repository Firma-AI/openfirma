//! Pretty / JSON renderers for the doctor report.

use std::io::{self, Write};

use owo_colors::{OwoColorize as _, Stream};

use crate::doctor::report::{Check, Report, Status};

/// Render `report` in pretty form to `out`.
pub fn pretty(report: &Report, out: &mut dyn Write) -> io::Result<()> {
    pretty_with_color(report, out, false)
}

/// Render `report` in pretty form with terminal color enabled.
pub fn pretty_for_stdout(report: &Report, out: &mut dyn Write) -> io::Result<()> {
    pretty_with_color(report, out, true)
}

fn pretty_with_color(report: &Report, out: &mut dyn Write, color: bool) -> io::Result<()> {
    writeln!(out, "firma doctor")?;
    writeln!(out, "=============")?;
    for check in &report.checks {
        writeln!(out, "{}", format_check(check, color))?;
    }
    Ok(())
}

fn format_check(check: &Check, color: bool) -> String {
    let tag = match check.status {
        Status::Ok if color => format!(
            "{}",
            "[OK]  ".if_supports_color(Stream::Stdout, |t| t.green())
        ),
        Status::Warn if color => format!(
            "{}",
            "[WARN]".if_supports_color(Stream::Stdout, |t| t.yellow())
        ),
        Status::Fail if color => format!(
            "{}",
            "[FAIL]".if_supports_color(Stream::Stdout, |t| t.bright_red())
        ),
        Status::Ok => "[OK]  ".to_string(),
        Status::Warn => "[WARN]".to_string(),
        Status::Fail => "[FAIL]".to_string(),
    };
    format!("{tag} {:<22} {}", check.category, check.reason)
}

/// Render `report` as a single JSON object to `out`. Always emits a trailing newline.
pub fn json(report: &Report, out: &mut dyn Write) -> io::Result<()> {
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        checks: &'a [Check],
        worst: Option<Status>,
        exit_code: u8,
    }
    let envelope = Envelope {
        checks: &report.checks,
        worst: report.worst(),
        exit_code: report.exit_code(),
    };
    let encoded = serde_json::to_string(&envelope).map_err(|e| io::Error::other(e.to_string()))?;
    writeln!(out, "{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn sample_report() -> Report {
        let mut r = Report::default();
        r.push(Check::ok("firma binary", "/usr/local/bin/firma (v0.1.0)"));
        r.push(Check::warn(
            "sandbox vz",
            "framework available on macOS 13+; run-time probe not implemented",
        ));
        r.push(Check::fail(
            "authority reachable",
            "127.0.0.1:50051: connection refused",
        ));
        r
    }

    #[test]
    fn pretty_renders_header_and_three_lines() {
        let mut buf = Vec::new();
        pretty(&sample_report(), &mut buf).expect("render");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(
            out.starts_with("firma doctor\n=============\n"),
            "got: {out}"
        );
        assert!(out.contains("[OK]   firma binary"), "got: {out}");
        assert!(out.contains("[WARN] sandbox vz"), "got: {out}");
        assert!(out.contains("[FAIL] authority reachable"), "got: {out}");
    }

    #[test]
    fn json_emits_worst_and_exit_code() {
        let mut buf = Vec::new();
        json(&sample_report(), &mut buf).expect("render");
        let out = String::from_utf8(buf).expect("utf8");
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert_eq!(parsed["exit_code"], 1);
        assert_eq!(parsed["worst"], "fail");
        assert_eq!(parsed["checks"].as_array().expect("array").len(), 3);
    }

    #[test]
    fn json_ends_with_newline() {
        let mut buf = Vec::new();
        json(&sample_report(), &mut buf).expect("render");
        assert!(buf.ends_with(b"\n"));
    }
}
