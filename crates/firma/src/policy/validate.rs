//! Parse and schema-check a Cedar policy file (`firma policy validate`).
//!
//! Implements the offline `firma policy validate <file.cedar>` flow: read the
//! file, parse it into a [`cedar_policy::PolicySet`], parse the canonical
//! Firma schema, then strictly type-check the policy set against that schema.
//!
//! The flow is fully local and fail-closed. Every failure path (I/O, parse,
//! schema, validation) prints a human-readable diagnostic to stderr and yields
//! exit code `1`. Parse and schema-validation diagnostics are rendered through
//! a deterministic, no-color [`miette::GraphicalReportHandler`] with the policy
//! source attached, so every diagnostic carries a `[name:line:col]` location
//! and a caret snippet. Only a fully valid policy prints `OK` to stdout and
//! yields exit code `0`.

use std::path::Path;
use std::process::ExitCode;

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme, NamedSource, Report};

/// Parse and schema-check the Cedar policy file at `path`.
///
/// Reads the file, parses it as a [`PolicySet`], parses the embedded Firma
/// schema, and strictly validates the policy set against it. On success
/// prints `OK` to stdout and returns [`ExitCode::SUCCESS`]. Every failure
/// prints a diagnostic to stderr and returns exit code `1`.
///
/// # Errors
///
/// This function never returns `Err`: all failure modes are converted to a
/// stderr diagnostic plus a non-zero [`ExitCode`], keeping enforcement
/// fail-closed. The `anyhow::Result` return type matches sibling service
/// entry points so `main.rs` can dispatch uniformly.
// The `Result` wrapper is intentional and not removable: it is the shared
// contract for `firma` service entry points dispatched by `main.rs`, and the
// sibling `PolicyCommand::Test` arm in `services::policy` does return `Err`.
#[allow(clippy::unnecessary_wraps)]
pub fn run(path: &Path) -> anyhow::Result<ExitCode> {
    let (code, diagnostic) = validate_to_outcome(path);
    if let Some(diagnostic) = diagnostic {
        eprint!("{diagnostic}");
    } else {
        crate::output::ok("policy validated");
    }
    Ok(code)
}

/// Run the validation pipeline and return the exit code plus an optional
/// rendered diagnostic.
///
/// Returns `(ExitCode::SUCCESS, None)` when the policy is valid. Every failure
/// mode (I/O, parse, schema load, schema validation) returns
/// `(ExitCode::from(1), Some(rendered))` where `rendered` is the full,
/// human-readable diagnostic — already terminated by a newline — that `run`
/// writes to stderr. Splitting this out keeps the rendered text testable
/// without capturing process stderr while preserving fail-closed behavior.
fn validate_to_outcome(path: &Path) -> (ExitCode, Option<String>) {
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            return (
                ExitCode::from(1),
                Some(format!(
                    "error: cannot read '{}': {error}\n",
                    path.display()
                )),
            );
        }
    };

    let source_name = path.display().to_string();

    let policy_set = match source.parse::<PolicySet>() {
        Ok(policy_set) => policy_set,
        Err(errors) => {
            let report = Report::new(errors)
                .with_source_code(NamedSource::new(&source_name, source.clone()));
            let mut rendered = format!(
                "error: failed to parse Cedar policy '{}':\n",
                path.display()
            );
            rendered.push_str(&render_diagnostic(report.as_ref()));
            return (ExitCode::from(1), Some(rendered));
        }
    };

    let schema = match Schema::from_cedarschema_str(firma_core::cedar::FIRMA_SCHEMA) {
        Ok((schema, _warnings)) => schema,
        Err(error) => {
            return (
                ExitCode::from(1),
                Some(format!(
                    "error: failed to parse embedded Firma schema: {error}\n"
                )),
            );
        }
    };

    let result = Validator::new(schema).validate(&policy_set, ValidationMode::Strict);
    if !result.validation_passed() {
        let mut rendered = format!(
            "error: policy '{}' failed schema validation:\n",
            path.display()
        );
        // Validation errors and warnings carry their own source code, so the
        // graphical handler renders `[name:line:col]` plus a caret snippet
        // directly. Render every diagnostic, not just the first.
        for validation_error in result.validation_errors() {
            rendered.push_str(&render_diagnostic(validation_error));
        }
        for validation_warning in result.validation_warnings() {
            rendered.push_str(&render_diagnostic(validation_warning));
        }
        return (ExitCode::from(1), Some(rendered));
    }

    (ExitCode::SUCCESS, None)
}

/// Render a single [`Diagnostic`] to a deterministic, no-color string.
///
/// Uses an ASCII, monochrome [`GraphicalReportHandler`] with links and
/// `docs.rs` URLs disabled so the output is stable across terminals and crate
/// versions. The handler renders the primary span — and any `related`
/// sub-diagnostics — as a `[name:line:col]` header plus a caret snippet,
/// provided the source code is reachable from the diagnostic (attached via
/// [`Report::with_source_code`] for parse errors, or carried intrinsically by
/// Cedar validation diagnostics). On the unreachable path where the handler
/// fails to format, the diagnostic's `Display` form is used as a fail-closed
/// fallback so a location-less message is still surfaced.
fn render_diagnostic(diagnostic: &dyn Diagnostic) -> String {
    let handler = GraphicalReportHandler::new_themed(GraphicalTheme::none())
        .with_links(false)
        .with_urls(false);
    let mut rendered = String::new();
    if handler.render_report(&mut rendered, diagnostic).is_err() {
        rendered = format!("{diagnostic}");
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_policy(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new()
            .suffix(".cedar")
            .tempfile()
            .expect("create temp policy file");
        file.write_all(contents.as_bytes())
            .expect("write temp policy");
        file.flush().expect("flush temp policy");
        file
    }

    /// Assert the rendered diagnostic encodes a source location with BOTH a
    /// line and a column. The graphical handler emits the primary span as a
    /// `[line:col]` (or `[name:line:col]`) header, so a bracketed pair of
    /// colon-separated integers proves line and column are present and is not
    /// merely a byte offset.
    fn assert_has_line_and_column(rendered: &str) {
        let has_line_col = rendered
            .match_indices('[')
            .filter_map(|(open, _)| {
                let close = rendered[open..].find(']')? + open;
                Some(&rendered[open + 1..close])
            })
            .any(|inner| {
                // Trailing two `:`-separated parts must be line and column
                // integers (`name` prefix, if any, is ignored).
                let mut parts = inner.rsplitn(3, ':');
                let col = parts.next();
                let line = parts.next();
                matches!(
                    (line, col),
                    (Some(line), Some(col))
                        if !line.is_empty()
                            && line.bytes().all(|b| b.is_ascii_digit())
                            && !col.is_empty()
                            && col.bytes().all(|b| b.is_ascii_digit())
                )
            });
        assert!(
            has_line_col,
            "diagnostic must contain a `[line:col]` location with both \
             line and column; got:\n{rendered}"
        );
    }

    #[test]
    fn good_policy_validates() {
        // Uses a real action from `firma.cedarschema` and a context attribute
        // declared on `EnforcementContext`.
        let policy = r#"
            permit(
                principal,
                action == Firma::Action::"payment.transfer",
                resource
            ) when { context.transfer_amount <= 1000 };
        "#;
        let file = write_policy(policy);
        let (code, diagnostic) = validate_to_outcome(file.path());
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            diagnostic.is_none(),
            "valid policy must produce no diagnostic"
        );
        let code = run(file.path()).expect("run returns Ok");
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn syntactically_invalid_policy_fails() {
        let file = write_policy("permit(principal action, resource;");
        let (code, diagnostic) = validate_to_outcome(file.path());
        assert_eq!(code, ExitCode::from(1));
        let rendered = diagnostic.expect("parse failure must produce a diagnostic");
        assert!(
            rendered.contains("failed to parse Cedar policy"),
            "missing parse error header; got:\n{rendered}"
        );
        assert_has_line_and_column(&rendered);
    }

    #[test]
    fn unknown_action_uid_fails_schema_check() {
        // Syntactically valid, but `Firma::Action::"does.not.exist"` is not
        // declared in the Firma schema, so strict validation rejects it.
        let policy = r#"
            permit(
                principal,
                action == Firma::Action::"does.not.exist",
                resource
            );
        "#;
        let file = write_policy(policy);
        let (code, diagnostic) = validate_to_outcome(file.path());
        assert_eq!(code, ExitCode::from(1));
        let rendered = diagnostic.expect("schema failure must produce a diagnostic");
        assert!(
            rendered.contains("failed schema validation"),
            "missing schema error header; got:\n{rendered}"
        );
        assert_has_line_and_column(&rendered);
    }

    #[test]
    fn wrong_context_attr_type_fails_schema_check() {
        // `context.transfer_amount` is a `Long`; comparing it to a string is
        // a strict type error against `EnforcementContext`.
        let policy = r#"
            permit(
                principal,
                action == Firma::Action::"payment.transfer",
                resource
            ) when { context.transfer_amount == "lots" };
        "#;
        let file = write_policy(policy);
        let (code, diagnostic) = validate_to_outcome(file.path());
        assert_eq!(code, ExitCode::from(1));
        let rendered = diagnostic.expect("schema failure must produce a diagnostic");
        assert_has_line_and_column(&rendered);
    }

    #[test]
    fn missing_file_fails() {
        let path = Path::new("/nonexistent/firma-policy-validate/missing.cedar");
        let (code, diagnostic) = validate_to_outcome(path);
        assert_eq!(code, ExitCode::from(1));
        let rendered = diagnostic.expect("missing file must produce a diagnostic");
        assert!(
            rendered.contains("cannot read"),
            "missing-file diagnostic should mention the read failure; got:\n{rendered}"
        );
        let code = run(path).expect("run returns Ok");
        assert_eq!(code, ExitCode::from(1));
    }
}
