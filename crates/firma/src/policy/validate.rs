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

use cedar_policy::{PolicySet, Schema, ValidationMode, ValidationWarning, Validator};
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme, NamedSource};

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
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the shared CLI service entry-point signature returning anyhow::Result<ExitCode>"
)]
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

    let named_source = NamedSource::new(path.display().to_string(), source.clone());

    let policy_set = match source.parse::<PolicySet>() {
        Ok(policy_set) => policy_set,
        Err(errors) => {
            let mut rendered = format!(
                "error: failed to parse Cedar policy '{}':\n",
                path.display()
            );
            for error in errors.iter() {
                rendered.push_str(&render_diagnostic(error, &named_source));
            }
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
    // Cedar reports a policy whose scope matches no action as a warning since
    // 4.13; the Authority rejects it, so validation must too.
    let scope_matches_no_action = result
        .validation_warnings()
        .any(|warning| matches!(warning, ValidationWarning::InvalidActionApplication(_)));
    if !result.validation_passed() || scope_matches_no_action {
        let mut rendered = format!(
            "error: policy '{}' failed schema validation:\n",
            path.display()
        );
        // Render every diagnostic, not just the first.
        for validation_error in result.validation_errors() {
            rendered.push_str(&render_diagnostic(validation_error, &named_source));
        }
        for validation_warning in result.validation_warnings() {
            rendered.push_str(&render_diagnostic(validation_warning, &named_source));
        }
        return (ExitCode::from(1), Some(rendered));
    }

    (ExitCode::SUCCESS, None)
}

/// Render a single [`Diagnostic`] to a deterministic, no-color string.
///
/// Uses an ASCII, monochrome [`GraphicalReportHandler`] with links and
/// `docs.rs` URLs disabled so the output is stable across terminals and crate
/// versions. The handler renders the primary span as a `[name:line:col]`
/// header plus a caret snippet. On the unreachable path where the handler
/// fails to format, the diagnostic's `Display` form is used as a fail-closed
/// fallback so a location-less message is still surfaced.
fn render_diagnostic(diagnostic: &dyn Diagnostic, source: &NamedSource<String>) -> String {
    let handler = GraphicalReportHandler::new_themed(GraphicalTheme::none())
        .with_links(false)
        .with_urls(false);
    let named = WithFileSource { diagnostic, source };
    let mut rendered = String::new();
    if handler.render_report(&mut rendered, &named).is_err() {
        rendered = format!("{diagnostic}");
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

/// A Cedar diagnostic rendered against the policy file it came from.
///
/// Cedar diagnostics carry their own unnamed copy of the policy text, which
/// takes precedence over [`Report::with_source_code`](miette::Report), so the
/// handler would omit the file name and, for one-line snippets, the location.
/// This wrapper substitutes the named file source and delegates the rest.
#[derive(Debug)]
struct WithFileSource<'a> {
    diagnostic: &'a dyn Diagnostic,
    source: &'a NamedSource<String>,
}

impl std::fmt::Display for WithFileSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.diagnostic, f)
    }
}

impl std::error::Error for WithFileSource<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.diagnostic.source()
    }
}

impl Diagnostic for WithFileSource<'_> {
    fn code<'b>(&'b self) -> Option<Box<dyn std::fmt::Display + 'b>> {
        self.diagnostic.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.diagnostic.severity()
    }

    fn help<'b>(&'b self) -> Option<Box<dyn std::fmt::Display + 'b>> {
        self.diagnostic.help()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(self.source)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.diagnostic.labels()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.diagnostic.diagnostic_source()
    }
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
    fn scope_matching_no_action_fails_schema_check() {
        let policy = r#"permit(principal is Firma::Resource, action == Firma::Action::"filesystem.read", resource);"#;
        let file = write_policy(policy);
        let (code, diagnostic) = validate_to_outcome(file.path());
        assert_eq!(code, ExitCode::from(1));
        let rendered = diagnostic.expect("schema failure must produce a diagnostic");
        assert!(
            rendered.contains("unable to find an applicable action"),
            "missing the scope diagnostic; got:\n{rendered}"
        );
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
        let location = format!("[{}:", file.path().display());
        assert!(
            rendered.contains(&location),
            "snippet location must name the policy file; got:\n{rendered}"
        );
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
