//! Fixture-based Cedar evaluation for `firma policy test <fixture.toml>`.
//!
//! Loads a fixture file, reads the referenced `*.cedar` bundle directory,
//! builds a Cedar request whose entity UIDs, schema, and context construction
//! exactly mirror the Sidecar hot path
//! ([`firma_sidecar` `cedar_evaluator`]), evaluates it, and compares the
//! decision against the fixture's expectation.
//!
//! The flow is fully local and fail-closed. Every failure mode — unreadable
//! or malformed fixture, missing or unparsable bundle, unparsable entity UID,
//! schema-rejected context, request-build failure — prints a diagnostic to
//! stderr and yields exit code `1`. Only a decision that matches the
//! fixture's `expected` prints the decision line to stdout and exits `0`.
//!
//! Relative `bundle.path` values are resolved against the fixture file's
//! parent directory, so `firma policy test path/to/fix.toml` works regardless
//! of the current working directory. Absolute bundle paths are used as-is.
//!
//! # Schema scope
//!
//! The canonical Firma schema declares fifteen *required* `EnforcementContext`
//! attributes. [`crate::policy::fixture::default_context`] supplies all
//! fifteen, mirroring the Sidecar hot path's `build_context` so a fixture
//! verdict equals the enforcement verdict for the equivalent plain request; a
//! fixture therefore needs no `[fixture.context]` block. Fixtures may still
//! override any attribute (or add others) via `[fixture.context]`; an unknown
//! or wrongly-typed key is rejected by Cedar's schema-strict context build,
//! which fail-closes here.

use std::path::Path;
use std::process::ExitCode;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request, Schema};
use firma_core::AgentId;
use firma_core::FirmaEntityUid;

use crate::policy::bundle;
use crate::policy::fixture::{Expected, Fixture};

/// Outcome of evaluating a fixture: the exit code plus the lines to emit.
///
/// `stdout` is the parseable decision line printed on the success path (and
/// also on a decision/expectation mismatch, so the actual decision is always
/// visible). `stderr` carries the human-readable failure or mismatch
/// explanation. Splitting this from [`run`] keeps behavior testable without
/// capturing process streams.
struct Outcome {
    code: ExitCode,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl Outcome {
    fn failure(message: String) -> Self {
        Self {
            code: ExitCode::from(1),
            stdout: None,
            stderr: Some(message),
        }
    }
}

/// Evaluate the fixture at `path` and report the result.
///
/// Prints the decision line to stdout and any diagnostic to stderr, returning
/// [`ExitCode::SUCCESS`] iff the decision matches the fixture's `expected`.
///
/// # Errors
///
/// Never returns `Err`: every failure is converted to a stderr diagnostic
/// plus a non-zero [`ExitCode`], keeping evaluation fail-closed. The
/// `anyhow::Result` return type matches sibling `firma` service entry points.
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the shared CLI service entry-point signature returning anyhow::Result<ExitCode>"
)]
pub fn run(path: &Path) -> anyhow::Result<ExitCode> {
    let outcome = evaluate_to_outcome(path);
    if let Some(stdout) = outcome.stdout {
        println!("{stdout}");
    }
    if let Some(stderr) = outcome.stderr {
        eprint!("{stderr}");
    }
    Ok(outcome.code)
}

/// Run the fixture pipeline and return the exit code plus output lines.
///
/// Mirrors the Sidecar hot path's UID, schema, context, and request
/// construction so a fixture verdict equals the enforcement verdict.
fn evaluate_to_outcome(path: &Path) -> Outcome {
    let fixture = match Fixture::from_path(path) {
        Ok(fixture) => fixture,
        Err(error) => return Outcome::failure(format!("error: {error}\n")),
    };

    // Resolve a relative bundle path against the fixture file's directory so
    // the command is ergonomic from any working directory.
    let bundle_dir = {
        let raw = Path::new(&fixture.bundle.path);
        if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            path.parent().unwrap_or_else(|| Path::new(".")).join(raw)
        }
    };

    let policy_set = match bundle::read_policy_set(&bundle_dir) {
        Ok(policy_set) => policy_set,
        Err(error) => return Outcome::failure(format!("error: {error}\n")),
    };

    let schema = match Schema::from_cedarschema_str(firma_core::cedar::FIRMA_SCHEMA) {
        Ok((schema, _warnings)) => schema,
        Err(error) => {
            return Outcome::failure(format!(
                "error: failed to parse embedded Firma schema: {error}\n"
            ));
        }
    };

    let (principal_uid, action_uid, resource_uid) = match build_uids(&fixture) {
        Ok(uids) => uids,
        Err(message) => return Outcome::failure(message),
    };

    let ctx_value = crate::policy::fixture::merged_context(&fixture.fixture.context);
    let cedar_context = match Context::from_json_value(ctx_value, Some((&schema, &action_uid))) {
        Ok(context) => context,
        Err(error) => {
            return Outcome::failure(format!(
                "error: failed to build Cedar context (schema-strict): {error}\n"
            ));
        }
    };

    let request = match Request::new(
        Some(principal_uid),
        Some(action_uid),
        Some(resource_uid),
        cedar_context,
        Some(&schema),
    ) {
        Ok(request) => request,
        Err(error) => {
            return Outcome::failure(format!("error: failed to build Cedar request: {error}\n"));
        }
    };

    let response = Authorizer::new().is_authorized(&request, &policy_set, &Entities::empty());

    let (decision, expected) = (response.decision(), fixture.fixture.expected);
    let decision_label = match decision {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
    };

    let reasons: Vec<String> = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    let reason_str = if reasons.is_empty() {
        "-".to_string()
    } else {
        reasons.join(",")
    };
    let stdout = format!("{decision_label} {reason_str}");

    let matches = matches!(
        (decision, expected),
        (Decision::Allow, Expected::Allow) | (Decision::Deny, Expected::Deny)
    );

    if matches {
        Outcome {
            code: ExitCode::SUCCESS,
            stdout: Some(stdout),
            stderr: None,
        }
    } else {
        Outcome {
            code: ExitCode::from(1),
            stdout: Some(stdout),
            stderr: Some(format!(
                "error: decision mismatch: expected {expected}, got {decision_label}\n"
            )),
        }
    }
}

/// Build the principal / action / resource Cedar UIDs from a fixture.
///
/// Mirrors the Sidecar hot path: the agent id is parsed into an
/// [`AgentId`] (enforcing the `[a-zA-Z0-9_-]{1,128}` shape) before becoming
/// a `Firma::Agent` UID; action class becomes a `Firma::Action` UID verbatim;
/// the resource host becomes a `Firma::Resource` UID. Any parse failure is
/// returned as a ready-to-print fail-closed diagnostic.
fn build_uids(fixture: &Fixture) -> Result<(EntityUid, EntityUid, EntityUid), String> {
    let agent_id = fixture
        .fixture
        .principal
        .agent_id
        .parse::<AgentId>()
        .map_err(|error| {
            format!(
                "error: invalid principal agent_id '{}': {error}\n",
                fixture.fixture.principal.agent_id
            )
        })?;

    let principal_uid: EntityUid = FirmaEntityUid::Agent(agent_id)
        .try_into()
        .map_err(|error| format!("error: invalid principal UID: {error}\n"))?;
    let action_uid: EntityUid = FirmaEntityUid::Action(fixture.fixture.action.class.clone())
        .try_into()
        .map_err(|error| format!("error: invalid action UID: {error}\n"))?;
    let resource_uid: EntityUid = FirmaEntityUid::Resource(fixture.fixture.resource.host.clone())
        .try_into()
        .map_err(|error| format!("error: invalid resource UID: {error}\n"))?;

    Ok((principal_uid, action_uid, resource_uid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_bundle(dir: &Path, contents: &str) {
        fs::write(dir.join("policy.cedar"), contents).expect("write bundle policy");
    }

    fn write_fixture(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("fixture.toml");
        fs::write(&path, body).expect("write fixture");
        path
    }

    #[test]
    fn allow_fixture_against_permit_all_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(tmp.path(), "permit(principal, action, resource);");
        // No `[fixture.context]`: the fifteen mirrored defaults satisfy the
        // schema-strict context build on their own.
        let body = r#"
[fixture]
expected = "ALLOW"
[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "api.github.com"
[bundle]
path = "."
"#;
        let fx = write_fixture(tmp.path(), body);
        let outcome = evaluate_to_outcome(&fx);
        assert_eq!(
            outcome.code,
            ExitCode::SUCCESS,
            "stderr={:?}",
            outcome.stderr
        );
        let stdout = outcome.stdout.expect("decision line");
        assert!(stdout.starts_with("ALLOW "), "got {stdout}");
        assert!(outcome.stderr.is_none());

        let code = run(&fx).expect("run returns Ok");
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn mismatch_expected_deny_but_allow_exits_one() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(tmp.path(), "permit(principal, action, resource);");
        let body = r#"
[fixture]
expected = "DENY"
[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "api.github.com"
[bundle]
path = "."
"#;
        let fx = write_fixture(tmp.path(), body);
        let outcome = evaluate_to_outcome(&fx);
        assert_eq!(outcome.code, ExitCode::from(1));
        let stderr = outcome.stderr.expect("mismatch diagnostic");
        assert!(
            stderr.contains("expected DENY") && stderr.contains("got ALLOW"),
            "got {stderr}"
        );
        // Decision line is still emitted for parseability.
        assert!(outcome.stdout.unwrap().starts_with("ALLOW "));
    }

    #[test]
    fn unknown_context_key_not_in_schema_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(tmp.path(), "permit(principal, action, resource);");
        // `not_a_schema_attr` is not declared on EnforcementContext, so the
        // schema-strict context build must reject it (fail-closed), NOT pass.
        let body = r#"
[fixture]
expected = "ALLOW"
[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "api.github.com"
[fixture.context]
not_a_schema_attr = 7
[bundle]
path = "."
"#;
        let fx = write_fixture(tmp.path(), body);
        let outcome = evaluate_to_outcome(&fx);
        assert_eq!(outcome.code, ExitCode::from(1));
        assert!(
            outcome
                .stderr
                .expect("schema rejection diagnostic")
                .contains("Cedar context"),
            "unknown context key must fail at schema-strict build"
        );
    }

    #[test]
    fn deny_fixture_against_forbid_all_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        write_bundle(tmp.path(), "forbid(principal, action, resource);");
        let body = r#"
[fixture]
expected = "DENY"
[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "api.github.com"
[bundle]
path = "."
"#;
        let fx = write_fixture(tmp.path(), body);
        let outcome = evaluate_to_outcome(&fx);
        assert_eq!(
            outcome.code,
            ExitCode::SUCCESS,
            "stderr={:?}",
            outcome.stderr
        );
        assert!(outcome.stdout.unwrap().starts_with("DENY"));
    }

    #[test]
    fn missing_fixture_file_fails_closed() {
        let outcome = evaluate_to_outcome(Path::new("/nonexistent/firma-fixture-xyz.toml"));
        assert_eq!(outcome.code, ExitCode::from(1));
        assert!(outcome.stderr.unwrap().contains("cannot read fixture"));
    }

    #[test]
    fn missing_bundle_dir_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let body = r#"
[fixture]
expected = "ALLOW"
[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "api.github.com"
[bundle]
path = "no-such-bundle"
"#;
        let fx = write_fixture(tmp.path(), body);
        let outcome = evaluate_to_outcome(&fx);
        assert_eq!(outcome.code, ExitCode::from(1));
        assert!(outcome.stderr.unwrap().contains("policy bundle directory"));
    }
}
