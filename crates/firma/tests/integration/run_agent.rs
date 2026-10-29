//! `firma run --agent` CLI boundary, against a test double of the Control
//! Plane's token, Agent resolution, run start and close endpoints. The
//! real Authority is covered by the Firma Team end-to-end suite.

use std::process::{Command, Output};

#[cfg(target_os = "linux")]
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

#[cfg(unix)]
use crate::logout::saved_login;
#[cfg(target_os = "linux")]
use crate::logout::{REFRESH_TOKEN, file_backed_login};

#[cfg(target_os = "linux")]
const TOKEN: &str = "/api/agent-flow/v1/authorizations/token";
#[cfg(target_os = "linux")]
const ACCESS_TOKEN: &str = "run-agent-test-access-token";
#[cfg(target_os = "linux")]
const ROTATED: &str = "run-agent-test-rotated-refresh-token";
#[cfg(target_os = "linux")]
const RUN: &str = "run_01j0000000e008000000000001";
#[cfg(target_os = "linux")]
const RUNTIME_CREDENTIAL: &str = "run-agent-test-runtime-credential-43-chars-xx";

fn firma(args: &[&str], connection_dir: &std::path::Path) -> Result<Output, std::io::Error> {
    Command::new(crate::firma_bin())
        .args(args)
        .env("FIRMA_CONNECTION_DIR", connection_dir)
        .env_remove("FIRMA_CONFIG")
        .output()
}

#[test]
fn a_command_line_config_conflicts_with_agent() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    let output = firma(
        &[
            "run",
            "-c",
            "firma.toml",
            "--agent",
            "build-bot",
            "--",
            "true",
        ],
        &dir,
    )?;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    insta::assert_snapshot!(String::from_utf8(output.stderr)?.lines().next().unwrap_or_default(), @"error: the argument '--config <CONFIG>' cannot be used with '--agent <HANDLE>'");
    assert!(!dir.exists(), "no login is read");
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_session_override_is_refused_before_anything_is_started()
-> Result<(), Box<dyn std::error::Error>> {
    // A Control Plane that must never be asked anything.
    let server = MockServer::start().await;
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    file_backed_login(&dir, &format!("{}/", server.uri()))?;

    let output = tokio::task::spawn_blocking({
        let dir = dir.clone();
        move || {
            Command::new(crate::firma_bin())
                .args(["run", "--agent", "build-bot", "--", "true"])
                .env("FIRMA_CONNECTION_DIR", dir)
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
                .env("FIRMA_RUN_SESSION_ID", "ses_mine")
                .output()
        }
    })
    .await??;

    assert_eq!(output.status.code(), Some(1));
    insta::assert_snapshot!(String::from_utf8(output.stderr)?, @"[ERR]  FIRMA_RUN_SESSION_ID cannot override the run a managed run reports under; unset it before starting `firma run --agent`\n");
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "nothing was started"
    );
    Ok(())
}

#[test]
fn local_options_conflict_with_agent() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    for option in [
        "--profile=codex",
        "--backend=bwrap",
        "--capability-file=seed.toml",
        "--identity-mode=host-user",
        "--preserve-host-user",
        "--print-effective-config",
        "--sidecar=local",
        "--no-autostart",
        "--sidecar-startup-timeout-secs=10",
        "--authority=local",
        "--authority-profile=default",
        "--allow-non-structural",
    ] {
        let output = firma(&["run", "--agent", "build-bot", option, "--", "true"], &dir)?;
        assert_eq!(output.status.code(), Some(2), "{option}");
        assert_eq!(output.stdout, [] as [u8; 0]);
        let stderr = String::from_utf8(output.stderr)?;
        let diagnostic = stderr.split("Usage:").next().unwrap_or_default().trim_end();
        insta::allow_duplicates! {
        insta::assert_snapshot!(diagnostic, @"
        error: the argument '--agent <HANDLE>' cannot be used with:
          --profile <PROFILE>
          --backend <BACKEND>
          --capability-file <CAPABILITY_FILE>
          --identity-mode <IDENTITY_MODE>
          --preserve-host-user
          --print-effective-config
          --sidecar <SIDECAR>
          --no-autostart
          --sidecar-startup-timeout-secs <SIDECAR_STARTUP_TIMEOUT_SECS>
          --authority <AUTHORITY>
          --authority-profile <AUTHORITY_PROFILE>
          --allow-non-structural
        ");
        }
    }
    assert!(!dir.exists(), "no login is read");
    Ok(())
}

#[test]
fn without_a_saved_login_it_says_to_log_in() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");

    let output = firma(&["run", "--agent", "build-bot", "--", "true"], &dir)?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "[ERR]  no login is saved; run `firma login`\n"
    );
    assert!(!dir.exists(), "nothing is created");
    Ok(())
}

/// A renewal that rotates the saved refresh credential to [`ROTATED`].
#[cfg(target_os = "linux")]
fn token_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": ACCESS_TOKEN,
        "refresh_token": ROTATED,
        "token_type": "Bearer",
        "expires_in": 600,
        "workspace_id": "wsp_01j0000000e008000000000001",
        "membership_id": "mem_01j0000000e008000000000001",
    }))
}

/// The Agent `build-bot` as the Control Plane describes it, named `name`.
#[cfg(target_os = "linux")]
fn resolved_agent(name: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "agt_01j0000000e008000000000001",
        "handle": "build-bot",
        "name": name,
        "profile_id": "claude-code",
        "policy_set_id": "pset_01j0000000e008000000000001",
    })
}

/// A Control Plane that resolves `build-bot` with a display name holding a
/// terminal escape sequence and an Authority nothing listens at, starts one
/// run of it, and closes it as failed. The saved login is
/// renewed once: the close reuses the access token.
#[cfg(target_os = "linux")]
async fn control_plane() -> MockServer {
    control_plane_answering(started(), "failed", closed("failed"), 1).await
}

/// The successful start of [`RUN`].
#[cfg(target_os = "linux")]
fn started() -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(serde_json::json!({
        "contract_version": 1,
        "run": {
            "id": RUN,
            "agent_id": "agt_01j0000000e008000000000001",
            "state": "active",
            "desired_generation": "42",
            "outcome": null,
            "terminated_at": null,
            "sidecar_id": "sc_01j0000000e008000000000001",
            "expires_at": "2026-09-10T09:02:10Z",
        },
        "runtime_credential": {
            "token_type": "Bearer",
            "access_token": RUNTIME_CREDENTIAL,
        },
    }))
}

/// A close of [`RUN`] that the Control Plane recorded as `outcome`.
#[cfg(target_os = "linux")]
fn closed(outcome: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "contract_version": 1,
        "run": {
            "id": RUN,
            "state": "terminal",
            "outcome": outcome,
        },
    }))
}

/// [`control_plane`], answering the start with `start` and each of
/// `close_attempts` closes that request `requested` with `close`.
#[cfg(target_os = "linux")]
async fn control_plane_answering(
    start: ResponseTemplate,
    requested: &str,
    close: ResponseTemplate,
    close_attempts: u64,
) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN))
        .respond_with(token_response())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent-flow/v1/agents/build-bot"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(header("firma-agent-flow-version", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "contract_version": 1,
            "agent": resolved_agent("Luca's \u{1b}[2J \u{202e}tob\u{61c}\u{2028}"),
            "configuration": {
                "generation": "42",
                "authority_grpc_uri": "http://127.0.0.1:9/",
                "capability_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/agent-flow/v1/runs"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(header("firma-agent-flow-version", "1"))
        .and(header("content-type", "application/json"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "agent_handle": "build-bot",
            "resolved_configuration_generation": "42",
        })))
        .respond_with(start)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/agent-flow/v1/runs/{RUN}/close")))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "outcome": requested }),
        ))
        .respond_with(close)
        .expect(close_attempts)
        .mount(&server)
        .await;
    server
}

// Linux only: elsewhere the renewal is saved to the platform credential
// store, which this test must not touch.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_started_run_is_reported_then_the_launch_fails_without_an_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane().await;
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    file_backed_login(&dir, &format!("{}/", server.uri()))?;
    let project = tempfile::tempdir()?;
    let marker = project.path().join("started");
    let log = root.path().join("firma.log");
    let state = root.path().join("state");
    let shell = ["sh", "-c", "touch \"$MARKER\""];
    // Positive control: the wrapped command does create the marker.
    assert!(
        Command::new(shell[0])
            .args(&shell[1..])
            .env("MARKER", &marker)
            .status()?
            .success()
    );
    std::fs::remove_file(&marker)?;

    let log_arg = log.to_str().ok_or("log path")?;
    let output = tokio::task::spawn_blocking({
        let dir = dir.clone();
        let project = project.path().to_owned();
        let marker = marker.clone();
        let log_arg = log_arg.to_owned();
        let state = state.clone();
        move || {
            Command::new(crate::firma_bin())
                .args(["--log-file", &log_arg, "--log-filter", "trace"])
                .args(["run", "--agent", "build-bot", "--"])
                .args(shell)
                .current_dir(project)
                .env("FIRMA_CONNECTION_DIR", dir)
                // No credential service: the renewal stays in the file backend
                // instead of the host's keyring.
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
                // An exported governance file does not block a managed run.
                .env("FIRMA_CONFIG", "/nonexistent/firma.toml")
                .env("FIRMA_STATE_DIR", state)
                // A proxy-only backend (WSL2) still reaches the mint.
                .env("FIRMA_RUN_ALLOW_NON_STRUCTURAL", "1")
                .env("MARKER", marker)
                .output()
        }
    })
    .await??;

    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert_eq!(stdout, "");
    let (report, diagnostic) = stderr.split_once("[ERR]  ").ok_or("missing launch error")?;
    insta::assert_snapshot!(report, @r#"
    Agent:      build-bot (agt_01j0000000e008000000000001)
    Name:       "Luca's \u{1b}[2J \u{202e}tob\u{61c}\u{2028}"
    Profile:    claude-code
    Policy Set: "pset_01j0000000e008000000000001"
    Workspace:  wsp_01j0000000e008000000000001
    Generation: 42
    Run:  run_01j0000000e008000000000001
    Sidecar:    sc_01j0000000e008000000000001
    "#);
    // The launch is attempted only once the run started; with
    // no Authority to mint from it ends before the wrapped command, and the
    // run leaves no state behind.
    assert!(
        diagnostic.contains("authority unreachable at http://127.0.0.1:9"),
        "{stderr}"
    );
    assert!(!marker.exists(), "the wrapped command did not run");
    // A run that fails before its command closes the run as failed.
    assert!(stderr.ends_with("\nClosed:     failed\n"), "{stderr}");
    // The run's marker directory is gone; only the empty parent remains.
    let left = std::process::Command::new("find").arg(&state).output()?;
    let runs = std::fs::read_dir(state.join("run")).map_or(0, Iterator::count);
    assert_eq!(
        runs,
        0,
        "a run marker survived: {}",
        String::from_utf8_lossy(&left.stdout)
    );
    assert!(
        !project.path().join(".firma").exists(),
        "nothing was scaffolded"
    );
    let saved = std::fs::read_to_string(dir.join("connection.json"))?;
    assert!(saved.contains(ROTATED), "the renewed login was saved");
    let log = std::fs::read_to_string(log)?;
    for text in [&stdout, &stderr, &log] {
        for secret in [
            REFRESH_TOKEN,
            ROTATED,
            ACCESS_TOKEN,
            RUNTIME_CREDENTIAL,
            "Bearer ",
        ] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
    }
    server.verify().await;
    Ok(())
}

/// `firma run --agent build-bot -- <command>` against [`control_plane`],
/// with the login saved under `root`, run from `project`, and `env` added.
#[cfg(target_os = "linux")]
async fn run_build_bot(
    server: &MockServer,
    root: &std::path::Path,
    project: &std::path::Path,
    command: &[&str],
    env: &[(&str, &std::ffi::OsStr)],
) -> Result<Output, Box<dyn std::error::Error>> {
    let dir = root.join("firma");
    file_backed_login(&dir, &format!("{}/", server.uri()))?;
    let mut run = Command::new(crate::firma_bin());
    run.args(["run", "--agent", "build-bot", "--"])
        .args(command)
        .current_dir(project)
        .env("FIRMA_CONNECTION_DIR", dir)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
        .env("FIRMA_STATE_DIR", root.join("state"))
        .env("FIRMA_RUN_ALLOW_NON_STRUCTURAL", "1");
    for (name, value) in env {
        run.env(name, value);
    }
    Ok(tokio::task::spawn_blocking(move || run.output()).await??)
}

/// A start the Control Plane refused leaves no run to close.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_start_closes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane_answering(
        ResponseTemplate::new(500),
        "cancelled",
        closed("cancelled"),
        0,
    )
    .await;
    let root = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;

    let output = run_build_bot(&server, root.path(), project.path(), &["true"], &[]).await?;

    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("Run:"), "nothing started: {stderr}");
    assert!(!stderr.contains("Closed:"), "nothing to close: {stderr}");
    server.verify().await;
    Ok(())
}

/// A close that the Control Plane never accepts, even after its retries, is
/// reported as unconfirmed, never as done, and leaves the run's exit code as
/// it was.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn an_unavailable_control_plane_leaves_the_close_unconfirmed()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane_answering(started(), "failed", ResponseTemplate::new(503), 3).await;
    let root = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;

    let output = run_build_bot(&server, root.path(), project.path(), &["true"], &[]).await?;

    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    insta::assert_snapshot!(stderr.lines().last().ok_or("no close line")?, @"Closed:     unconfirmed (the Control Plane is unavailable (503 Service Unavailable)); if it is still open, the Control Plane will expire it");
    server.verify().await;
    Ok(())
}

/// The first close of a run wins: when the Control Plane recorded
/// another outcome, the line shows that one and the one requested.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_close_reports_the_outcome_the_control_plane_recorded()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane_answering(started(), "failed", closed("expired"), 1).await;
    let root = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;

    let output = run_build_bot(&server, root.path(), project.path(), &["true"], &[]).await?;

    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.ends_with("\nClosed:     expired (requested failed)\n"),
        "{stderr}"
    );
    server.verify().await;
    Ok(())
}

/// Once `--agent` runs the command, `firma`'s stdout is the wrapped
/// command's: a pipeline such as `firma run --agent bot -- jq . in.json >
/// out.json` must receive the command's output alone, so the resolution and
/// start report belongs on stderr like every other diagnostic.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_managed_run_leaves_stdout_to_the_wrapped_command()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane().await;
    let root = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;

    let output = run_build_bot(&server, root.path(), project.path(), &["true"], &[]).await?;

    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("Run:  run_01j0000000e008000000000001"),
        "the start is still reported: {stderr}"
    );
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "",
        "firma wrote its own report into the wrapped command's stdout"
    );
    Ok(())
}

/// A host that cannot sandbox the command must be refused before the
/// Control Plane starts a run that can then never
/// run, the same rule the reserved-environment checks follow.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_a_sandbox_backend_starts_no_run() -> Result<(), Box<dyn std::error::Error>>
{
    let server = control_plane().await;
    let root = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    // No `bwrap` on an empty PATH: the bwrap backend cannot prepare.
    let empty_path = root.path().join("empty-path");
    std::fs::create_dir(&empty_path)?;

    let output = run_build_bot(
        &server,
        root.path(),
        project.path(),
        &["/bin/true"],
        &[("PATH", empty_path.as_os_str())],
    )
    .await?;

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let started = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.url.path().starts_with("/api/agent-flow/v1/runs"))
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect::<Vec<_>>();
    // The start mocks expect one call each; once nothing is started they
    // must not fail this test when the server drops.
    server.reset().await;
    assert_eq!(
        started,
        [] as [String; 0],
        "a run was started for a run that could not start: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn an_access_only_login_cannot_run_an_agent() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    saved_login(
        &dir,
        "http://127.0.0.1:9/",
        &serde_json::json!({ "backend": "none" }),
    )?;

    let output = firma(&["run", "--agent", "build-bot", "--", "true"], &dir)?;

    assert_eq!(output.status.code(), Some(1));
    insta::assert_snapshot!(String::from_utf8(output.stderr)?, @"[ERR]  this saved login cannot be renewed; managed runs need a renewable login, so run `firma logout`, then `firma login` (not yet available on Windows)");
    Ok(())
}

/// `firma login` refuses while a login is saved, so the advice for an
/// access-only login must remove it first.
#[cfg(unix)]
#[test]
fn the_advice_for_an_access_only_login_can_be_followed() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("firma");
    let origin = "http://127.0.0.1:9/";
    saved_login(&dir, origin, &serde_json::json!({ "backend": "none" }))?;

    let refused = firma(&["run", "--agent", "build-bot", "--", "true"], &dir)?;
    let login = firma(
        &[
            "login",
            "--control-plane-origin",
            origin,
            "--development-loopback",
            "--terminal-code",
        ],
        &dir,
    )?;

    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(login.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(login.stderr)?,
        "[ERR]  a login is already saved; run firma logout before logging in again\n",
        "a saved login blocks `firma login`"
    );
    let advice = String::from_utf8(refused.stderr)?;
    assert!(
        advice.contains("`firma logout`"),
        "the advice must remove the saved login before logging in again: {advice}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_resolution_names_its_cause() -> Result<(), Box<dyn std::error::Error>> {
    const INCOMPATIBLE: &str = "[ERR]  the Control Plane answered in a form this firma does not understand; update firma\n";
    for (case, answer, expected) in [
        (
            "unknown handle",
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({ "code": "agent_not_found" })),
            "[ERR]  no Agent build-bot in this Workspace\n",
        ),
        (
            "another contract version",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "contract_version": 2,
                "agent": resolved_agent("build-bot"),
                "configuration": {
                    "generation": "42",
                    "authority_grpc_uri": "http://127.0.0.1:9/",
                    "capability_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            })),
            INCOMPATIBLE,
        ),
        // A Control Plane without the route answers a bare 404, not
        // `agent_not_found`.
        (
            "no resolution route",
            ResponseTemplate::new(404),
            INCOMPATIBLE,
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN))
            .respond_with(token_response())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agent-flow/v1/agents/build-bot"))
            .respond_with(answer)
            .mount(&server)
            .await;
        let root = tempfile::tempdir()?;
        let dir = root.path().join("firma");
        file_backed_login(&dir, &format!("{}/", server.uri()))?;

        let output = tokio::task::spawn_blocking(move || {
            Command::new(crate::firma_bin())
                .args(["run", "--agent", "build-bot", "--", "true"])
                .env("FIRMA_CONNECTION_DIR", dir)
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null")
                .env_remove("FIRMA_CONFIG")
                .output()
        })
        .await??;

        assert_eq!(output.status.code(), Some(1), "{case}");
        assert_eq!(String::from_utf8(output.stderr)?, expected, "{case}");
        assert_eq!(output.stdout, [] as [u8; 0], "{case}");
    }
    Ok(())
}
