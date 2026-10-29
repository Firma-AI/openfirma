//! Agent resolution through the public Control Plane client, against a test
//! double of the token and Agent endpoints.

use firma_login::{CloseOutcome, ControlPlaneClient, ControlPlaneError, RecordedOutcome};
use secrecy::ExposeSecret as _;
use std::assert_matches;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use crate::session::{saved_login, token_response};

const TOKEN_PATH: &str = "/api/agent-flow/v1/authorizations/token";
const RUN: &str = "run_01j0000000e008000000000001";
const PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn resolution(authority_grpc_uri: &str, capability_public_key: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "contract_version": 1,
        "agent": {
            "id": "agt_01j0000000e008000000000001",
            "handle": "build-bot",
            "name": "Build bot",
            "profile_id": "claude-code",
            "policy_set_id": "pset_01j0000000e008000000000001",
        },
        "configuration": {
            "generation": "42",
            "authority_grpc_uri": authority_grpc_uri,
            "capability_public_key": capability_public_key,
        },
    }))
}

/// A `201` start answer for `RUN` with `edit` applied to its body.
fn started(edit: impl FnOnce(&mut serde_json::Value)) -> ResponseTemplate {
    let mut body = serde_json::json!({
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
            "access_token": "runtime-credential-value",
        },
    });
    edit(&mut body);
    ResponseTemplate::new(201).set_body_json(body)
}

/// A Control Plane that renews the login and answers `build-bot`'s
/// resolution with `agents`.
async fn control_plane(agents: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent-flow/v1/agents/build-bot"))
        .respond_with(agents)
        .mount(&server)
        .await;
    server
}

/// Mounts one more answer on `server`.
async fn answer(
    server: &MockServer,
    verb: &str,
    route: impl Into<String>,
    template: ResponseTemplate,
) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(template)
        .mount(server)
        .await;
}

fn client(
    server: &MockServer,
) -> Result<(ControlPlaneClient, tempfile::TempDir), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), server)?;
    Ok((ControlPlaneClient::new(store), root))
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_agent_requires_404_but_not_a_valid_diagnostic_id()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    let mut client = ControlPlaneClient::new(store);
    for start in [false, true] {
        for status in [404, 422] {
            let response = Mock::given(method(if start { "POST" } else { "GET" }))
                .and(path(if start {
                    "/api/agent-flow/v1/runs"
                } else {
                    "/api/agent-flow/v1/agents/build-bot"
                }))
                .respond_with(ResponseTemplate::new(status).set_body_json(
                    serde_json::json!({"code":"agent_not_found", "request_id":"broken"}),
                ))
                .expect(1)
                .mount_as_scoped(&server)
                .await;
            let handle = "build-bot".parse()?;
            let error = if start {
                client.start_run(&handle, "42").await.err()
            } else {
                client.resolve_agent(&handle).await.err()
            }
            .ok_or("expected refusal")?;
            if status == 404 {
                assert_matches!(error, ControlPlaneError::AgentNotFound(actual) if actual == handle);
            } else {
                assert_matches!(error, ControlPlaneError::Refused {status, code, request_id:None} if status.as_u16() == 422 && code == "agent_not_found");
            }
            drop(response);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_start_validates_version_state_identity_and_credential_without_exposing_it()
-> Result<(), Box<dyn std::error::Error>> {
    for change in [
        Some(("/contract_version", serde_json::json!(2))),
        Some(("/run/state", serde_json::json!("terminal"))),
        Some(("/run/sidecar_id", serde_json::Value::Null)),
        Some(("/runtime_credential/token_type", serde_json::json!("Basic"))),
        Some(("/runtime_credential/access_token", serde_json::json!(""))),
        None,
    ] {
        let field = change.as_ref().map_or("valid", |(field, _)| *field);
        let server = control_plane(resolution("http://127.0.0.1:50051/", PUBLIC_KEY)).await;
        let answer_with = started(|body| {
            if let Some((field, value)) = change {
                *body.pointer_mut(field).expect("field of the start body") = value;
            }
        });
        answer(&server, "POST", RUNS_PATH, answer_with).await;
        let (mut client, _root) = client(&server)?;

        let outcome = client.start_run(&"build-bot".parse()?, "42").await;

        assert!(
            !format!("{outcome:?}").contains("runtime-credential-value"),
            "{field}"
        );
        if field == "valid" {
            let started = outcome?;
            assert_eq!(started.run_id.to_string(), RUN);
            assert_eq!(
                started.sidecar_id.to_string(),
                "sc_01j0000000e008000000000001"
            );
            assert_eq!(
                started.credential.expose_secret(),
                "runtime-credential-value"
            );
        } else {
            assert_matches!(
                outcome,
                Err(ControlPlaneError::IncompatibleServer),
                "{field}"
            );
        }
    }
    Ok(())
}

/// Each start creates a run, so not even an outage is retried: the
/// answer may have been lost after the commit.
#[tokio::test(flavor = "multi_thread")]
async fn a_start_is_sent_once_even_when_the_control_plane_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    for status in [408, 429, 500, 503] {
        let server = control_plane(resolution("http://127.0.0.1:50051/", PUBLIC_KEY)).await;
        Mock::given(method("POST"))
            .and(path(RUNS_PATH))
            .respond_with(ResponseTemplate::new(status).insert_header("Retry-After", "0"))
            .expect(1)
            .mount(&server)
            .await;
        let (mut client, _root) = client(&server)?;

        let error = client
            .start_run(&"build-bot".parse()?, "42")
            .await
            .unwrap_err();

        assert_matches!(error, ControlPlaneError::Unavailable { status: actual, request_id: None } if actual.as_u16() == status);
        let requests = server.received_requests().await.ok_or("missing requests")?;
        assert!(
            requests
                .iter()
                .filter(|request| request.url.path() == RUNS_PATH)
                .all(|request| !request.headers.contains_key("idempotency-key")),
            "a start carries no Idempotency-Key"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_after_is_bounded_and_invalid_values_fall_back()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    let mut client = ControlPlaneClient::new(store);
    for (header, minimum) in [
        (Some("999999999999999999999999999999"), 15),
        (Some("Wed, 21 Oct 2026 07:28:00 GMT"), 1),
        (Some("-1"), 1),
        (None, 1),
        (Some("0"), 0),
    ] {
        let mut unavailable = ResponseTemplate::new(503);
        if let Some(header) = header {
            unavailable = unavailable.insert_header("Retry-After", header);
        }
        let response = Mock::given(method("POST"))
            .and(path(CLOSE_PATH))
            .respond_with(unavailable)
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let replay = Mock::given(method("POST"))
            .and(path(CLOSE_PATH))
            .respond_with(closed("completed"))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(minimum + 5),
            client.close_run(RUN.parse()?, CloseOutcome::Completed),
        )
        .await?;
        assert_eq!(result?, RecordedOutcome::Completed);
        assert!(start.elapsed() >= std::time::Duration::from_secs(minimum));
        drop((response, replay));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_request_means_firma_needs_an_update() -> Result<(), Box<dyn std::error::Error>>
{
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    let mut client = ControlPlaneClient::new(store);

    for status in [
        301, 302, 307, 400, 404, 405, 406, 410, 415, 422, 408, 429, 500, 503,
    ] {
        let response = Mock::given(method("GET"))
            .and(path("/api/agent-flow/v1/agents/build-bot"))
            .respond_with(ResponseTemplate::new(status))
            .mount_as_scoped(&server)
            .await;
        let resolved = client.resolve_agent(&"build-bot".parse()?).await;
        if [408, 429, 500, 503].contains(&status) {
            assert_matches!(resolved, Err(ControlPlaneError::Unavailable { status: actual, request_id: None }) if actual.as_u16() == status);
        } else {
            assert_matches!(resolved, Err(ControlPlaneError::IncompatibleServer));
        }
        drop(response);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resolution_validates_canonical_profiles_and_preserves_generation_strings()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    let mut client = ControlPlaneClient::new(store);

    for (profile, generation, valid) in [
        ("claude-code", "1", true),
        ("vscode", "18446744073709551615", true),
        ("generic", "+042", false),
        ("generic", "007", false),
        ("generic", "0", false),
        ("generic", "", false),
        ("generic", "18446744073709551616", false),
        ("generic", "1\n", false),
        ("claude", "42", false),
        ("copilot-cli", "42", false),
        ("code", "42", false),
        ("unknown", "42", false),
    ] {
        let response = Mock::given(method("GET"))
            .and(path("/api/agent-flow/v1/agents/build-bot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "contract_version": 1,
                "agent": {
                    "id": "agt_01j0000000e008000000000001",
                    "handle": "build-bot",
                    "name": "Build bot",
                    "profile_id": profile,
                    "policy_set_id": "pset_01j0000000e008000000000001",
                },
                "configuration": {
                    "generation": generation,
                    "authority_grpc_uri": "http://127.0.0.1:50051",
                    "capability_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            })))
            .mount_as_scoped(&server)
            .await;
        let resolved = client.resolve_agent(&"build-bot".parse()?).await;
        if valid {
            let resolved = resolved?;
            assert_eq!(resolved.generation, generation);
            assert_eq!(resolved.profile_id.as_str(), profile);
        } else {
            assert_matches!(resolved, Err(ControlPlaneError::IncompatibleServer));
        }
        drop(response);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_generation_outside_the_documented_decimal_form_means_firma_needs_an_update()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent-flow/v1/agents/build-bot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "contract_version": 1,
            "agent": {
                "id": "agt_01j0000000e008000000000001",
                "handle": "build-bot",
                "name": "build-bot",
                "profile_id": "generic",
                "policy_set_id": "pset_01j0000000e008000000000001",
            },
            "configuration": {
                "generation": "+042",
                "authority_grpc_uri": "http://127.0.0.1:50051",
                "capability_public_key": PUBLIC_KEY,
            },
        })))
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;

    let resolved = ControlPlaneClient::new(store)
        .resolve_agent(&"build-bot".parse()?)
        .await;

    assert_matches!(resolved, Err(ControlPlaneError::IncompatibleServer));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_closure_refusal_is_specific_and_other_forbidden_responses_stay_access_denied()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane(resolution("http://127.0.0.1:50051/", PUBLIC_KEY)).await;
    let (mut client, _root) = client(&server)?;
    for (body, machine) in [
        (serde_json::json!({"code": "run_not_closable"}), true),
        (
            serde_json::json!({"code": "workspace_access_denied"}),
            false,
        ),
        (serde_json::json!({"code": "future_refusal"}), false),
        (serde_json::json!({"code": "invalid code"}), false),
        (serde_json::Value::Null, false),
    ] {
        let response = Mock::given(method("POST"))
            .and(path(CLOSE_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(body))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let error = client
            .close_run(RUN.parse()?, CloseOutcome::Completed)
            .await
            .err()
            .ok_or("expected closure refusal")?;
        if machine {
            assert_matches!(error, ControlPlaneError::RunNotClosable);
            insta::allow_duplicates! {
                insta::assert_snapshot!(error.to_string(), @"this run is owned by a machine and cannot be closed with your human login");
            }
        } else {
            assert_matches!(error, ControlPlaneError::AccessDenied);
            insta::allow_duplicates! {
                insta::assert_snapshot!(error.to_string(), @"your Membership cannot use Agents in this Workspace");
            }
        }
        drop(response);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn only_transient_statuses_replay_a_close() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    let mut client = ControlPlaneClient::new(store);
    for status in [408, 429, 500, 502, 503, 504, 501, 505] {
        let transient = ![501, 505].contains(&status);
        let response = Mock::given(method("POST"))
            .and(path(CLOSE_PATH))
            .respond_with(ResponseTemplate::new(status).insert_header("Retry-After", "0"))
            .expect(if transient { 3 } else { 1 })
            .mount_as_scoped(&server)
            .await;
        let error = client
            .close_run(RUN.parse()?, CloseOutcome::Completed)
            .await
            .err()
            .ok_or("expected outage")?;
        assert_matches!(error, ControlPlaneError::Unavailable { status: actual, request_id: None } if actual.as_u16() == status);
        drop(response);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn close_transient_budget_is_independent_of_one_token_renewal()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .expect(2)
        .mount(&server)
        .await;
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts = count.clone();
    Mock::given(method("POST"))
        .and(path(CLOSE_PATH))
        .respond_with(move |_: &wiremock::Request| {
            let status = match attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => 503,
                1 => 401,
                2 => 429,
                _ => 504,
            };
            ResponseTemplate::new(status).insert_header("Retry-After", "0")
        })
        .expect(4)
        .mount(&server)
        .await;
    let error = ControlPlaneClient::new(store)
        .close_run(RUN.parse()?, CloseOutcome::Completed)
        .await
        .err()
        .ok_or("expected outage")?;
    assert_matches!(error, ControlPlaneError::Unavailable { status, request_id: None } if status.as_u16() == 504);
    Ok(())
}

/// A client error other than a refused token or Membership is a contract
/// mismatch, such as a Control Plane that serves the path without `GET`; it
/// is not an outage the user should wait out.
#[tokio::test(flavor = "multi_thread")]
async fn an_unexpected_client_error_means_firma_needs_an_update()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/agent-flow/v1/agents/build-bot"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;

    let resolved = ControlPlaneClient::new(store)
        .resolve_agent(&"build-bot".parse()?)
        .await;

    assert_matches!(resolved, Err(ControlPlaneError::IncompatibleServer));
    Ok(())
}

const RUNS_PATH: &str = "/api/agent-flow/v1/runs";

const CLOSE_PATH: &str = "/api/agent-flow/v1/runs/run_01j0000000e008000000000001/close";

/// An Agent deleted between resolution and start is reported as missing,
/// exactly as resolution reports it, not as an unrecognised refusal.
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_deleted_before_the_start_is_reported_as_not_found()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(RUNS_PATH))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "code": "agent_not_found",
            "request_id": "0190d7b4-0000-7000-8000-000000000001",
        })))
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;

    let started = ControlPlaneClient::new(store)
        .start_run(&"build-bot".parse()?, "42")
        .await;

    let error = started.expect_err("the Agent is gone");
    assert_matches!(&error, ControlPlaneError::AgentNotFound(handle) if handle.as_str() == "build-bot");
    insta::assert_snapshot!(error.to_string(), @"no Agent build-bot in this Workspace");
    Ok(())
}

/// A token the Control Plane still refuses right after a renewal is not a
/// transient failure: one replay under the renewed token, then the refusal
/// stands, so a rejected login does not burn refresh-token rotations.
#[tokio::test(flavor = "multi_thread")]
async fn a_start_refused_for_its_renewed_token_is_not_replayed_again()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(token_response("access-one", "refresh-one"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(RUNS_PATH))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;

    let started = ControlPlaneClient::new(store)
        .start_run(&"build-bot".parse()?, "42")
        .await;

    assert_matches!(started, Err(ControlPlaneError::Unauthorized));
    let requests = server.received_requests().await.unwrap_or_default();
    let count = |wanted: &str| {
        requests
            .iter()
            .filter(|request| request.url.path() == wanted)
            .count()
    };
    assert_eq!(count(RUNS_PATH), 2, "one replay after the renewal");
    assert_eq!(count(TOKEN_PATH), 2, "one renewal per refused token");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resolution_names_the_authority_and_its_verifying_key()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane(resolution("http://127.0.0.1:50051/", PUBLIC_KEY)).await;
    let (mut client, _root) = client(&server)?;

    let agent = client.resolve_agent(&"build-bot".parse()?).await?;

    assert_eq!(agent.authority_grpc_uri.as_str(), "http://127.0.0.1:50051/");
    assert_eq!(agent.capability_public_key, [0; 32]);
    assert_eq!(agent.generation, "42");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authority_over_https_on_another_host_is_resolved()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane(resolution("https://control.firma.ai/", PUBLIC_KEY)).await;
    let (mut client, _root) = client(&server)?;

    let agent = client.resolve_agent(&"build-bot".parse()?).await?;

    assert_eq!(
        agent.authority_grpc_uri.as_str(),
        "https://control.firma.ai/"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authority_over_https_on_this_host_or_http_elsewhere_is_unsupported()
-> Result<(), Box<dyn std::error::Error>> {
    for authority_grpc_uri in ["https://127.0.0.1:50051/", "http://10.0.0.7:50051/"] {
        let server = control_plane(resolution(authority_grpc_uri, PUBLIC_KEY)).await;
        let (mut client, _root) = client(&server)?;

        let error = client
            .resolve_agent(&"build-bot".parse()?)
            .await
            .unwrap_err();

        assert_matches!(
            error,
            ControlPlaneError::AuthorityTransportUnsupported,
            "{authority_grpc_uri}"
        );
    }
    insta::assert_snapshot!(
        ControlPlaneError::AuthorityTransportUnsupported.to_string(),
        @"this firma reaches the Authority of a managed run only over https on another host, or plain http on a loopback host"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_verifying_key_of_another_size_is_an_incompatible_server()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane(resolution("http://127.0.0.1:50051/", "AAAA")).await;
    let (mut client, _root) = client(&server)?;

    let error = client
        .resolve_agent(&"build-bot".parse()?)
        .await
        .unwrap_err();

    assert_matches!(error, ControlPlaneError::IncompatibleServer);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_problem_code_that_is_not_a_short_name_never_reaches_the_terminal()
-> Result<(), Box<dyn std::error::Error>> {
    let server = control_plane(resolution("http://127.0.0.1:50051/", PUBLIC_KEY)).await;
    answer(
        &server,
        "POST",
        "/api/agent-flow/v1/runs",
        ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "code": "Run `rm -rf /`\u{1b}[2J",
        })),
    )
    .await;
    let (mut client, _root) = client(&server)?;

    let error = client
        .start_run(&"build-bot".parse()?, "42")
        .await
        .unwrap_err();

    assert_matches!(error, ControlPlaneError::IncompatibleServer);
    Ok(())
}

fn closed(outcome: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "contract_version": 1,
        "run": {
            "id": RUN,
            "agent_id": "agt_01j0000000e008000000000001",
            "state": "terminal",
            "desired_generation": "42",
            "outcome": outcome,
            "terminated_at": "2026-09-10T09:05:00Z",
            "sidecar_id": "sc_01j0000000e008000000000001",
            "expires_at": "2026-09-10T09:02:10Z",
        },
    }))
}

/// The Control Plane records a run whose Sidecar stopped refreshing
/// mid-run as `expired`; the contract has no `runtime_expired`,
/// so an answer naming it is not a terminal record this firma understands.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_accepts_only_the_outcomes_the_contract_records()
-> Result<(), Box<dyn std::error::Error>> {
    for (recorded, expected) in [
        ("expired", Some(RecordedOutcome::Expired)),
        ("key_expired", Some(RecordedOutcome::KeyExpired)),
        ("runtime_expired", None),
    ] {
        let server = control_plane(resolution("http://127.0.0.1:50051/", PUBLIC_KEY)).await;
        answer(
            &server,
            "POST",
            format!("/api/agent-flow/v1/runs/{RUN}/close"),
            closed(recorded),
        )
        .await;
        let (mut client, _root) = client(&server)?;

        let answer = client
            .close_run(RUN.parse()?, CloseOutcome::Completed)
            .await;

        match expected {
            Some(outcome) => {
                let actual = answer?;
                assert_eq!(actual, outcome, "{recorded}");
                assert_eq!(actual.to_string(), recorded);
            }
            None => assert_matches!(
                answer,
                Err(ControlPlaneError::IncompatibleServer),
                "{recorded}"
            ),
        }
    }
    Ok(())
}
