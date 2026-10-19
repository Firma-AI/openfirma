use firma_login::{
    AuthenticatedConnection, AuthorizationAttempt, AuthorizationRequest, AuthorizationScope,
    AuthorizedTokenExchange, CallbackWaitTimeout, ControlPlaneOrigin, LoginRefusal,
    NativeTokenClient, NativeTokenError, OriginValidationMode, TerminalAuthorizationRequest,
};
use std::time::Duration;

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use firma_identifiers::{MembershipId, WorkspaceId};
use secrecy::ExposeSecret as _;

/// A token value that is deliberately not a JWT: the client must treat the
/// access token as opaque and send it back byte for byte.
const OPAQUE_TOKEN: &str = "not-a-jwt-token";
const TERMINAL_REDIRECT: &str = "http://127.0.0.1:9/callback";
const CODE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn public_client_composes_exact_authorization_fields() -> Result<(), Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        "https://example.test".parse()?,
        OriginValidationMode::Production,
    )?;
    let pending = AuthorizationAttempt::start()?.bind_loopback()?;
    let expected_state = pending.state_parameter().to_owned();
    let expected_challenge = pending.pkce_challenge().as_str().to_owned();
    let request =
        AuthorizationRequest::with_scope(&origin, pending, AuthorizationScope::AccessOnly);
    assert_eq!(
        request.as_url().path(),
        "/agent-flow/authorizations/authorize"
    );
    let fields: std::collections::BTreeMap<_, _> = request.as_url().query_pairs().collect();
    assert_eq!(fields.len(), 6);
    assert_eq!(fields.get("response_type").map(AsRef::as_ref), Some("code"));
    assert_eq!(
        fields.get("client_id").map(AsRef::as_ref),
        Some("firma-cli")
    );
    assert_eq!(
        fields.get("code_challenge_method").map(AsRef::as_ref),
        Some("S256")
    );
    assert_eq!(
        fields.get("redirect_uri").map(AsRef::as_ref),
        Some(request.redirect_uri().as_str())
    );
    assert_eq!(
        fields.get("state").map(AsRef::as_ref),
        Some(expected_state.as_str())
    );
    assert_eq!(
        fields.get("code_challenge").map(AsRef::as_ref),
        Some(expected_challenge.as_str())
    );
    Ok(())
}

/// What the mock Authority saw and what the client returned.
struct MockRun {
    /// Workspace and Membership the exchange delivered.
    exchange: Result<(WorkspaceId, MembershipId), NativeTokenError>,
    proof: Option<Result<AuthenticatedConnection, NativeTokenError>>,
    token_form: String,
    current_authorization: Option<String>,
    revocation_form: Option<String>,
    expected_verifier: String,
    expected_redirect: String,
}

/// How the mock run obtains its authorization code.
#[derive(Clone, Copy)]
enum Delivery {
    Loopback,
    Terminal,
}

/// Serve one token response and, when `current` is set, one current Workspace
/// response; then run the real client against them.
async fn run_against_mock(
    delivery: Delivery,
    token_status: StatusCode,
    token_content_type: &'static str,
    token_body: String,
    current: Option<(StatusCode, String)>,
) -> Result<MockRun, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = ControlPlaneOrigin::new(
        format!("http://{}", listener.local_addr()?).parse()?,
        OriginValidationMode::DevelopmentLoopback,
    )?;
    let (form_sender, mut form_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (header_sender, mut header_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (revoke_sender, mut revoke_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (current_status, current_response) =
        current.clone().unwrap_or((StatusCode::OK, String::new()));
    let router = Router::new()
        .route(
            "/api/agent-flow/v1/authorizations/token",
            post(move |form: Bytes| {
                let form_sender = form_sender.clone();
                let token_body = token_body.clone();
                async move {
                    let _ = form_sender.send(String::from_utf8_lossy(&form).into_owned());
                    (
                        token_status,
                        [
                            ("content-type", token_content_type),
                            ("location", "/redirect-target"),
                        ],
                        token_body,
                    )
                }
            }),
        )
        .route(
            "/api/agent-flow/v1/sessions/workspace/current",
            get(move |headers: HeaderMap| {
                let header_sender = header_sender.clone();
                let current_response = current_response.clone();
                async move {
                    let authorization = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    let _ = header_sender.send(authorization);
                    (
                        current_status,
                        [("content-type", "application/json")],
                        current_response,
                    )
                }
            }),
        )
        .route(
            "/api/agent-flow/v1/authorizations/revoke",
            post(move |form: Bytes| {
                let revoke_sender = revoke_sender.clone();
                async move {
                    let _ = revoke_sender.send(String::from_utf8_lossy(&form).into_owned());
                    StatusCode::OK
                }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let token_client = NativeTokenClient::new(&origin)?;

    let (exchange, expected_verifier, expected_redirect) = authorize(delivery, &origin).await?;
    let exchange = token_client.exchange(exchange).await;
    let token_form = tokio::time::timeout(Duration::from_secs(5), form_receiver.recv())
        .await?
        .ok_or("missing token request")?;
    let mut proof = None;
    let mut current_authorization = None;
    let exchange = match (exchange, current) {
        (Ok(grant), Some(_)) => {
            let ids = (grant.workspace_id, grant.membership_id);
            proof = Some(token_client.prove(grant).await);
            current_authorization =
                tokio::time::timeout(Duration::from_secs(5), header_receiver.recv())
                    .await?
                    .ok_or("missing current request")?;
            Ok(ids)
        }
        (other, _) => other.map(|grant| (grant.workspace_id, grant.membership_id)),
    };
    server.abort();
    let _ = server.await;
    Ok(MockRun {
        exchange,
        proof,
        token_form,
        current_authorization,
        revocation_form: revoke_receiver.try_recv().ok(),
        expected_verifier,
        expected_redirect,
    })
}

#[tokio::test]
async fn unscoped_exchange_revokes_an_unexpected_refresh_token()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace_id = WorkspaceId::generate();
    let membership_id = MembershipId::generate();
    for body in [
        serde_json::json!({
            "access_token": OPAQUE_TOKEN,
            "refresh_token": "unexpected-refresh-token",
            "token_type": "Bearer",
            "workspace_id": workspace_id,
            "membership_id": membership_id,
        }),
        serde_json::json!({
            "refresh_token": "unexpected-refresh-token",
            "token_type": "Bearer",
            "workspace_id": workspace_id,
            "membership_id": membership_id,
        }),
    ] {
        let run = run_against_mock(
            Delivery::Loopback,
            StatusCode::OK,
            "application/json",
            body.to_string(),
            None,
        )
        .await?;

        assert!(matches!(
            run.exchange,
            Err(NativeTokenError::InvalidResponse)
        ));
        let form: std::collections::BTreeMap<_, _> = url::form_urlencoded::parse(
            run.revocation_form
                .as_deref()
                .ok_or("missing revocation")?
                .as_bytes(),
        )
        .into_owned()
        .collect();
        assert_eq!(form.get("client_id").map(String::as_str), Some("firma-cli"));
        assert_eq!(
            form.get("token").map(String::as_str),
            Some("unexpected-refresh-token")
        );
        assert_eq!(
            form.get("token_type_hint").map(String::as_str),
            Some("refresh_token")
        );
    }
    Ok(())
}

/// Complete one authorization the way `delivery` does, returning the exchange
/// with the verifier and redirect URI the token form must carry.
async fn authorize(
    delivery: Delivery,
    origin: &ControlPlaneOrigin,
) -> Result<(AuthorizedTokenExchange, String, String), Box<dyn std::error::Error>> {
    let attempt = AuthorizationAttempt::start()?;
    let expected_verifier = attempt.verifier().as_secret().expose_secret().to_owned();
    let (exchange, expected_redirect) = match delivery {
        Delivery::Loopback => {
            let request = AuthorizationRequest::with_scope(
                origin,
                attempt.bind_loopback()?,
                AuthorizationScope::AccessOnly,
            );
            let expected_redirect = request.redirect_uri().to_string();
            let state = request
                .as_url()
                .query_pairs()
                .find(|(name, _)| name == "state")
                .ok_or("missing state")?
                .1
                .into_owned();
            let mut callback = request.redirect_uri().clone();
            callback
                .query_pairs_mut()
                .append_pair("state", &state)
                .append_pair("code", CODE);
            let receiving = tokio::spawn(
                request.receive(CallbackWaitTimeout::try_from(Duration::from_secs(5))?),
            );
            let callback_response = reqwest::get(callback).await?;
            assert_eq!(callback_response.status(), StatusCode::OK);
            (receiving.await??, expected_redirect)
        }
        Delivery::Terminal => (
            TerminalAuthorizationRequest::with_scope(
                origin,
                attempt,
                AuthorizationScope::AccessOnly,
            )
            .complete(CODE)?,
            TERMINAL_REDIRECT.to_owned(),
        ),
    };
    Ok((exchange, expected_verifier, expected_redirect))
}

fn token_body(workspace_id: &WorkspaceId, membership_id: &MembershipId) -> String {
    serde_json::json!({
        "access_token": OPAQUE_TOKEN,
        // Case-insensitive per RFC 6749 section 5.1.
        "token_type": "bearer",
        "expires_in": 600,
        "workspace_id": workspace_id.to_string(),
        "membership_id": membership_id.to_string(),
        // An additive field the client does not know must be ignored.
        "scope": "workspace:connect",
    })
    .to_string()
}

fn current_body(workspace_id: &WorkspaceId, membership_id: &MembershipId) -> (StatusCode, String) {
    let body = serde_json::json!({
        "workspace_id": workspace_id.to_string(),
        "membership_id": membership_id.to_string(),
    });
    (StatusCode::OK, body.to_string())
}

#[tokio::test]
async fn exchange_posts_exact_form_and_proof_sends_the_opaque_token_back()
-> Result<(), Box<dyn std::error::Error>> {
    for delivery in [Delivery::Loopback, Delivery::Terminal] {
        assert_exact_exchange(delivery).await?;
    }
    Ok(())
}

async fn assert_exact_exchange(delivery: Delivery) -> Result<(), Box<dyn std::error::Error>> {
    let workspace_id = WorkspaceId::generate();
    let membership_id = MembershipId::generate();
    let run = run_against_mock(
        delivery,
        StatusCode::OK,
        // Parameters do not change the media type (RFC 7231).
        "Application/JSON; charset=utf-8",
        token_body(&workspace_id, &membership_id),
        Some(current_body(&workspace_id, &membership_id)),
    )
    .await?;

    let (granted_workspace, granted_membership) = run.exchange?;
    assert_eq!(granted_workspace, workspace_id);
    assert_eq!(granted_membership, membership_id);
    let fields: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(run.token_form.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(fields.len(), 5);
    assert_eq!(
        fields.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        fields.get("client_id").map(String::as_str),
        Some("firma-cli")
    );
    assert_eq!(fields.get("code").map(String::as_str), Some(CODE));
    assert_eq!(fields.get("code_verifier"), Some(&run.expected_verifier));
    assert_eq!(fields.get("redirect_uri"), Some(&run.expected_redirect));

    let connection = run.proof.ok_or("prove was not called")??;
    assert_eq!(connection.workspace_id, workspace_id);
    assert_eq!(connection.membership_id, membership_id);
    assert_eq!(connection.access_token().expose_secret(), OPAQUE_TOKEN);
    assert_eq!(
        run.current_authorization.as_deref(),
        Some(format!("Bearer {OPAQUE_TOKEN}").as_str())
    );
    Ok(())
}

#[tokio::test]
async fn proof_rejects_a_current_response_for_another_membership()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace_id = WorkspaceId::generate();
    let run = run_against_mock(
        Delivery::Loopback,
        StatusCode::OK,
        "application/json",
        token_body(&workspace_id, &MembershipId::generate()),
        Some(current_body(&workspace_id, &MembershipId::generate())),
    )
    .await?;

    assert!(matches!(
        run.proof,
        Some(Err(NativeTokenError::InvalidResponse))
    ));
    Ok(())
}

#[tokio::test]
async fn proof_reports_a_rejected_token_by_its_oauth_code() -> Result<(), Box<dyn std::error::Error>>
{
    let workspace_id = WorkspaceId::generate();
    let membership_id = MembershipId::generate();
    let run = run_against_mock(
        Delivery::Loopback,
        StatusCode::OK,
        "application/json",
        token_body(&workspace_id, &membership_id),
        Some((
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_token"}"#.into(),
        )),
    )
    .await?;

    assert!(matches!(
        run.proof,
        Some(Err(NativeTokenError::Refused(LoginRefusal::InvalidToken)))
    ));
    Ok(())
}

#[test]
fn terminal_request_uses_fixed_redirect_and_rejects_impossible_code()
-> Result<(), Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        "https://example.test".parse()?,
        OriginValidationMode::Production,
    )?;
    let request = TerminalAuthorizationRequest::with_scope(
        &origin,
        AuthorizationAttempt::start()?,
        AuthorizationScope::AccessOnly,
    );
    let fields: std::collections::BTreeMap<_, _> = request.as_url().query_pairs().collect();
    assert_eq!(fields.get("response_type").map(AsRef::as_ref), Some("code"));
    assert_eq!(
        fields.get("redirect_uri").map(AsRef::as_ref),
        Some(TERMINAL_REDIRECT)
    );
    assert!(matches!(
        request.complete(""),
        Err(NativeTokenError::InvalidCode)
    ));
    Ok(())
}

#[test]
fn terminal_complete_does_not_pin_the_server_code_format() -> Result<(), Box<dyn std::error::Error>>
{
    let origin = ControlPlaneOrigin::new(
        "https://example.test".parse()?,
        OriginValidationMode::Production,
    )?;
    // Not the 43-character Base64 shape the Authority happens to issue today.
    // The CLI must forward it and let the Authority judge it.
    let request = TerminalAuthorizationRequest::with_scope(
        &origin,
        AuthorizationAttempt::start()?,
        AuthorizationScope::AccessOnly,
    );
    assert!(request.complete("ABC-123").is_ok());
    // Whitespace copied around the code is not part of it.
    let request = TerminalAuthorizationRequest::with_scope(
        &origin,
        AuthorizationAttempt::start()?,
        AuthorizationScope::AccessOnly,
    );
    assert!(request.complete(" ABC-123\n").is_ok());
    let request = TerminalAuthorizationRequest::with_scope(
        &origin,
        AuthorizationAttempt::start()?,
        AuthorizationScope::AccessOnly,
    );
    assert!(matches!(
        request.complete(&"a".repeat(513)),
        Err(NativeTokenError::InvalidCode)
    ));
    Ok(())
}

#[tokio::test]
async fn token_exchange_rejects_redirect_and_invalid_success_documents()
-> Result<(), Box<dyn std::error::Error>> {
    let redirect = run_against_mock(
        Delivery::Loopback,
        StatusCode::FOUND,
        "application/json",
        "{}".into(),
        None,
    )
    .await?;
    assert!(matches!(
        redirect.exchange,
        Err(NativeTokenError::Rejected(StatusCode::FOUND))
    ));
    let rejected = run_against_mock(
        Delivery::Loopback,
        StatusCode::BAD_REQUEST,
        "application/json",
        "{}".into(),
        None,
    )
    .await?;
    assert!(matches!(
        rejected.exchange,
        Err(NativeTokenError::Rejected(StatusCode::BAD_REQUEST))
    ));
    let refused = run_against_mock(
        Delivery::Loopback,
        StatusCode::BAD_REQUEST,
        "application/json",
        r#"{"error":"invalid_grant"}"#.into(),
        None,
    )
    .await?;
    assert!(matches!(
        refused.exchange,
        Err(NativeTokenError::Refused(LoginRefusal::InvalidGrant))
    ));
    let failed = run_against_mock(
        Delivery::Loopback,
        StatusCode::INTERNAL_SERVER_ERROR,
        "application/json",
        r#"{"error":"server_error"}"#.into(),
        None,
    )
    .await?;
    assert!(matches!(
        failed.exchange,
        Err(NativeTokenError::Refused(LoginRefusal::ServerError))
    ));
    let wrong_content_type = run_against_mock(
        Delivery::Loopback,
        StatusCode::OK,
        "text/plain",
        "{}".into(),
        None,
    )
    .await?;
    assert!(matches!(
        wrong_content_type.exchange,
        Err(NativeTokenError::InvalidResponse)
    ));
    let workspace_id = WorkspaceId::generate().to_string();
    let membership_id = MembershipId::generate().to_string();
    for body in [
        "{}".to_owned(),
        // A token type the client does not understand (RFC 6749 section 7.1).
        serde_json::json!({
            "access_token": OPAQUE_TOKEN, "token_type": "mac",
            "workspace_id": workspace_id, "membership_id": membership_id,
        })
        .to_string(),
        // An empty token.
        serde_json::json!({
            "access_token": "", "token_type": "Bearer",
            "workspace_id": workspace_id, "membership_id": membership_id,
        })
        .to_string(),
        "x".repeat(4097),
    ] {
        let run = run_against_mock(
            Delivery::Loopback,
            StatusCode::OK,
            "application/json",
            body,
            None,
        )
        .await?;
        assert!(matches!(
            run.exchange,
            Err(NativeTokenError::InvalidResponse)
        ));
    }
    Ok(())
}
