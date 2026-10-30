//! In-process renewal through the public native-session boundary.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use firma_connection_store::{
    Connection, ConnectionSecret, ConnectionStore, OriginMode, SecretPolicy,
};
use firma_login::{NativeSession, SessionError};
use secrecy::{ExposeSecret as _, SecretString};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const TOKEN_PATH: &str = "/api/agent-flow/v1/authorizations/token";
const WORKSPACE: &str = "wsp_01j0000000e008000000000001";
const MEMBERSHIP: &str = "mem_01j0000000e008000000000001";
const R0: &str = "refresh-zero";
const R1: &str = "refresh-one";
const R2: &str = "refresh-two";

pub fn saved_login(
    dir: &std::path::Path,
    server: &MockServer,
) -> Result<ConnectionStore, Box<dyn std::error::Error>> {
    let native = keyring_core::mock::Store::new()?;
    let store = ConnectionStore::open_with_native_store(dir, native)?;
    let guard = store.exclusive()?;
    guard.replace(
        &Connection {
            origin: format!("{}/", server.uri()).parse()?,
            origin_mode: OriginMode::DevelopmentLoopback,
            workspace_id: WORKSPACE.parse()?,
            membership_id: MEMBERSHIP.parse()?,
        },
        Some(&ConnectionSecret::new(SecretString::from(R0))),
        SecretPolicy::NativeOnly,
    )?;
    drop(guard);
    Ok(store)
}

pub fn token_response(access: &str, refresh: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": 600,
        "workspace_id": WORKSPACE,
        "membership_id": MEMBERSHIP,
    }))
}

#[tokio::test(flavor = "multi_thread")]
async fn transient_retries_reuse_one_key_and_publish_before_returning()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let responder_attempts = Arc::clone(&attempts);
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(move |_: &wiremock::Request| {
            if responder_attempts.fetch_add(1, Ordering::Relaxed) < 3 {
                ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"error": "server_error"}))
            } else {
                token_response("access-one", R1)
            }
        })
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    let mut session = NativeSession::new(store.clone());

    let error = session
        .access_token()
        .await
        .expect_err("first retry budget exhausted");
    assert!(matches!(
        error,
        SessionError::RefreshFailed {
            source: firma_login::NativeTokenError::Refused(firma_login::LoginRefusal::ServerError),
            ..
        }
    ));
    insta::assert_snapshot!(error.to_string().replace(&server.uri(), "[origin]"), @"the renewal outcome may be unknown; run `firma logout`, then `firma login --control-plane-origin [origin] --development-loopback` before retrying in a new process");
    assert_eq!(
        session.access_token().await?.token().expose_secret(),
        "access-one"
    );
    let requests = server.received_requests().await.ok_or("missing requests")?;
    assert_eq!(requests.len(), 4);
    let key = requests[0]
        .headers
        .get("idempotency-key")
        .ok_or("missing idempotency key")?;
    for request in &requests {
        assert_eq!(request.headers.get("idempotency-key"), Some(key));
        assert!(String::from_utf8_lossy(&request.body).contains("refresh_token=refresh-zero"));
    }
    let access = session.access_token().await?;
    assert_eq!(
        access.origin().as_url().as_str(),
        format!("{}/", server.uri())
    );
    assert_eq!(access.workspace_id(), WORKSPACE.parse()?);
    let guard = store.shared()?;
    let saved = guard.load()?.ok_or("missing saved login")?;
    assert_eq!(saved.secret.secret().ok_or("missing R1")?.expose(), R1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_after_send_recovers_with_the_same_r0_and_key()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let received = Arc::new(tokio::sync::Notify::new());
    let responder_received = Arc::clone(&received);
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(move |_: &wiremock::Request| {
            responder_received.notify_one();
            token_response("access-one", R1).set_delay(Duration::from_secs(1))
        })
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    let mut session = NativeSession::new(store);

    {
        let first_refresh = session.access_token();
        tokio::pin!(first_refresh);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                () = received.notified() => {}
                result = &mut first_refresh => panic!("refresh completed before cancellation: {result:?}"),
            }
        }).await?;
    }
    assert_eq!(
        session.access_token().await?.token().expose_secret(),
        "access-one"
    );
    let requests = server.received_requests().await.ok_or("missing request")?;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(
        requests[0].headers.get("idempotency-key"),
        requests[1].headers.get("idempotency-key")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_sessions_hold_the_lock_through_successor_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let responder_attempts = Arc::clone(&attempts);
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(move |_: &wiremock::Request| {
            if responder_attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                token_response("access-one", R1).set_delay(Duration::from_millis(100))
            } else {
                token_response("access-two", R2)
            }
        })
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    let mut first = NativeSession::new(store.clone());
    let mut second = NativeSession::new(store.clone());

    let first_access = tokio::spawn(async move {
        first
            .access_token()
            .await
            .map(|access| access.token().expose_secret().to_owned())
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while attempts.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let second_access = second.access_token().await?;

    assert_eq!(first_access.await??, "access-one");
    assert_eq!(second_access.token().expose_secret(), "access-two");
    let requests = server.received_requests().await.ok_or("missing requests")?;
    assert_eq!(requests.len(), 2);
    assert!(String::from_utf8_lossy(&requests[0].body).contains("refresh_token=refresh-zero"));
    assert!(String::from_utf8_lossy(&requests[1].body).contains("refresh_token=refresh-one"));
    let guard = store.shared()?;
    let saved = guard.load()?.ok_or("missing saved login")?;
    assert_eq!(saved.secret.secret().ok_or("missing R2")?.expose(), R2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_no_retry_can_change_requires_a_new_login()
-> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({"error": "invalid_client"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir()?;
    let store = saved_login(&root.path().join("firma"), &server)?;
    let mut session = NativeSession::new(store);

    let error = session.access_token().await.expect_err("refused");

    assert!(matches!(
        error,
        SessionError::RenewalRefused {
            source: firma_login::NativeTokenError::Refused(firma_login::LoginRefusal::Other),
            ..
        }
    ));
    insta::assert_snapshot!(error.to_string().replace(&server.uri(), "[origin]"), @"the saved login could not be renewed; run `firma logout`, then `firma login --control-plane-origin [origin] --development-loopback`");
    server.verify().await;
    Ok(())
}
