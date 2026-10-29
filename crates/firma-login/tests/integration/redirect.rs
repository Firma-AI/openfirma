use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use firma_login::{
    AuthorizationAttempt, CallbackLanding, CallbackTimeoutError, CallbackWaitTimeout,
    ControlPlaneOrigin, LANDING_PATH, LoginRefusal, LoopbackCallbackError, OriginValidationMode,
    PendingAuthorizationAttempt,
};
use secrecy::ExposeSecret as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(1);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const PARSER_LIMIT_TEST_TIMEOUT: Duration = Duration::from_secs(6);
const HEADER_TIMEOUT_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADERS: usize = 64;
const MAX_BUFFER_SIZE: usize = 64 * 1024;

fn pending_attempt() -> Result<PendingAuthorizationAttempt, Box<dyn std::error::Error>> {
    AuthorizationAttempt::start()?
        .bind_loopback()
        .map_err(Into::into)
}

fn callback_address(attempt: &PendingAuthorizationAttempt) -> Result<SocketAddr, std::io::Error> {
    let port = attempt
        .redirect_uri()
        .as_url()
        .port()
        .ok_or_else(|| std::io::Error::other("bound callback URI has no port"))?;

    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

fn landing() -> Result<CallbackLanding, Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        url::Url::parse("https://team.example.com")?,
        OriginValidationMode::Production,
    )?;
    Ok(CallbackLanding::on(&origin))
}

fn callback_timeout() -> Result<CallbackWaitTimeout, CallbackTimeoutError> {
    CallbackWaitTimeout::try_from(CALLBACK_TIMEOUT)
}

fn callback_request(query: &str, port: u16) -> Vec<u8> {
    format!("GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn callback_request_with_header_count(query: &str, port: u16, header_count: usize) -> Vec<u8> {
    assert!(header_count >= 2);

    let mut request =
        format!("GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n").into_bytes();
    for index in 0..header_count - 2 {
        request.extend_from_slice(format!("X-Test-{index}: value\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");

    request
}

fn incomplete_callback_request_at_buffer_threshold(query: &str, port: u16) -> Vec<u8> {
    let mut request =
        format!("GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Fill: ")
            .into_bytes();
    request.extend(std::iter::repeat_n(b'x', MAX_BUFFER_SIZE));

    request
}

async fn send_request(address: SocketAddr, request: Vec<u8>) -> Result<String, std::io::Error> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&request).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;

    Ok(response)
}

async fn send_request_and_wait_for_close(
    address: SocketAddr,
    request: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&request).await?;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
    Ok(())
}

#[test]
fn binds_the_exact_ipv4_loopback_callback_uri() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let redirect = attempt.redirect_uri();

    assert_eq!(redirect.as_url().scheme(), "http");
    assert_eq!(redirect.as_url().host_str(), Some("127.0.0.1"));
    assert_eq!(redirect.as_url().path(), "/callback");
    assert!(redirect.as_url().query().is_none());
    assert!(redirect.as_url().fragment().is_none());
    assert_ne!(callback_address(&attempt)?.port(), 0);
    Ok(())
}

#[test]
fn preserves_the_authorization_inputs_when_binding_the_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = AuthorizationAttempt::start()?;
    let challenge = attempt.pkce_challenge().as_str().to_owned();
    let state = attempt.state().as_str().to_owned();

    let pending = attempt.bind_loopback()?;

    assert_eq!(pending.pkce_challenge().as_str(), challenge);
    assert_eq!(pending.state_parameter(), state);
    Ok(())
}

#[tokio::test]
async fn returns_one_valid_callback_with_its_matching_verifier()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let request = callback_request(
        &format!(
            "code=authorization+code=opaque&state={}",
            attempt.state_parameter()
        ),
        address.port(),
    );
    let client = tokio::spawn(send_request(address, request));

    let completed = attempt.receive(callback_timeout()?, landing()?).await?;
    let response = client.await??;

    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization code=opaque"
    );
    assert_eq!(
        completed.pkce_verifier().as_secret().expose_secret().len(),
        43
    );
    assert!(
        response.starts_with("HTTP/1.1 303 See Other\r\n"),
        "{response}"
    );
    assert!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[tokio::test]
async fn treats_a_matching_oauth_error_as_terminal() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let request = callback_request(
        &format!("error=access_denied&state={}", attempt.state_parameter()),
        address.port(),
    );
    let client = tokio::spawn(send_request(address, request));

    let error = attempt.receive(callback_timeout()?, landing()?).await.err();
    let response = client.await??;

    assert!(matches!(
        error,
        Some(LoopbackCallbackError::AuthorizationRejected(
            LoginRefusal::AccessDenied
        ))
    ));
    assert!(
        response.starts_with("HTTP/1.1 303 See Other\r\n"),
        "{response}"
    );
    assert!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[tokio::test]
async fn an_invalid_state_does_not_consume_the_attempt() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(callback_timeout()?, landing()?));

    let invalid = send_request(
        address,
        callback_request("code=authorization-code&state=wrong-state", address.port()),
    )
    .await?;
    // Same length as the real state, so the rejection comes from the constant
    // time comparison rather than from the length gate in front of it.
    let mut forged = state.clone();
    forged.replace_range(..1, if state.starts_with('a') { "b" } else { "a" });
    let same_length = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={forged}"),
            address.port(),
        ),
    )
    .await?;
    let valid = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(invalid.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(same_length.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(valid.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_host_shapes_do_not_consume_the_attempt() -> Result<(), Box<dyn std::error::Error>>
{
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(callback_timeout()?, landing()?));
    let path = format!("/callback?code=authorization-code&state={state}");
    let mut non_utf8_host = format!("GET {path} HTTP/1.1\r\nHost: ").into_bytes();
    non_utf8_host.push(0xff);
    non_utf8_host.extend_from_slice(b"\r\nConnection: close\r\n\r\n");

    let invalid_requests = [
        format!("GET {path} HTTP/1.1\r\nConnection: close\r\n\r\n").into_bytes(),
        format!(
            "GET {path} HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
            address.port()
        )
        .into_bytes(),
        non_utf8_host,
    ];

    for request in invalid_requests {
        let response = send_request(address, request).await?;
        assert!(!response.starts_with("HTTP/1.1 303 See Other\r\n"));
    }

    let response = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(response.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn incorrect_routes_and_methods_do_not_consume_the_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(callback_timeout()?, landing()?));

    let route_response = send_request(
        address,
        format!(
            "GET /other?code=authorization-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            address.port()
        )
        .into_bytes(),
    )
    .await?;
    let method_response = send_request(
        address,
        format!(
            "POST /callback?code=authorization-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            address.port()
        )
        .into_bytes(),
    )
    .await?;
    let valid_response = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(route_response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(method_response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert!(valid_response.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_query_parameters_do_not_consume_the_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(callback_timeout()?, landing()?));

    let invalid_response = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}&st%61te=duplicate"),
            address.port(),
        ),
    )
    .await?;
    // Longer than any code the terminal path would accept.
    let oversized_response = send_request(
        address,
        callback_request(
            &format!("code={}&state={state}", "a".repeat(513)),
            address.port(),
        ),
    )
    .await?;
    // Exactly the bound is still a code.
    let code = "a".repeat(512);
    let valid_response = send_request(
        address,
        callback_request(
            &format!("code={code}&&state={state}&iss=%FF&future"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(invalid_response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(oversized_response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(valid_response.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        code
    );
    Ok(())
}

#[tokio::test]
async fn accepts_exactly_the_configured_header_limit() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let request = callback_request_with_header_count(
        &format!(
            "code=authorization-code&state={}",
            attempt.state_parameter()
        ),
        address.port(),
        MAX_HEADERS,
    );
    let client = tokio::spawn(send_request(address, request));

    let completed = attempt.receive(callback_timeout()?, landing()?).await?;
    let response = client.await??;

    assert!(response.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn too_many_headers_do_not_consume_the_attempt() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(
        CallbackWaitTimeout::try_from(PARSER_LIMIT_TEST_TIMEOUT)?,
        landing()?,
    ));

    let rejected = send_request(
        address,
        callback_request_with_header_count(
            &format!("code=incorrect-code&state={state}"),
            address.port(),
            MAX_HEADERS + 1,
        ),
    )
    .await?;
    let accepted = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(!rejected.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert!(accepted.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn incomplete_buffer_at_the_limit_does_not_consume_the_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(
        CallbackWaitTimeout::try_from(PARSER_LIMIT_TEST_TIMEOUT)?,
        landing()?,
    ));
    tokio::task::yield_now().await;

    send_request_and_wait_for_close(
        address,
        incomplete_callback_request_at_buffer_threshold(
            &format!("code=incorrect-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let accepted = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(accepted.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn header_read_timeout_does_not_consume_the_attempt() -> Result<(), Box<dyn std::error::Error>>
{
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(
        CallbackWaitTimeout::try_from(HEADER_TIMEOUT_TEST_TIMEOUT)?,
        landing()?,
    ));
    tokio::task::yield_now().await;

    let mut stalled = TcpStream::connect(address).await?;
    stalled
        .write_all(
            format!(
                "GET /callback?code=incorrect-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
                address.port()
            )
            .as_bytes(),
        )
        .await?;
    let close = tokio::spawn(async move {
        let mut response = Vec::new();
        stalled.read_to_end(&mut response).await
    });

    let _ = tokio::time::timeout(HEADER_READ_TIMEOUT + Duration::from_secs(1), close).await???;

    let accepted = send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    )
    .await?;
    let completed = receiver.await??;

    assert!(accepted.starts_with("HTTP/1.1 303 See Other\r\n"));
    assert_eq!(
        completed.authorization_code().as_secret().expose_secret(),
        "authorization-code"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_terminal_callbacks_produce_one_completed_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let first = tokio::spawn(send_request(
        address,
        callback_request(&format!("code=first&state={state}"), address.port()),
    ));
    let second = tokio::spawn(send_request(
        address,
        callback_request(&format!("code=second&state={state}"), address.port()),
    ));

    let completed = attempt.receive(callback_timeout()?, landing()?).await?;
    let _ = first.await?;
    let _ = second.await?;

    assert!(matches!(
        completed.authorization_code().as_secret().expose_secret(),
        "first" | "second"
    ));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_stalled_peer_does_not_extend_the_overall_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let timeout = callback_timeout()?;
    // Connect while the listener is still a plain OS socket. On macOS, awaiting
    // this connection after the paused-time server task starts can let Tokio
    // advance directly to the callback deadline before the connection completes.
    let mut stalled = TcpStream::connect(address).await?;
    let receiver = tokio::spawn(attempt.receive(timeout, landing()?));
    tokio::task::yield_now().await;

    let write_result = stalled.write_all(b"GET /callback?").await;
    tokio::task::yield_now().await;
    tokio::time::advance(CALLBACK_TIMEOUT).await;

    let error = receiver
        .await?
        .err()
        .ok_or_else(|| io::Error::other("a stalled peer must not extend the callback deadline"))?;
    assert_eq!(
        error.to_string(),
        "no valid loopback callback arrived before its deadline"
    );
    if let Err(error) = write_result {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        ));
    }
    assert!(TcpStream::connect(address).await.is_err());
    drop(stalled);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_callback_cannot_arrive_after_the_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let attempt = pending_attempt()?;
    let address = callback_address(&attempt)?;
    let state = attempt.state_parameter().to_owned();
    let receiver = tokio::spawn(attempt.receive(callback_timeout()?, landing()?));
    tokio::task::yield_now().await;
    tokio::time::advance(CALLBACK_TIMEOUT).await;

    let callback = tokio::spawn(send_request(
        address,
        callback_request(
            &format!("code=authorization-code&state={state}"),
            address.port(),
        ),
    ));

    let error = receiver.await?.err();
    let callback = callback.await?;
    assert!(matches!(
        error,
        Some(LoopbackCallbackError::CallbackFailed(_))
    ));
    if let Ok(response) = callback {
        assert!(!response.starts_with("HTTP/1.1 303 See Other\r\n"));
    }
    assert!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[test]
fn rejects_a_zero_callback_timeout() {
    assert!(matches!(
        CallbackWaitTimeout::try_from(Duration::ZERO),
        Err(CallbackTimeoutError::Zero)
    ));
}

#[tokio::test]
async fn a_callback_sends_the_browser_to_the_control_plane_without_a_referrer()
-> Result<(), Box<dyn std::error::Error>> {
    for (query, outcome, refusal) in [
        ("code=opaque", "approved", false),
        ("error=access_denied", "denied", true),
    ] {
        let attempt = pending_attempt()?;
        let address = callback_address(&attempt)?;
        let request = callback_request(
            &format!("{query}&state={}", attempt.state_parameter()),
            address.port(),
        );
        let client = tokio::spawn(send_request(address, request));

        let result = attempt.receive(callback_timeout()?, landing()?).await;
        let response = client.await??;

        assert_eq!(result.is_err(), refusal, "{query}");
        assert!(
            response.starts_with("HTTP/1.1 303 See Other\r\n"),
            "{response}"
        );
        assert!(
            response.contains(&format!(
                "\r\nlocation: https://team.example.com{LANDING_PATH}?outcome={outcome}\r\n"
            )),
            "{response}"
        );
        assert!(
            response.contains("\r\nreferrer-policy: no-referrer\r\n"),
            "{response}"
        );
        assert!(
            !response.contains("opaque"),
            "the one-time code must not reach the Location: {response}"
        );
    }
    Ok(())
}
