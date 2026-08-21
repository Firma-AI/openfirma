use std::str::FromStr;

use firma_http::Str;
#[cfg(not(unix))]
use firma_secret_provider::endpoint::EndpointInner;
use firma_secret_provider::{
    broker::{
        BinaryName, BrokerExitStatus, BrokerOutputChunk, BrokerRequest, BrokerResponse,
        BrokerResponseDecodeError, DecodedBrokerResponse,
        client::{
            BrokerClient,
            config::BrokerClientConfig,
            error::{BrokerClientError, OutcomeUnknownError, ProtocolViolation},
        },
        server::{BrokerListener, config::BrokerListenerConfig},
    },
    endpoint::{client::ClientEndpoint, server::ServerEndpoint},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

mod config;

struct BoundBroker {
    listener: BrokerListener,
    #[cfg(unix)]
    _dir: tempfile::TempDir,
    #[cfg(not(unix))]
    _dir: (),
    endpoint: ClientEndpoint,
}

fn executed_response(stdout: &[u8]) -> BrokerResponse<'static> {
    BrokerResponse::executed(
        [BrokerOutputChunk::Stdout(stdout.to_vec())],
        BrokerExitStatus::Exited { code: 0 },
    )
}

fn decode_stdout(response: BrokerResponse<'_>) -> Result<Vec<u8>, BrokerClientError> {
    match response.decode() {
        Ok(DecodedBrokerResponse::Executed(output)) => Ok(output
            .output
            .into_iter()
            .filter_map(|chunk| match chunk {
                BrokerOutputChunk::Stdout(bytes) => Some(bytes),
                BrokerOutputChunk::Stderr(_) => None,
            })
            .flatten()
            .collect()),
        Ok(DecodedBrokerResponse::Rejected(error)) => Err(BrokerClientError::Rejected(error)),
        Err(error) => Err(BrokerClientError::ProtocolViolation(
            ProtocolViolation::Output(error),
        )),
    }
}

/// Bind a listener on a fresh Unix socket in a temp dir.
#[cfg(unix)]
async fn bind_broker() -> anyhow::Result<BoundBroker> {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir()?;
    tokio::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).await?;
    let path = dir.path().join("broker.sock");
    let endpoint = ServerEndpoint::from_str(&format!("unix://{}", path.display()))?;
    let listener = BrokerListener::bind(&endpoint, BrokerListenerConfig::default()).await?;
    Ok(BoundBroker {
        listener,
        _dir: dir,
        endpoint: ClientEndpoint::from_str(&format!("unix://{}", path.display()))?,
    })
}

/// Bind a listener on a fresh loopback TCP port (the Windows transport).
#[cfg(not(unix))]
async fn bind_broker() -> anyhow::Result<BoundBroker> {
    let endpoint = ServerEndpoint::from_str("tcp://127.0.0.1:0")?;
    let listener = BrokerListener::bind(&endpoint, BrokerListenerConfig::default()).await?;
    let EndpointInner::Tcp(addr) = listener.bound_endpoint()?;
    Ok(BoundBroker {
        listener,
        _dir: (),
        endpoint: ClientEndpoint::from_str(&format!("tcp://{addr}"))?,
    })
}

fn serve_ok(listener: BrokerListener, stdout: Vec<u8>) {
    tokio::spawn(async move {
        #[expect(clippy::expect_used, reason = "this is a test")]
        listener
            .accept_one(async move |_req| executed_response(&stdout))
            .await
            .expect("accept_one");
    });
}

#[tokio::test]
async fn run_returns_decoded_stdout() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_broker().await.expect("bind");
    serve_ok(listener, b"secret-value".to_vec());
    let client = BrokerClient::new(endpoint, BrokerClientConfig::default());
    let output = client
        .run("bws", &["secret", "get", "abc"])
        .await
        .expect("run");
    assert_eq!(
        output.output,
        [BrokerOutputChunk::Stdout(b"secret-value".to_vec())]
    );
    assert_eq!(output.status, BrokerExitStatus::Exited { code: 0 });
}

#[tokio::test]
async fn run_propagates_broker_rejection() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_broker().await.expect("bind");
    tokio::spawn(async move {
        listener
            .accept_one(async |_req| BrokerResponse::rejected("tool not found"))
            .await
            .expect("accept_one");
    });
    let client = BrokerClient::new(endpoint, BrokerClientConfig::default());
    let error = client
        .run("bws", &["secret", "get", "x"])
        .await
        .expect_err("rejected");
    std::assert_matches!(error, BrokerClientError::Rejected(_));
}

#[tokio::test]
async fn request_fails_closed_when_response_exceeds_buffer() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_broker().await.expect("bind");
    serve_ok(listener, vec![b'x'; 256]);
    let config = BrokerClientConfig {
        max_response_size: bytesize::ByteSize::b(64),
        ..BrokerClientConfig::default()
    };
    let client = BrokerClient::new(endpoint, config);
    let error = client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
            },
            |_| Ok(()),
        )
        .await;
    std::assert_matches!(
        error,
        Err(BrokerClientError::ProtocolViolation(
            ProtocolViolation::ResponseTooLarge
        ))
    );
}

#[tokio::test]
async fn request_accepts_response_exactly_at_buffer_limit() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_broker().await.expect("bind");
    // A response whose encoded JSON line is exactly `max_response_size`
    // bytes must be accepted (the trailing newline must not count against
    // the limit). Sizing the limit from the real serialized payload keeps
    // the boundary exact.
    let stdout = vec![b'x'; 42];
    let response_payload = serde_json::to_vec(&executed_response(&stdout)).expect("serialize");
    let config = BrokerClientConfig {
        max_response_size: bytesize::ByteSize::b(response_payload.len() as u64),
        ..BrokerClientConfig::default()
    };
    serve_ok(listener, stdout.clone());
    let client = BrokerClient::new(endpoint, config);
    let response = client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
            },
            decode_stdout,
        )
        .await;
    assert_eq!(response.expect("response"), stdout);
}

/// Bind a bare listener that answers the first connection with `padded`
/// raw bytes, bypassing [`BrokerListener`] so the test can send a response
/// line that no serializer would produce (e.g. whitespace-padded).
#[cfg(unix)]
#[expect(clippy::expect_used, reason = "this is a test")]
fn bind_raw_responder(padded: Vec<u8>) -> (ClientEndpoint, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("set_permissions");
    let path = dir.path().join("broker.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("set_permissions");
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("accept");
        let mut reader = tokio::io::BufReader::new(&mut conn);
        let mut request = Vec::new();
        let _ = reader.read_until(b'\n', &mut request).await;
        drop(reader);
        conn.write_all(&padded).await.expect("write");
    });
    (
        ClientEndpoint::from_str(&format!("unix://{}", path.display())).expect("valid endpoint"),
        dir,
    )
}

/// Windows twin of [`bind_raw_responder`], using the TCP transport.
#[cfg(not(unix))]
#[expect(clippy::expect_used, reason = "this is a test")]
fn bind_raw_responder(padded: Vec<u8>) -> (ClientEndpoint, ()) {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let listener = tokio::net::TcpListener::from_std(std_listener).expect("tcp listener");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("accept");
        let mut reader = tokio::io::BufReader::new(&mut conn);
        let mut request = Vec::new();
        let _ = reader.read_until(b'\n', &mut request).await;
        drop(reader);
        conn.write_all(&padded).await.expect("write");
    });
    (
        ClientEndpoint::from_str(&format!("tcp://{addr}")).expect("valid endpoint"),
        (),
    )
}

#[tokio::test]
async fn request_rejects_over_limit_line_padded_with_whitespace() {
    let stdout = b"secret-value".to_vec();
    let response_payload = serde_json::to_vec(&executed_response(&stdout)).expect("serialize");
    // The broker pads the response line with a trailing space, so the raw
    // line is one byte over `max_response_size` even though the trimmed
    // content is not. The size check must measure the line, not the
    // trimmed content.
    let mut padded = response_payload.clone();
    padded.push(b' ');
    padded.push(b'\n');
    let (endpoint, _guard) = bind_raw_responder(padded);
    let config = BrokerClientConfig {
        max_response_size: bytesize::ByteSize::b(response_payload.len() as u64),
        ..BrokerClientConfig::default()
    };
    let client = BrokerClient::new(endpoint, config);
    let error = client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
            },
            |_| Ok(()),
        )
        .await;
    assert!(
        matches!(
            error,
            Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::ResponseTooLarge
            ))
        ),
        "unexpected error: {error:?}"
    );
}

/// Runs a single `request` round-trip against `raw_response` bytes written
/// by a bare responder, returning the client error.
#[expect(clippy::expect_used, reason = "this is a test")]
async fn raw_response_error(raw_response: &[u8]) -> BrokerClientError {
    let (endpoint, _guard) = bind_raw_responder(raw_response.to_vec());
    let client = BrokerClient::new(endpoint, BrokerClientConfig::default());
    client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
            },
            |_| Ok(()),
        )
        .await
        .expect_err("protocol-violating response must fail closed")
}

#[tokio::test]
async fn request_rejects_invalid_base64_stdout() {
    // `run`'s exec closure decodes the success payload's base64, so the
    // malformed-payload path lives there rather than in the generic
    // `request` deserialization.
    let (endpoint, _guard) = bind_raw_responder(
        br#"{"type":"executed","output":[{"stream":"stdout","data":"not-base64!!"}],"status":{"type":"exited","code":0}}"#
            .to_vec(),
    );
    let client = BrokerClient::new(endpoint, BrokerClientConfig::default());
    let error = client
        .run("bws", &["secret", "get", "abc"])
        .await
        .expect_err("invalid base64 must fail closed");
    std::assert_matches!(
        error,
        BrokerClientError::ProtocolViolation(ProtocolViolation::Output(
            BrokerResponseDecodeError::Stdout { index: 0, .. }
        ))
    );
}

#[tokio::test]
async fn request_rejects_invalid_base64_stderr() {
    let (endpoint, _guard) = bind_raw_responder(
        br#"{"type":"executed","output":[{"stream":"stderr","data":"not-base64!!"}],"status":{"type":"exited","code":0}}"#
            .to_vec(),
    );
    let client = BrokerClient::new(endpoint, BrokerClientConfig::default());
    let error = client
        .run("bws", &["secret", "get", "abc"])
        .await
        .expect_err("invalid base64 must fail closed");
    std::assert_matches!(
        error,
        BrokerClientError::ProtocolViolation(ProtocolViolation::Output(
            BrokerResponseDecodeError::Stderr { index: 0, .. }
        ))
    );
}

#[tokio::test]
async fn request_rejects_non_utf8_response_line() {
    let error = raw_response_error(&[0xff, 0xfe, b'\n']).await;
    std::assert_matches!(
        error,
        BrokerClientError::ProtocolViolation(ProtocolViolation::InvalidUtf8(_))
    );
}

#[tokio::test]
async fn request_rejects_empty_response_line() {
    let error = raw_response_error(b"\n").await;
    std::assert_matches!(
        error,
        BrokerClientError::OutcomeUnknown {
            source: OutcomeUnknownError::Empty,
            ..
        }
    );
}

#[tokio::test]
async fn request_rejects_malformed_response_json() {
    let error = raw_response_error(b"not json\n").await;
    std::assert_matches!(
        error,
        BrokerClientError::ProtocolViolation(ProtocolViolation::Deserialize(_))
    );
}

#[tokio::test]
async fn request_fails_closed_when_request_exceeds_buffer() {
    let BoundBroker {
        listener: _never_used,
        endpoint,
        _dir,
    } = bind_broker().await.expect("bind");
    let config = BrokerClientConfig {
        max_request_size: bytesize::ByteSize::b(16),
        ..BrokerClientConfig::default()
    };
    let client = BrokerClient::new(endpoint, config);
    let error = client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("x".repeat(64))],
            },
            |_| Ok(()),
        )
        .await;
    std::assert_matches!(error, Err(BrokerClientError::RequestTooLarge { .. }));
}

#[tokio::test]
async fn request_fails_closed_when_operation_times_out() {
    // Bind a listener but never accept: the client connects into the
    // backlog, writes its request, and must time out waiting for a
    // response that never arrives.
    let BoundBroker {
        listener: _kept_alive,
        endpoint,
        _dir,
    } = bind_broker().await.expect("bind");
    let config = BrokerClientConfig {
        operation_timeout: std::time::Duration::from_millis(100),
        ..BrokerClientConfig::default()
    };
    let client = BrokerClient::new(endpoint, config);
    let error = client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
            },
            |_| Ok(()),
        )
        .await;
    std::assert_matches!(
        error,
        Err(BrokerClientError::OutcomeUnknown {
            source: OutcomeUnknownError::OperationTimeout,
            ..
        })
    );
}

#[cfg(not(unix))]
#[tokio::test]
async fn request_fails_fast_when_broker_is_unreachable() {
    let endpoint = ClientEndpoint::from_str("tcp://127.0.0.1:1").expect("valid addr");
    let client = BrokerClient::new(endpoint, BrokerClientConfig::default());
    let error = client
        .request(
            &BrokerRequest {
                bin: BinaryName::new("bws").expect("valid binary name"),
                args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
            },
            |_| Ok(()),
        )
        .await;
    std::assert_matches!(error, Err(BrokerClientError::Unavailable { .. }));
}
