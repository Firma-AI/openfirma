use std::str::FromStr;

use firma_http::Str;
use firma_secret_provider::{
    broker::{
        BinaryName, BrokerExitStatus, BrokerOutput, BrokerRequest, BrokerResponse,
        DecodedBrokerResponse,
        server::{BrokerListener, config::BrokerListenerConfig},
        stream::BrokerStream,
    },
    endpoint::{EndpointInner, server::ServerEndpoint},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

mod config;

struct BoundBroker {
    listener: BrokerListener,
    #[cfg(unix)]
    _dir: tempfile::TempDir,
    #[cfg(not(unix))]
    _dir: (),
    endpoint: ServerEndpoint,
}

fn executed_response(stdout: &[u8]) -> BrokerResponse<'static> {
    BrokerResponse::executed(stdout, b"", BrokerExitStatus::Exited { code: 0 })
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn decode_output(response: BrokerResponse<'_>) -> Result<BrokerOutput, String> {
    match response.decode().expect("valid response output") {
        DecodedBrokerResponse::Executed(output) => Ok(output),
        DecodedBrokerResponse::Rejected(error) => Err(error),
    }
}

/// Bind a listener on a fresh Unix socket in a temp dir.
#[cfg(unix)]
async fn bind_with_config(config: BrokerListenerConfig) -> anyhow::Result<BoundBroker> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("broker.sock");
    let endpoint = ServerEndpoint::from_str(&format!("unix://{}", path.display()))?;
    let listener = BrokerListener::bind(&endpoint, config).await?;
    Ok(BoundBroker {
        listener,
        _dir: dir,
        endpoint,
    })
}

/// Bind a listener on a fresh loopback TCP port (the Windows transport).
#[cfg(not(unix))]
async fn bind_with_config(config: BrokerListenerConfig) -> anyhow::Result<BoundBroker> {
    let endpoint = ServerEndpoint::from_str("tcp://127.0.0.1:0")?;
    let listener = BrokerListener::bind(&endpoint, config).await?;
    let EndpointInner::Tcp(addr) = listener.bound_endpoint()?;
    Ok(BoundBroker {
        listener,
        _dir: (),
        endpoint: ServerEndpoint::from_str(&format!("tcp://{addr}"))?,
    })
}

async fn connect_and_send(
    endpoint: &ServerEndpoint,
    request: &BrokerRequest<'_>,
) -> anyhow::Result<String> {
    let mut stream: BrokerStream = match endpoint.as_inner() {
        EndpointInner::Tcp(addr) => BrokerStream::Tcp {
            stream: tokio::net::TcpStream::connect(addr).await?,
        },
        #[cfg(unix)]
        EndpointInner::Unix(path) => BrokerStream::Unix {
            stream: tokio::net::UnixStream::connect(path).await?,
        },
    };
    let payload = serde_json::to_string(request)?;
    stream.write_all(format!("{payload}\n").as_bytes()).await?;
    stream.flush().await?;
    let mut reader = tokio::io::BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

async fn connect_and_send_raw(endpoint: &ServerEndpoint, raw: &[u8]) -> anyhow::Result<String> {
    let mut stream: BrokerStream = match endpoint.as_inner() {
        EndpointInner::Tcp(addr) => BrokerStream::Tcp {
            stream: tokio::net::TcpStream::connect(addr).await?,
        },
        #[cfg(unix)]
        EndpointInner::Unix(path) => BrokerStream::Unix {
            stream: tokio::net::UnixStream::connect(path).await?,
        },
    };
    stream.write_all(raw).await?;
    stream.flush().await?;
    let mut reader = tokio::io::BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

#[tokio::test]
async fn roundtrip_ok_response() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig::default())
        .await
        .expect("bind");
    let request = BrokerRequest {
        bin: BinaryName::new("bws").expect("valid binary name"),
        args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
    };
    let request_clone = request.clone();
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |req| {
                assert_eq!(req, request_clone);
                executed_response(b"secret-value")
            })
            .await
            .expect("accept_one");
    });
    let line = connect_and_send(&endpoint, &request)
        .await
        .expect("connect_and_send");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert_eq!(
        decode_output(response).expect("executed").stdout,
        b"secret-value"
    );
}

#[tokio::test]
async fn handler_error_written_as_error_response() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig::default())
        .await
        .expect("bind");
    let request = BrokerRequest {
        bin: BinaryName::new("bws").expect("valid binary name"),
        args: vec![Str::from("secret"), Str::from("get"), Str::from("x")],
    };
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| BrokerResponse::rejected("tool not found"))
            .await
            .expect("accept_one");
    });
    let line = connect_and_send(&endpoint, &request)
        .await
        .expect("connect_and_send");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert_eq!(decode_output(response), Err(String::from("tool not found")));
}

#[tokio::test]
async fn oversized_response_is_replaced_with_clean_error() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig {
        max_response_size: bytesize::ByteSize::b(64),
        ..BrokerListenerConfig::default()
    })
    .await
    .expect("bind");
    let request = BrokerRequest {
        bin: BinaryName::new("bws").expect("valid binary name"),
        args: vec![Str::from("secret"), Str::from("get"), Str::from("x")],
    };
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| executed_response(&vec![b'x'; 256]))
            .await
            .expect("accept_one");
    });
    let line = connect_and_send(&endpoint, &request)
        .await
        .expect("connect_and_send");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert_eq!(
        decode_output(response).expect_err("must be an error"),
        "response too large"
    );
}

#[tokio::test]
async fn response_exactly_at_limit_is_forwarded() {
    // Size the cap from the real serialized payload so the boundary is exact:
    // a response line equal to `max_response_bytes` must pass, the trailing
    // newline must not count against the limit.
    let stdout = vec![b'y'; 42];
    let payload = serde_json::to_vec(&executed_response(&stdout)).expect("serialize");
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig {
        max_response_size: bytesize::ByteSize::b(payload.len() as u64),
        ..BrokerListenerConfig::default()
    })
    .await
    .expect("bind");
    let request = BrokerRequest {
        bin: BinaryName::new("bws").expect("valid binary name"),
        args: vec![Str::from("secret"), Str::from("get"), Str::from("x")],
    };
    let served_stdout = stdout.clone();
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| executed_response(&served_stdout))
            .await
            .expect("accept_one");
    });
    let line = connect_and_send(&endpoint, &request)
        .await
        .expect("connect_and_send");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert_eq!(decode_output(response).expect("executed").stdout, stdout);
}

#[cfg(windows)]
#[tokio::test]
async fn bound_endpoint_returns_assigned_tcp_port() {
    let BoundBroker { endpoint, .. } = bind_with_config(BrokerListenerConfig::default())
        .await
        .expect("bind");
    let EndpointInner::Tcp(addr) = endpoint.as_inner();
    assert_ne!(addr.port(), 0, "OS must assign a non-zero port");
}

#[tokio::test]
async fn oversize_request_is_rejected() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig {
        max_request_size: bytesize::ByteSize::b(4000),
        ..BrokerListenerConfig::default()
    })
    .await
    .expect("bind");
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| panic!("oversize request must not reach the handler"))
            .await
            .expect("accept_one");
    });
    let big = "x".repeat(4096);
    let line = connect_and_send_raw(&endpoint, format!("{{\"bin\":\"{big}\"}}\n").as_bytes())
        .await
        .expect("connect_and_send_raw");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert!(decode_output(response).is_err());
}

#[tokio::test]
async fn request_padded_with_whitespace_over_limit_is_rejected() {
    let limit = 64u64;
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig {
        max_request_size: bytesize::ByteSize::b(limit),
        ..BrokerListenerConfig::default()
    })
    .await
    .expect("bind");
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| panic!("oversize request must not reach the handler"))
            .await
            .expect("accept_one");
    });
    // A valid request is shorter than the limit; pad it with leading
    // whitespace so the raw line is `limit + 1` bytes even though the
    // trimmed content is not. The size check must measure the line, not
    // the trimmed content.
    let request = BrokerRequest {
        bin: BinaryName::new("bws").expect("valid binary name"),
        args: vec![Str::from("secret"), Str::from("get"), Str::from("abc")],
    };
    let json = serde_json::to_string(&request).expect("serialize");
    let mut padded = " ".repeat(usize::try_from(limit + 1).expect("usize") - json.len());
    padded.push_str(&json);
    padded.push('\n');
    let line = connect_and_send_raw(&endpoint, padded.as_bytes())
        .await
        .expect("connect_and_send_raw");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert!(decode_output(response).is_err());
}

#[tokio::test]
async fn malformed_request_is_rejected_without_reaching_handler() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig::default())
        .await
        .expect("bind");
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| panic!("malformed request must not reach the handler"))
            .await
            .expect("accept_one");
    });
    let line = connect_and_send_raw(&endpoint, b"this is not json\n")
        .await
        .expect("connect_and_send_raw");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert!(decode_output(response).is_err());
}

#[tokio::test]
async fn empty_request_is_rejected_without_reaching_handler() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig::default())
        .await
        .expect("bind");
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| panic!("empty request must not reach the handler"))
            .await
            .expect("accept_one");
    });
    let line = connect_and_send_raw(&endpoint, b"\n")
        .await
        .expect("connect_and_send_raw");
    server.await.expect("server task");
    let response: BrokerResponse = serde_json::from_str(line.trim()).expect("deserialize");
    assert!(decode_output(response).is_err());
}

#[tokio::test]
async fn non_utf8_request_is_rejected_without_reaching_handler() {
    let BoundBroker {
        listener,
        endpoint,
        _dir,
    } = bind_with_config(BrokerListenerConfig::default())
        .await
        .expect("bind");
    let server = tokio::spawn(async move {
        listener
            .accept_one(async |_req| panic!("non-utf8 request must not reach the handler"))
            .await
            .expect_err("non-utf8 request must fail accept_one");
    });
    // The server cannot serialize a response to a peer that sent invalid
    // bytes, so the connection is closed without a response line.
    let line = connect_and_send_raw(&endpoint, &[0xff, 0xfe, b'\n'])
        .await
        .expect("connect_and_send_raw");
    server.await.expect("server task");
    assert!(line.is_empty(), "connection must close without a response");
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broker.sock");
    let endpoint =
        ServerEndpoint::from_str(&format!("unix://{}", path.display())).expect("valid endpoint");
    let listener = BrokerListener::bind(&endpoint, BrokerListenerConfig::default())
        .await
        .expect("bind");
    let metadata = std::fs::metadata(&path).expect("metadata");
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o600,
        "broker socket must be owner-only"
    );
    drop(listener);
    assert!(!path.exists(), "drop must remove the socket file");
}
