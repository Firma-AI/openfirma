use firma_http::Authority;
use firma_secret_provider::{
    SecretPlaceholder,
    gateway::{
        client::{
            GatewayClient, ResolveError,
            config::GatewayClientConfig,
            error::{GatewayClientError, ProtocolViolation, TransportError},
        },
        endpoint::{GatewayEndpoint, GatewayEndpointParseError},
    },
};
use secrecy::SecretString;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

/// Binds an ephemeral TCP listener that accepts a single connection,
/// reads its request line, and (if `response` is non-empty) writes back
/// `response` followed by a newline before closing. An empty `response`
/// closes the connection without writing anything, to exercise the
/// empty-response error path.
async fn mock_gateway(response: &str) -> Result<GatewayEndpoint, GatewayEndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(GatewayEndpointParseError::IO)?;
    let addr = listener
        .local_addr()
        .map_err(GatewayEndpointParseError::IO)?;
    let response = response.to_owned();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            if !response.is_empty() {
                let _ = writer.write_all(response.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
            }
            let _ = writer.shutdown().await;
        }
    });
    GatewayEndpoint::parse(&format!("tcp:{addr}"))
}

/// Binds an ephemeral TCP listener that accepts a single connection, reads
/// its request line, then writes back `response` verbatim (no trailing
/// newline) before closing. Used to simulate a gateway that never terminates
/// its response line, to exercise the bounded-read path.
async fn mock_gateway_unterminated(
    response: &[u8],
) -> Result<GatewayEndpoint, GatewayEndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(GatewayEndpointParseError::IO)?;
    let addr = listener
        .local_addr()
        .map_err(GatewayEndpointParseError::IO)?;
    let response = response.to_owned();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            let _ = writer.write_all(&response).await;
            let _ = writer.shutdown().await;
        }
    });
    GatewayEndpoint::parse(&format!("tcp:{addr}"))
}

/// Binds an ephemeral TCP listener and immediately drops it, yielding an
/// address nothing is listening on, to exercise the connect-failure path.
async fn unreachable_endpoint() -> Result<GatewayEndpoint, GatewayEndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(GatewayEndpointParseError::IO)?;
    let addr = listener
        .local_addr()
        .map_err(GatewayEndpointParseError::IO)?;
    drop(listener);
    GatewayEndpoint::parse(&format!("tcp:{addr}"))
}

#[tokio::test]
async fn resolve_batch_returns_empty_without_io_for_empty_placeholders() {
    // Deliberately unreachable: an empty batch must short-circuit before
    // any connection is attempted.
    let client = GatewayClient::new(
        unreachable_endpoint().await.expect("unreachable endpoint"),
        GatewayClientConfig::default(),
    );
    let result = client
        .resolve_batch(&[], Authority::from_static("example.com"))
        .await
        .expect("empty batch needs no io");
    assert!(result.is_ok_and(|vec| vec.is_empty()));
}

#[tokio::test]
async fn resolve_batch_maps_per_placeholder_results() {
    let client = GatewayClient::new(mock_gateway(
            r#"[{"type":"ok","secret_b64":"aGVsbG8="},{"type":"ok","secret_b64":"not-base64!!"},{"type":"err","error":"unknown placeholder"}]"#,
        )
        .await.expect("mock gateway"), GatewayClientConfig::default());

    let result = client
        .resolve_batch(
            &[
                SecretPlaceholder::new(),
                SecretPlaceholder::new(),
                SecretPlaceholder::new(),
            ],
            Authority::from_static("example.com"),
        )
        .await
        .expect("outer call succeeds");

    assert!(result.is_err());
    std::assert_matches!(result, Err(ResolveError::Base64(_)));
}

#[tokio::test]
async fn resolve_batch_rejects_mismatched_result_count() {
    let client = GatewayClient::new(
        mock_gateway(r#"[{"type":"ok","secret_b64":"aGVsbG8="}]"#)
            .await
            .expect("mock gateway"),
        GatewayClientConfig::default(),
    );

    let err = client
        .resolve_batch(
            &[SecretPlaceholder::new(), SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect_err("count mismatch");
    std::assert_matches!(
        err,
        GatewayClientError::ProtocolViolation(ProtocolViolation::Mismatch {
            results,
            placeholders
        }) if results == 1 && placeholders == 2
    );
}

#[tokio::test]
async fn resolve_batch_rejects_malformed_response() {
    let client = GatewayClient::new(
        mock_gateway("not json").await.expect("mock gateway"),
        GatewayClientConfig::default(),
    );

    let err = client
        .resolve_batch(
            &[SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect_err("malformed response");
    std::assert_matches!(
        err,
        GatewayClientError::ProtocolViolation(ProtocolViolation::Deserialize(_))
    );
}

#[tokio::test]
async fn resolve_batch_reports_empty_response_line() {
    let client = GatewayClient::new(
        mock_gateway("").await.expect("mock gateway"),
        GatewayClientConfig::default(),
    );

    let err = client
        .resolve_batch(
            &[SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect_err("empty response");
    std::assert_matches!(
        err,
        GatewayClientError::Transport {
            source: TransportError::Empty,
            ..
        }
    );
}

#[tokio::test]
async fn resolve_batch_rejects_oversized_unterminated_response() {
    // A response line without a trailing newline that exceeds max_buffer_size
    // must be rejected instead of buffered without bound; caps max_buffer_size
    // low so the test doesn't need to push megabytes to exercise the limit.
    let client = GatewayClient::new(
        mock_gateway_unterminated(&[b'['; 64])
            .await
            .expect("mock gateway"),
        GatewayClientConfig {
            max_buffer_size: bytesize::ByteSize::b(16),
            ..Default::default()
        },
    );

    let err = client
        .resolve_batch(
            &[SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect_err("oversized unterminated response");
    std::assert_matches!(
        err,
        GatewayClientError::ProtocolViolation(ProtocolViolation::MaxBufferSizeExceeded)
    );
}

#[tokio::test]
async fn resolve_batch_reports_unreachable_gateway() {
    let client = GatewayClient::new(
        unreachable_endpoint().await.expect("unreachable endpoint"),
        GatewayClientConfig {
            connection_timeout: std::time::Duration::from_hours(1),
            ..Default::default()
        },
    );

    let err = client
        .resolve_batch(
            &[SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect_err("unreachable");
    std::assert_matches!(
        err,
        GatewayClientError::Transport {
            source: TransportError::Connect(_),
            ..
        }
    );
}

#[tokio::test]
async fn push_secret_returns_placeholder_on_success() {
    let placeholder = SecretPlaceholder::new();
    let secret = SecretString::from("s3cr3t");
    let client = GatewayClient::new(
        mock_gateway(&format!(r#"{{"type":"ok","placeholder":"{placeholder}"}}"#))
            .await
            .expect("mock gateway"),
        GatewayClientConfig::default(),
    );

    let returned = client
        .push_secret(&placeholder, &secret, vec![])
        .await
        .expect("push succeeds");
    assert_eq!(returned, placeholder);
}

#[tokio::test]
async fn push_secret_reports_gateway_rejection() {
    let placeholder = SecretPlaceholder::new();
    let secret = SecretString::from("s3cr3t");
    let client = GatewayClient::new(
        mock_gateway(r#"{"type":"err","error":"malformed placeholder"}"#)
            .await
            .expect("mock gateway"),
        GatewayClientConfig::default(),
    );

    let err = client
        .push_secret(&placeholder, &secret, vec![])
        .await
        .expect_err("rejected");
    std::assert_matches!(err, GatewayClientError::Rejected(err) if err == "malformed placeholder");
}

#[tokio::test]
async fn push_secret_rejects_malformed_response() {
    let placeholder = SecretPlaceholder::new();
    let secret = SecretString::from("s3cr3t");
    let client = GatewayClient::new(
        mock_gateway("not json").await.expect("mock gateway"),
        GatewayClientConfig::default(),
    );

    let err = client
        .push_secret(&placeholder, &secret, vec![])
        .await
        .expect_err("malformed response");
    std::assert_matches!(
        err,
        GatewayClientError::ProtocolViolation(ProtocolViolation::Deserialize(_))
    );
}

#[tokio::test]
async fn push_secret_reports_unreachable_gateway() {
    let placeholder = SecretPlaceholder::new();
    let secret = SecretString::from("s3cr3t");
    let client = GatewayClient::new(
        unreachable_endpoint().await.expect("unreachable endpoint"),
        GatewayClientConfig {
            connection_timeout: std::time::Duration::from_hours(1),
            ..Default::default()
        },
    );

    let err = client
        .push_secret(&placeholder, &secret, vec![])
        .await
        .expect_err("unreachable");
    std::assert_matches!(
        err,
        GatewayClientError::Transport {
            source: TransportError::Connect(_),
            ..
        }
    );
}
