use std::{collections::HashSet, str::FromStr};

use firma_config_schema::{gateway::GatewayConfig, utils::NonZeroDuration};
use firma_http::Authority;
use firma_secret_provider::{
    ExposeSecret, SecretPlaceholder,
    endpoint::{client::ClientEndpoint, error::EndpointParseError},
    gateway::client::{
        GatewayClient, ResolveError,
        error::{GatewayClientError, ProtocolViolation, TransportError},
    },
};
use secrecy::SecretString;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

/// Binds an ephemeral TCP listener that accepts a single connection,
/// reads its request line, and (if `response` is non-empty) writes back
/// `response` followed by a newline before closing. An empty `response`
/// closes the connection without writing anything, to exercise the
/// empty-response error path.
async fn mock_gateway(response: &str) -> Result<ClientEndpoint, EndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(EndpointParseError::IO)?;
    let addr = listener.local_addr().map_err(EndpointParseError::IO)?;
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
    ClientEndpoint::from_str(&format!("tcp://{addr}"))
}

/// Binds an ephemeral TCP listener that accepts a single connection, reads
/// its request line, then writes back `response` verbatim (no trailing
/// newline) before closing. Used to simulate a gateway that never terminates
/// its response line, to exercise the bounded-read path.
async fn mock_gateway_unterminated(response: &[u8]) -> Result<ClientEndpoint, EndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(EndpointParseError::IO)?;
    let addr = listener.local_addr().map_err(EndpointParseError::IO)?;
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
    ClientEndpoint::from_str(&format!("tcp://{addr}"))
}

/// Binds an ephemeral TCP listener that accepts a single connection, reads
/// the request, and then holds the connection open without responding until
/// the client gives up, to exercise the operation-timeout path.
async fn mock_gateway_silent() -> Result<ClientEndpoint, EndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(EndpointParseError::IO)?;
    let addr = listener.local_addr().map_err(EndpointParseError::IO)?;
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut stream = stream;
            let mut buf = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        }
    });
    ClientEndpoint::from_str(&format!("tcp://{addr}"))
}

/// Binds an ephemeral TCP listener that immediately drops it, yielding an
/// address nothing is listening on, to exercise the connect-failure path.
async fn unreachable_endpoint() -> Result<ClientEndpoint, EndpointParseError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(EndpointParseError::IO)?;
    let addr = listener.local_addr().map_err(EndpointParseError::IO)?;
    drop(listener);
    ClientEndpoint::from_str(&format!("tcp://{addr}"))
}

#[tokio::test]
async fn resolve_batch_returns_empty_without_io_for_empty_placeholders() {
    // Deliberately unreachable: an empty batch must short-circuit before
    // any connection is attempted.
    let client = GatewayClient::new(
        unreachable_endpoint().await.expect("unreachable endpoint"),
        GatewayConfig::default(),
    );
    let result = client
        .resolve_batch(vec![], Authority::from_static("example.com"))
        .await
        .expect("empty batch needs no io");
    assert!(result.is_ok_and(|vec| vec.is_empty()));
}

#[tokio::test]
async fn resolve_batch_maps_all_ok_results_in_order() {
    let client = GatewayClient::new(
        mock_gateway(
            r#"[{"type":"ok","secret_b64":"aGVsbG8="},{"type":"ok","secret_b64":"d29ybGQ="}]"#,
        )
        .await
        .expect("mock gateway"),
        GatewayConfig::default(),
    );

    let secrets = client
        .resolve_batch(
            vec![SecretPlaceholder::new(), SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect("outer call succeeds")
        .expect("all placeholders resolve");

    assert_eq!(
        secrets
            .iter()
            .map(ExposeSecret::expose_secret)
            .collect::<Vec<_>>(),
        ["hello", "world"]
    );
}

#[tokio::test]
async fn resolve_batch_reports_per_placeholder_gateway_error() {
    let client = GatewayClient::new(
        mock_gateway(r#"[{"type":"err","error":"unknown placeholder"}]"#)
            .await
            .expect("mock gateway"),
        GatewayConfig::default(),
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect("outer call succeeds")
        .expect_err("gateway error result");
    std::assert_matches!(
        err,
        ResolveError::Gateway(ref message) if message == "unknown placeholder"
    );
    insta::assert_snapshot!(err.to_string(), @"gateway error: unknown placeholder");
}

#[tokio::test]
async fn resolve_batch_rejects_non_utf8_secret() {
    let client = GatewayClient::new(
        mock_gateway(r#"[{"type":"ok","secret_b64":"/w=="}]"#)
            .await
            .expect("mock gateway"),
        GatewayConfig::default(),
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect("outer call succeeds")
        .expect_err("non-utf8 secret");
    std::assert_matches!(err, ResolveError::Utf8);
}

#[tokio::test]
async fn resolve_batch_reports_operation_timeout() {
    let client = GatewayClient::new(
        mock_gateway_silent().await.expect("silent mock gateway"),
        GatewayConfig {
            operation_timeout: NonZeroDuration::new(std::time::Duration::from_millis(100))
                .expect("non-zero operation timeout"),
            ..Default::default()
        },
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect_err("operation timeout");
    std::assert_matches!(
        err,
        GatewayClientError::Transport {
            source: TransportError::OperationTimeout,
            ..
        }
    );
}

#[tokio::test]
async fn resolve_batch_maps_per_placeholder_results() {
    let client = GatewayClient::new(mock_gateway(
            r#"[{"type":"ok","secret_b64":"aGVsbG8="},{"type":"ok","secret_b64":"not-base64!!"},{"type":"err","error":"unknown placeholder"}]"#,
        )
        .await.expect("mock gateway"), GatewayConfig::default());

    let result = client
        .resolve_batch(
            vec![
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
        GatewayConfig::default(),
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new(), SecretPlaceholder::new()],
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
        GatewayConfig::default(),
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
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
        GatewayConfig::default(),
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
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
        GatewayConfig {
            max_buffer_size: bytesize::ByteSize::b(16),
            ..Default::default()
        },
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
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
async fn resolve_batch_does_not_preallocate_configured_maximum() {
    let client = GatewayClient::new(
        mock_gateway(r#"[{"type":"ok","secret_b64":"aA=="}]"#)
            .await
            .expect("mock gateway"),
        GatewayConfig {
            max_buffer_size: bytesize::ByteSize::b(u64::MAX),
            ..Default::default()
        },
    );

    let secrets = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
            Authority::from_static("example.com"),
        )
        .await
        .expect("transport succeeds")
        .expect("resolution succeeds");

    assert_eq!(secrets.len(), 1);
}

#[tokio::test]
async fn resolve_batch_reports_unreachable_gateway() {
    let client = GatewayClient::new(
        unreachable_endpoint().await.expect("unreachable endpoint"),
        GatewayConfig {
            connection_timeout: NonZeroDuration::new(std::time::Duration::from_hours(1))
                .expect("non-zero connection timeout"),
            ..Default::default()
        },
    );

    let err = client
        .resolve_batch(
            vec![SecretPlaceholder::new()],
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
        GatewayConfig::default(),
    );

    let returned = client
        .push_secret(placeholder.clone(), secret, HashSet::new())
        .await
        .expect("push succeeds");
    assert_eq!(returned, placeholder);
}

#[tokio::test]
async fn push_secret_rejects_mismatched_placeholder() {
    let requested = SecretPlaceholder::new();
    let returned = SecretPlaceholder::new();
    let secret = SecretString::from("s3cr3t");
    let client = GatewayClient::new(
        mock_gateway(&format!(r#"{{"type":"ok","placeholder":"{returned}"}}"#))
            .await
            .expect("mock gateway"),
        GatewayConfig::default(),
    );

    let error = client
        .push_secret(requested.clone(), secret, HashSet::new())
        .await
        .expect_err("mismatched placeholder must fail closed");

    let rendered = error.to_string();
    let requested_text = requested.to_string();
    let returned_text = returned.to_string();
    assert!(rendered.contains(&requested_text));
    assert!(rendered.contains(&returned_text));
    let rendered = rendered
        .replace(&requested_text, "[requested]")
        .replace(&returned_text, "[returned]");
    insta::assert_snapshot!(rendered, @"secret gateway protocol violation: gateway returned placeholder [returned] after pushing [requested]");
    std::assert_matches!(
        error,
        GatewayClientError::ProtocolViolation(
            ProtocolViolation::PushPlaceholderMismatch { expected, actual }
        ) if expected == requested && actual == returned
    );
}

#[tokio::test]
async fn push_secret_reports_gateway_rejection() {
    let placeholder = SecretPlaceholder::new();
    let secret = SecretString::from("s3cr3t");
    let client = GatewayClient::new(
        mock_gateway(r#"{"type":"err","error":"malformed placeholder"}"#)
            .await
            .expect("mock gateway"),
        GatewayConfig::default(),
    );

    let err = client
        .push_secret(placeholder, secret, HashSet::new())
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
        GatewayConfig::default(),
    );

    let err = client
        .push_secret(placeholder, secret, HashSet::new())
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
        GatewayConfig {
            connection_timeout: NonZeroDuration::new(std::time::Duration::from_hours(1))
                .expect("non-zero connection timeout"),
            ..Default::default()
        },
    );

    let err = client
        .push_secret(placeholder, secret, HashSet::new())
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
