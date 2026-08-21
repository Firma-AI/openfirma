use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(unix)]
use std::path::Path;

use firma_grpc_interceptor_proto::InterceptRequest;
use firma_grpc_interceptor_proto::interceptor_hook_client::InterceptorHookClient;
use firma_runtime_state::RuntimeLayout;
#[cfg(unix)]
use firma_sidecar::config::InterceptorMode;
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::handler::RequestHandler;
use firma_sidecar::interceptor::grpc::GrpcInterceptor;
use firma_sidecar::startup::{build_connector_registry, build_pipeline_runtime, spawn_interceptor};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

fn grpc_config_and_handler(
    listen_addr: SocketAddr,
) -> anyhow::Result<(SidecarConfig, Arc<RequestHandler>)> {
    let temp = tempfile::tempdir()?;
    let rules_path = temp.path().join("mapping-rules.toml");
    fs::write(
        &rules_path,
        r#"
[[rules]]
method = "GET"
host = "example.com"
path = "/"
action_class = "communication.external.send"
"#,
    )?;
    let config_path = temp.path().join("firma.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[interceptor]
mode = "grpc"
listen_addr = "{listen_addr}"

[mapping]
rules_path = '{}'
default_protected = false
"#,
            rules_path.display()
        ),
    )?;

    let config = SidecarConfig::load_from_path(&config_path).map_err(anyhow::Error::msg)?;
    let runtime_layout = RuntimeLayout::from_root(temp.path());
    let runtime = build_pipeline_runtime(&runtime_layout, &config)?;
    let connectors = build_connector_registry(&config.connector)?;
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(1);
    let handler = Arc::new(RequestHandler::new(runtime.pipeline, connectors, audit_tx));
    Ok((config, handler))
}

#[tokio::test]
async fn grpc_spawn_reports_connectable_dynamic_endpoint() -> anyhow::Result<()> {
    let requested_addr = "127.0.0.1:0".parse()?;
    let (config, handler) = grpc_config_and_handler(requested_addr)?;
    let cancel = CancellationToken::new();
    let runtime_layout = RuntimeLayout::from_root(env::temp_dir());

    let spawned = spawn_interceptor(&runtime_layout, &config, handler, cancel.clone())?;
    let effective_addr: SocketAddr = spawned.listen_addr.parse()?;

    assert_eq!(effective_addr.ip(), requested_addr.ip());
    assert_ne!(effective_addr.port(), 0);
    let stream = TcpStream::connect(effective_addr).await?;

    drop(stream);
    cancel.cancel();
    spawned.handle.await?;
    Ok(())
}

#[tokio::test]
async fn grpc_malformed_request_fields_return_structured_denials() -> anyhow::Result<()> {
    let requested_addr = "127.0.0.1:0".parse()?;
    let (config, handler) = grpc_config_and_handler(requested_addr)?;
    let cancel = CancellationToken::new();
    let runtime_layout = RuntimeLayout::from_root(env::temp_dir());
    let spawned = spawn_interceptor(&runtime_layout, &config, handler, cancel.clone())?;
    let mut client =
        InterceptorHookClient::connect(format!("http://{}", spawned.listen_addr)).await?;

    let malformed_requests = [
        InterceptRequest {
            method: "GET /injected".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
            is_https: true,
            session_id: String::new(),
        },
        InterceptRequest {
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            headers: HashMap::from([("bad header".to_string(), "value".to_string())]),
            body: Vec::new(),
            is_https: true,
            session_id: String::new(),
        },
        InterceptRequest {
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            headers: HashMap::from([("x-test".to_string(), "bad\r\nvalue".to_string())]),
            body: Vec::new(),
            is_https: true,
            session_id: String::new(),
        },
    ];

    let mut results = Vec::new();
    for request in malformed_requests {
        results.push(client.intercept(request).await);
    }
    cancel.cancel();
    spawned.handle.await?;

    for result in results {
        let response = result
            .map_err(|status| anyhow::anyhow!("malformed request returned gRPC {status}"))?
            .into_inner();
        assert!(!response.allowed);
        assert!(
            response.reason.starts_with("MALFORMED_REQUEST:"),
            "unexpected denial reason: {:?}",
            response.reason
        );
    }
    Ok(())
}

#[tokio::test]
async fn grpc_listener_preserves_fixed_endpoint() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixed_addr = listener.local_addr()?;
    let (_config, handler) = grpc_config_and_handler(fixed_addr)?;
    let cancel = CancellationToken::new();
    let interceptor = GrpcInterceptor::from(fixed_addr);
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            interceptor
                .run_with_listener(listener, handler, cancel)
                .await
        }
    });

    let stream = TcpStream::connect(fixed_addr).await?;

    drop(stream);
    cancel.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn grpc_spawn_fails_synchronously_when_fixed_endpoint_is_occupied() -> anyhow::Result<()> {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let occupied_addr = occupied.local_addr()?;
    let (config, handler) = grpc_config_and_handler(occupied_addr)?;
    let runtime_layout = RuntimeLayout::from_root(env::temp_dir());

    let error = spawn_interceptor(&runtime_layout, &config, handler, CancellationToken::new())
        .err()
        .ok_or_else(|| anyhow::anyhow!("occupied endpoint unexpectedly accepted"))?;
    let io_error = error
        .downcast_ref::<io::Error>()
        .ok_or_else(|| anyhow::anyhow!("bind failure did not preserve its I/O error: {error:#}"))?;

    assert_eq!(io_error.kind(), io::ErrorKind::AddrInUse);
    drop(occupied);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_default_uses_lifecycle_runtime_layout() -> anyhow::Result<()> {
    let runtime = tempfile::tempdir()?;
    let requested_addr = "127.0.0.1:0".parse()?;
    let (mut config, handler) = grpc_config_and_handler(requested_addr)?;
    config.interceptor.mode = InterceptorMode::UnixSocket;
    config.interceptor.socket_path = None;
    let runtime_layout = RuntimeLayout::from_root(runtime.path());
    let cancel = CancellationToken::new();

    let spawned = spawn_interceptor(&runtime_layout, &config, handler, cancel.clone())?;

    assert_eq!(
        Path::new(&spawned.listen_addr),
        runtime_layout.sidecar_socket()
    );
    cancel.cancel();
    spawned.handle.await?;
    Ok(())
}
