use std::collections::HashMap;
use std::io;
#[cfg(unix)]
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsFd as _;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Duration, Instant};

use firma_grpc_interceptor_proto::InterceptRequest;
use firma_grpc_interceptor_proto::interceptor_hook_client::InterceptorHookClient;
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
    std::fs::write(
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
    std::fs::write(
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
    let runtime = build_pipeline_runtime(&config)?;
    let connectors = build_connector_registry(&config.connector)?;
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(1);
    let handler = Arc::new(RequestHandler::new(runtime.pipeline, connectors, audit_tx));
    Ok((config, handler))
}

#[cfg(unix)]
fn unix_config_and_handler(
    socket_path: &std::path::Path,
) -> anyhow::Result<(SidecarConfig, Arc<RequestHandler>)> {
    let (mut config, handler) = grpc_config_and_handler("127.0.0.1:0".parse()?)?;
    config.interceptor.mode = firma_sidecar::config::InterceptorMode::UnixSocket;
    config.interceptor.socket_path = Some(socket_path.to_path_buf());
    Ok((config, handler))
}

#[tokio::test]
async fn grpc_spawn_reports_connectable_dynamic_endpoint() -> anyhow::Result<()> {
    let requested_addr = "127.0.0.1:0".parse()?;
    let (config, handler) = grpc_config_and_handler(requested_addr)?;
    let cancel = CancellationToken::new();

    let spawned = spawn_interceptor(&config, handler, cancel.clone())?;
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
    let spawned = spawn_interceptor(&config, handler, cancel.clone())?;
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

    let error = spawn_interceptor(&config, handler, CancellationToken::new())
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
async fn concurrent_unix_stale_socket_replacement_preserves_the_winner() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let socket_path = temp.path().join("interceptor.sock");
    let crashed = tokio::net::UnixListener::bind(&socket_path)?;
    drop(crashed);

    let mut children = [
        spawn_fixture(&socket_path, None)?,
        spawn_fixture(&socket_path, None)?,
    ];
    for child in &mut children {
        assert_eq!(read_child_line(child)?, "READY");
    }
    // Both processes are released without waiting for either result. The OS may
    // schedule one first, but the test does not assume which one wins.
    for child in &mut children {
        send_child_line(child, "GO")?;
    }
    let outcomes = [
        read_child_line(&mut children[0])?,
        read_child_line(&mut children[1])?,
    ];
    assert_eq!(
        outcomes.iter().filter(|line| *line == "LISTENING").count(),
        1
    );
    let loser = outcomes
        .iter()
        .find(|line| line.starts_with("ERROR "))
        .ok_or_else(|| anyhow::anyhow!("no startup reported a bind error: {outcomes:?}"))?;
    assert_eq!(
        loser,
        &format!(
            "ERROR bind failed: socket {} is already accepting connections",
            socket_path.display()
        )
    );
    let stream = tokio::net::UnixStream::connect(&socket_path).await?;
    drop(stream);
    for (child, outcome) in children.iter_mut().zip(outcomes) {
        if outcome == "LISTENING" {
            send_child_line(child, "STOP")?;
        }
        assert!(child.wait()?.success());
    }
    assert!(
        socket_path
            .with_file_name("interceptor.sock.bind.lock")
            .is_file()
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_spawn_preserves_relative_bare_socket_path() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let relative = std::path::Path::new("interceptor.sock");
    let mut child = spawn_fixture(relative, Some(temp.path()))?;
    assert_eq!(read_child_line(&mut child)?, "READY");
    send_child_line(&mut child, "GO")?;
    assert_eq!(read_child_line(&mut child)?, "LISTENING");
    let stream = tokio::net::UnixStream::connect(temp.path().join(relative)).await?;
    drop(stream);
    send_child_line(&mut child, "STOP")?;
    assert!(child.wait()?.success());
    assert!(temp.path().join("interceptor.sock.bind.lock").is_file());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_spawn_rejects_paths_reserved_for_coordination_files() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let socket_path = temp.path().join("interceptor.sock.bind.lock");
    let recursive_lock_path = temp.path().join("interceptor.sock.bind.lock.bind.lock");
    let (config, handler) = unix_config_and_handler(&socket_path)?;

    let error = spawn_interceptor(&config, handler, CancellationToken::new())
        .err()
        .ok_or_else(|| anyhow::anyhow!("reserved socket path unexpectedly accepted"))?;

    assert_eq!(
        error.to_string(),
        format!(
            "bind failed: socket path {} uses the reserved coordination suffix .bind.lock",
            socket_path.display()
        )
    );
    assert!(!socket_path.exists());
    assert!(!recursive_lock_path.exists());
    Ok(())
}

#[cfg(unix)]
struct ChildGuard {
    child: Child,
}

#[cfg(unix)]
impl ChildGuard {
    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("child {} did not exit within 10s", self.child.id()),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(unix)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn spawn_fixture(
    socket_path: &std::path::Path,
    cwd: Option<&std::path::Path>,
) -> io::Result<ChildGuard> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "interceptor_startup::unix_spawn_fixture",
            "--ignored",
            "--nocapture",
        ])
        // nextest's execution-protocol environment makes a recursively invoked
        // test binary enter listing mode instead of running the selected fixture.
        .env_clear()
        .env("FIRMA_TEST_SOCKET_PATH", socket_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.spawn().map(|child| ChildGuard { child })
}

#[cfg(unix)]
fn read_child_line(child: &mut ChildGuard) -> io::Result<String> {
    let mut line = Vec::new();
    let child_id = child.child.id();
    let stderr = child
        .child
        .stderr
        .as_mut()
        .ok_or_else(|| io::Error::other("missing child stderr"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout =
            nix::poll::PollTimeout::try_from(remaining).unwrap_or(nix::poll::PollTimeout::MAX);
        let mut descriptors = [nix::poll::PollFd::new(
            stderr.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        if nix::poll::poll(&mut descriptors, timeout)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "child {child_id} protocol read timed out after 10s; partial stderr: {}",
                    String::from_utf8_lossy(&line)
                ),
            ));
        }
        let mut byte = [0];
        match stderr.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(error) => return Err(error),
        }
    }
    String::from_utf8(line).map_err(io::Error::other)
}

#[cfg(unix)]
fn send_child_line(child: &mut ChildGuard, line: &str) -> io::Result<()> {
    let stdin = child
        .child
        .stdin
        .as_mut()
        .ok_or_else(|| io::Error::other("missing child stdin"))?;
    writeln!(stdin, "{line}")?;
    stdin.flush()
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "subprocess fixture"]
async fn unix_spawn_fixture() -> anyhow::Result<()> {
    let socket_path = std::env::var_os("FIRMA_TEST_SOCKET_PATH")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("FIRMA_TEST_SOCKET_PATH is missing"))?;
    eprintln!("READY");
    io::stderr().flush()?;
    let mut input = io::stdin().lock().lines();
    if input.next().transpose()?.as_deref() != Some("GO") {
        return Err(anyhow::anyhow!("fixture did not receive GO"));
    }
    let (config, handler) = unix_config_and_handler(&socket_path)?;
    let cancel = CancellationToken::new();
    let spawned = match spawn_interceptor(&config, handler, cancel.clone()) {
        Ok(spawned) => spawned,
        Err(error) => {
            eprintln!("ERROR {error}");
            io::stderr().flush()?;
            return Ok(());
        }
    };
    eprintln!("LISTENING");
    io::stderr().flush()?;
    if input.next().transpose()?.as_deref() != Some("STOP") {
        return Err(anyhow::anyhow!("fixture did not receive STOP"));
    }
    drop(input);
    cancel.cancel();
    spawned.handle.await?;
    Ok(())
}
