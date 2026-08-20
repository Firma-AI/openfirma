use std::{collections::HashSet, str::FromStr, sync::Arc};

use firma_http::Authority;
use firma_secret_provider::{
    ExposeSecret, SecretPlaceholder,
    broker::stream::BrokerStream,
    endpoint::{EndpointInner, client::ClientEndpoint, server::ServerEndpoint},
    gateway::{client::GatewayClient, config::GatewayConfig, server::GatewayListener},
    store::SecretStore,
};
use secrecy::SecretString;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    sync::RwLock,
};

struct BoundGateway {
    listener: GatewayListener,
    #[cfg(unix)]
    _dir: tempfile::TempDir,
    #[cfg(not(unix))]
    _dir: (),
    endpoint: ServerEndpoint,
}

/// Bind a gateway listener on a fresh Unix socket in a temp dir.
#[cfg(unix)]
async fn bind_gateway(config: GatewayConfig) -> anyhow::Result<BoundGateway> {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir()?;
    tokio::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).await?;
    let path = dir.path().join("gateway.sock");
    let endpoint = ServerEndpoint::from_str(&format!("unix://{}", path.display()))?;
    let listener = GatewayListener::bind(&endpoint, config).await?;
    Ok(BoundGateway {
        listener,
        _dir: dir,
        endpoint,
    })
}

/// Bind a gateway listener on a fresh loopback TCP port (the Windows transport).
#[cfg(not(unix))]
async fn bind_gateway(config: GatewayConfig) -> anyhow::Result<BoundGateway> {
    let endpoint = ServerEndpoint::from_str("tcp://127.0.0.1:0")?;
    let listener = GatewayListener::bind(&endpoint, config).await?;
    let EndpointInner::Tcp(addr) = listener.bound_endpoint()?;
    Ok(BoundGateway {
        listener,
        _dir: (),
        endpoint: ServerEndpoint::from_str(&format!("tcp://{addr}"))?,
    })
}

fn client_endpoint(
    endpoint: &ServerEndpoint,
) -> Result<ClientEndpoint, firma_secret_provider::endpoint::error::EndpointParseError> {
    ClientEndpoint::from_str(&endpoint.to_string())
}

async fn connect(endpoint: &ServerEndpoint) -> anyhow::Result<BrokerStream> {
    let stream = match endpoint.as_inner() {
        EndpointInner::Tcp(addr) => BrokerStream::Tcp {
            stream: tokio::net::TcpStream::connect(addr).await?,
        },
        #[cfg(unix)]
        EndpointInner::Unix(path) => BrokerStream::Unix {
            stream: tokio::net::UnixStream::connect(path).await?,
        },
    };
    Ok(stream)
}

/// Read one newline-terminated line from a connected stream.
async fn read_line(stream: &mut BrokerStream) -> anyhow::Result<String> {
    let mut line = String::new();
    tokio::io::BufReader::new(stream)
        .read_line(&mut line)
        .await?;
    Ok(line)
}

#[tokio::test]
async fn push_then_resolve_roundtrip_through_listener() -> anyhow::Result<()> {
    let BoundGateway {
        listener,
        endpoint,
        _dir,
    } = bind_gateway(GatewayConfig::default()).await?;
    let store = Arc::new(RwLock::new(SecretStore::new()));
    let server = tokio::spawn(listener.serve_forever(Arc::clone(&store)));

    let client = GatewayClient::new(
        client_endpoint(&endpoint).expect("client endpoint parses"),
        GatewayConfig::default(),
    );

    // A wildcard push resolves for any request domain.
    let placeholder = SecretPlaceholder::new();
    let returned = client
        .push_secret(
            placeholder.clone(),
            SecretString::from("s3cr3t"),
            HashSet::new(),
        )
        .await?;
    assert_eq!(returned, placeholder);

    let secrets = client
        .resolve_batch(
            vec![placeholder.clone()],
            Authority::from_static("api.example.com"),
        )
        .await?
        .expect("wildcard push resolves for any domain");
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].expose_secret(), "s3cr3t");
    assert_eq!(store.read().await.len(), 1);

    // A domain-scoped push resolves only for that exact host.
    let scoped = SecretPlaceholder::new();
    client
        .push_secret(
            scoped.clone(),
            SecretString::from("ghp_xxx"),
            HashSet::from([Authority::from_static("api.github.com")]),
        )
        .await?;
    assert_eq!(
        store.read().await.len(),
        2,
        "both pushes are stored in the broker dictionary"
    );

    let github_secrets = client
        .resolve_batch(
            vec![scoped.clone()],
            Authority::from_static("api.github.com"),
        )
        .await?
        .expect("scoped secret resolves for its domain");
    assert_eq!(github_secrets[0].expose_secret(), "ghp_xxx");

    client
        .resolve_batch(vec![scoped], Authority::from_static("api.stripe.com"))
        .await?
        .expect_err("scoped secret must not resolve for another domain");

    server.abort();
    Ok(())
}

#[tokio::test]
async fn oversized_request_is_rejected_without_touching_the_store() -> anyhow::Result<()> {
    let BoundGateway {
        listener,
        endpoint,
        _dir,
    } = bind_gateway(GatewayConfig {
        max_buffer_size: bytesize::ByteSize::b(64),
        ..Default::default()
    })
    .await?;
    let store = Arc::new(RwLock::new(SecretStore::new()));
    let server = tokio::spawn(listener.serve_forever(Arc::clone(&store)));

    let mut stream = connect(&endpoint).await?;
    let mut payload = vec![b'['; 256];
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await?;

    let line = read_line(&mut stream).await?;
    assert!(
        line.contains("request too large"),
        "over-limit request must be answered with an error line, got: {line}"
    );
    assert_eq!(
        store.read().await.len(),
        0,
        "rejected request must not reach the store"
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn stalled_connection_is_closed_after_operation_timeout() -> anyhow::Result<()> {
    let BoundGateway {
        listener,
        endpoint,
        _dir,
    } = bind_gateway(GatewayConfig {
        operation_timeout: std::time::Duration::from_millis(50),
        ..Default::default()
    })
    .await?;
    let store = Arc::new(RwLock::new(SecretStore::new()));
    let server = tokio::spawn(listener.serve_forever(Arc::clone(&store)));

    // Connect and send nothing: the listener's operation timeout must close the
    // connection instead of holding the task forever.
    let mut stream = connect(&endpoint).await?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut buf = [0u8; 8];
    let read = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await?;
    assert_eq!(
        read, 0,
        "timed-out connection must be closed by the listener"
    );

    server.abort();
    Ok(())
}
