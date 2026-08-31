//! Gateway-side listener: accepts Sidecar connections and serves them from the
//! shared [`SecretStore`].
//!
//! The gateway is a trust boundary: it holds the secret dictionary and hands
//! real secret values to the Sidecar, so the listener restricts who can
//! connect. On Unix the socket file is created owner-only (`0600`) and the
//! connecting peer's credentials are validated to belong to the current user
//! before the request is read; a connection that fails these checks is closed
//! without touching the store. TCP loopback carries no peer credentials to
//! check (the Windows transport), so a `tcp://` endpoint relies on loopback
//! binding alone.
//!
//! A same-user local process is trusted: it already has the user's secrets.
//! The boundary enforced here is cross-user access.
//!
//! Concurrency: [`GatewayListener::serve_forever`] spawns a task per accepted
//! connection, so connections are serviced concurrently against the current
//! [`SecretStore`] snapshot. Each connection's read-then-respond exchange is
//! bounded by [`GatewayConfig::operation_timeout`] and its request line is
//! capped at [`GatewayConfig::max_buffer_size`], so a peer can neither stall a
//! connection indefinitely nor grow the broker's memory without bound.

#[cfg(unix)]
use std::path::PathBuf;
use std::{io, sync::Arc, time::Duration};

use base64::Engine;
use firma_config_schema::gateway::GatewayConfig;
use firma_http::Str;
use secrecy::{ExposeSecret, SecretString};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::RwLock,
    time::timeout,
};

use crate::{
    broker::{drain_remaining, read_bounded_line},
    endpoint::{EndpointInner, server::ServerEndpoint},
    store::SecretStore,
};

/// Sleep between retries of a transient accept error (e.g. the process briefly
/// hitting its file-descriptor limit).
const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(100);

enum GatewayListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener, PathBuf),
}

/// Gateway-side listener: accepts Sidecar connections and serves them from the
/// shared [`SecretStore`].
pub struct GatewayListener {
    inner: GatewayListenerInner,
    config: GatewayConfig,
}

impl GatewayListener {
    /// Bind a listener at `endpoint` with `config`.
    ///
    /// The endpoint must pass the transport's address-level invariants (see
    /// [`EndpointInner::parse_server`]): on Unix hosts only a Unix socket is accepted,
    /// and on any platform a non-loopback TCP endpoint is rejected. For Unix
    /// endpoints, any stale socket file is removed before binding and the new
    /// socket is created owner-only (`0600`), so only the owning user can
    /// connect. For TCP endpoints with port `0`, the OS assigns a free port;
    /// retrieve it with [`bound_endpoint`][Self::bound_endpoint].
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when the endpoint fails the
    /// address-level invariants, or the underlying I/O error if binding or
    /// setting socket permissions fails.
    pub async fn bind(endpoint: &ServerEndpoint, config: GatewayConfig) -> io::Result<Self> {
        match endpoint.as_inner() {
            EndpointInner::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await?;
                Ok(Self {
                    inner: GatewayListenerInner::Tcp(listener),
                    config,
                })
            }
            #[cfg(unix)]
            EndpointInner::Unix(path) => {
                if let Err(e) = std::fs::remove_file(path)
                    && e.kind() != io::ErrorKind::NotFound
                {
                    return Err(e);
                }
                let listener = UnixListener::bind(path)?;
                crate::unix::set_socket_permissions(path).await?;
                Ok(Self {
                    inner: GatewayListenerInner::Unix(listener, path.clone()),
                    config,
                })
            }
        }
    }

    /// Return the address this listener is actually bound to.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot report the local address.
    pub fn bound_endpoint(&self) -> io::Result<EndpointInner> {
        match &self.inner {
            GatewayListenerInner::Tcp(l) => Ok(EndpointInner::Tcp(l.local_addr()?)),
            #[cfg(unix)]
            GatewayListenerInner::Unix(_, path) => Ok(EndpointInner::Unix(path.clone())),
        }
    }

    /// Accept and serve `secret.resolve` / `secret.push` connections
    /// indefinitely.
    ///
    /// Each connection is dispatched on a dedicated task whose whole exchange
    /// is bounded by [`GatewayConfig::operation_timeout`]; on Unix the accepted
    /// peer's credentials are validated before the request is read. The loop
    /// exits when the listener hits a non-transient accept error; transient
    /// errors (e.g. hitting the file-descriptor limit) are retried with a
    /// short backoff. Consumes the listener, whose `Drop` removes the socket
    /// file when the loop ends or the task is dropped.
    pub async fn serve_forever(self, store: Arc<RwLock<SecretStore>>) {
        match &self.inner {
            GatewayListenerInner::Tcp(listener) => {
                serve_tcp(listener, self.config, store).await;
            }
            #[cfg(unix)]
            GatewayListenerInner::Unix(listener, _) => {
                serve_unix(listener, self.config, store).await;
            }
        }
    }
}

impl Drop for GatewayListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let GatewayListenerInner::Unix(_, path) = &self.inner {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn serve_tcp(listener: &TcpListener, config: GatewayConfig, store: Arc<RwLock<SecretStore>>) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let (reader, writer) = stream.split();
                    match timeout(
                        config.operation_timeout.duration(),
                        handle_protocol(reader, writer, config, store),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(error = %error, "secret gateway TCP connection error");
                        }
                        Err(_) => {
                            tracing::warn!(
                                "secret gateway TCP connection exceeded operation timeout"
                            );
                        }
                    }
                });
            }
            Err(error) => {
                if is_transient_accept_error(&error) {
                    tracing::debug!(
                        error = %error,
                        "secret gateway TCP accept hit a transient error; retrying"
                    );
                    tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                    continue;
                }
                tracing::debug!(error = %error, "secret gateway TCP accept loop stopped");
                break;
            }
        }
    }
}

#[cfg(unix)]
async fn serve_unix(
    listener: &UnixListener,
    config: GatewayConfig,
    store: Arc<RwLock<SecretStore>>,
) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    if let Err(error) = reject_mismatched_peer(&stream) {
                        let (_, mut writer) = stream.split();
                        let _ = timeout(
                            config.operation_timeout.duration(),
                            write_error_line(
                                &mut writer,
                                &format!("peer credential validation failed: {error}"),
                            ),
                        )
                        .await;
                        tracing::warn!(
                            error = %error,
                            "secret gateway Unix peer credential validation failed"
                        );
                        return;
                    }
                    let (reader, writer) = stream.split();
                    match timeout(
                        config.operation_timeout.duration(),
                        handle_protocol(reader, writer, config, store),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(error = %error, "secret gateway Unix connection error");
                        }
                        Err(_) => {
                            tracing::warn!(
                                "secret gateway Unix connection exceeded operation timeout"
                            );
                        }
                    }
                });
            }
            Err(error) => {
                if is_transient_accept_error(&error) {
                    tracing::debug!(
                        error = %error,
                        "secret gateway Unix accept hit a transient error; retrying"
                    );
                    tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                    continue;
                }
                tracing::debug!(error = %error, "secret gateway Unix accept loop stopped");
                break;
            }
        }
    }
}

async fn handle_protocol<R, W>(
    mut reader: R,
    mut writer: W,
    config: GatewayConfig,
    store: Arc<RwLock<SecretStore>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    // The read is capped at max_buffer_size + 1 (see [`read_bounded_line`]),
    // so an over-limit request line cannot grow memory without bound. The size
    // check measures the raw line (not the trimmed content), so padding an
    // over-limit request with boundary whitespace cannot let it pass. The
    // check also runs before UTF-8 decoding, so an over-limit line that
    // truncates mid-character still receives the "request too large" response.
    let line = read_bounded_line(&mut reader, config.max_buffer_size.as_u64()).await?;
    if line.bytes.len() > config.max_buffer_size() {
        write_error_line(&mut writer, "request too large").await?;
        // The request line was capped, so the rest of an over-limit request is
        // still in flight. Drain it before closing so the close delivers a
        // FIN, not an RST that can discard the error response the client has
        // not read yet (see [`drain_remaining`]).
        return drain_remaining(&mut reader).await;
    }

    let line = String::from_utf8(line.bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "gateway request is not UTF-8"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty gateway request",
        ));
    }

    let req = match serde_json::from_str::<super::GatewayRequest>(trimmed) {
        Ok(req) => req,
        Err(e) => {
            return write_error_line(&mut writer, &format!("malformed request: {e}")).await;
        }
    };

    match req {
        super::GatewayRequest::Resolve(resolve) => {
            handle_resolve(&resolve, &mut writer, store).await
        }
        super::GatewayRequest::Push(push) => handle_push(push, &mut writer, store).await,
    }
}

/// Validate that the accepted connection's peer belongs to the current user.
///
/// The caller writes an error response and fails the connection when this
/// returns an error. TCP loopback carries no peer credentials to check.
#[cfg(unix)]
fn reject_mismatched_peer(stream: &tokio::net::UnixStream) -> io::Result<()> {
    let actual_uid = crate::unix::peer_uid(stream)?;
    let expected_uid = crate::unix::current_uid();
    if actual_uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("gateway peer uid mismatch: expected uid={expected_uid} got uid={actual_uid}"),
        ));
    }
    Ok(())
}

/// Whether an accept error is transient — worth retrying with a short backoff
/// rather than stopping the accept loop. Covers signal interruption, loopback
/// connection resets, and the process briefly hitting its file-descriptor
/// limit (`EMFILE`/`ENFILE` on Unix).
fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    ) || is_fd_limit_error(error)
}

/// [`is_transient_accept_error`] on Unix, where hitting the file-descriptor
/// limit surfaces as `EMFILE`/`ENFILE` raw OS errors.
#[cfg(unix)]
fn is_fd_limit_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error().map(nix::errno::Errno::from_raw),
        Some(nix::errno::Errno::EMFILE | nix::errno::Errno::ENFILE)
    )
}

/// [`is_transient_accept_error`] on Windows, whose accept errors do not expose
/// the Unix file-descriptor-limit errnos.
#[cfg(not(unix))]
fn is_fd_limit_error(_error: &io::Error) -> bool {
    false
}

async fn write_error_line<W>(writer: &mut W, message: &str) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    write_json_line(
        writer,
        &super::PlaceholderResult::Err {
            error: Str::from(message),
        },
    )
    .await
}

async fn handle_resolve<W>(
    request: &super::ResolveRequest,
    writer: &mut W,
    store: Arc<RwLock<SecretStore>>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let snapshot = store.read().await;
    let results = request
        .placeholders
        .iter()
        .map(|placeholder| {
            tracing::debug!(
                %placeholder,
                domain = %request.domain,
                "secret gateway: resolving placeholder"
            );
            snapshot.resolve(placeholder, &request.domain).map_or_else(
                || super::PlaceholderResult::Err {
                    error: Str::from(format!("unknown placeholder: {placeholder}")),
                },
                |secret| super::PlaceholderResult::Ok {
                    secret_b64: Str::from(
                        base64::engine::general_purpose::STANDARD.encode(secret.expose_secret()),
                    ),
                },
            )
        })
        .collect::<Vec<_>>();
    drop(snapshot);

    write_json_line(writer, &results).await
}

/// Handle a `secret.push` request: insert the already-minted placeholder into
/// `store`, scoped to `domain` when present (unscoped/wildcard otherwise,
/// mirroring a CLI intercept whose matcher has no `domain_path`), and return
/// the placeholder so the Sidecar can substitute it into the response body it
/// forwards to the agent.
///
/// The store is shared with concurrently-serviced connections, so it is
/// updated copy-on-write: each push clones the current snapshot, inserts, and
/// swaps, making a write O(n) in the number of stored secrets. The dictionary
/// is run-scoped and small in practice, so this stays cheap; avoid designs
/// that store per-request entries here.
async fn handle_push<W>(
    request: super::PushRequest<'_>,
    writer: &mut W,
    store: Arc<RwLock<SecretStore>>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let super::PushRequest {
        placeholder,
        domain,
        value_b64,
    } = request;

    let value = match base64::engine::general_purpose::STANDARD.decode(&*value_b64) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => SecretString::from(s),
            Err(e) => {
                return write_json_line(
                    writer,
                    &super::PushResponse::Err {
                        error: Str::from(format!("invalid utf8 value: {e}")),
                    },
                )
                .await;
            }
        },
        Err(e) => {
            return write_json_line(
                writer,
                &super::PushResponse::Err {
                    error: Str::from(format!("invalid base64 value: {e}")),
                },
            )
            .await;
        }
    };

    tracing::debug!(
        placeholder = %placeholder,
        domain = ?domain,
        "secret gateway: pushing HTTP-intercepted secret"
    );
    let mut snapshot = store.write().await;
    snapshot.insert(placeholder.clone(), domain.clone(), value.clone());
    drop(snapshot);

    write_json_line(writer, &super::PushResponse::Ok { placeholder }).await
}

async fn write_json_line<T, W>(writer: &mut W, value: &T) -> io::Result<()>
where
    T: serde::Serialize + Sync,
    W: AsyncWrite + Unpin + Send,
{
    let mut payload = serde_json::to_vec(value)
        .map_err(|e| io::Error::other(format!("failed to serialize gateway response: {e}")))?;
    payload.push(b'\n');
    writer.write_all(&payload).await?;
    writer.flush().await
}
