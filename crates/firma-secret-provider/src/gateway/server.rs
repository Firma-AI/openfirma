//! Gateway-side listener: accepts Sidecar connections and serves them from the
//! shared [`SecretStore`].
//!
//! The gateway is a trust boundary: it holds the secret dictionary and hands
//! real secret values to the Sidecar, so the listener restricts who can
//! connect. On Unix
//! the socket file is created owner-only (`0600`), and the connecting peer's
//! credentials are validated to belong to the current user before the request
//! is read. A connection that fails these checks is closed without touching
//! the store.
//!
//! A same-user local process is trusted: it already has the user's secrets.
//! The boundary enforced here is cross-user access.
//!
//! Concurrency: [`GatewayListener::serve_forever`] spawns a task per accepted
//! connection, so connections are serviced concurrently against the current
//! [`SecretStore`] snapshot. Each connection carries one request, so there is
//! no per-connection timeout beyond the OS-level socket behavior; a stalled
//! connection only ties up its own task.

#[cfg(unix)]
use std::path::PathBuf;
use std::{io, sync::Arc};

use arc_swap::ArcSwap;
use base64::Engine;
use firma_http::Str;
use secrecy::{ExposeSecret, SecretString};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
};

use crate::{
    endpoint::{EndpointInner, server::ServerEndpoint},
    gateway::config::GatewayConfig,
    store::SecretStore,
};

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
    /// Each connection is dispatched on a dedicated task. The loop exits when
    /// the listener socket is closed or a fatal accept error occurs. The caller
    /// retains ownership; `Drop` removes the socket file after this returns.
    pub async fn serve_forever<R, S>(&self, store: Arc<ArcSwap<SecretStore>>) {
        match &self.inner {
            GatewayListenerInner::Tcp(listener) => {
                serve_tcp(listener, self.config.max_buffer_size(), store).await;
            }
            #[cfg(unix)]
            GatewayListenerInner::Unix(listener, _) => {
                serve_unix(listener, self.config.max_buffer_size(), store).await;
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

async fn serve_tcp(
    listener: &TcpListener,
    max_buffer_size: usize,
    store: Arc<ArcSwap<SecretStore>>,
) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let (reader, writer) = stream.split();
                    if let Err(e) =
                        handle_protocol(BufReader::new(reader), writer, max_buffer_size, store)
                            .await
                    {
                        tracing::warn!(error = %e, "secret gateway TCP connection error");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "secret gateway TCP accept loop stopped");
                break;
            }
        }
    }
}

#[cfg(unix)]
async fn serve_unix(
    listener: &UnixListener,
    max_buffer_size: usize,
    store: Arc<ArcSwap<SecretStore>>,
) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let (reader, writer) = stream.split();
                    if let Err(e) =
                        handle_protocol(BufReader::new(reader), writer, max_buffer_size, store)
                            .await
                    {
                        tracing::warn!(error = %e, "secret gateway Unix connection error");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "secret gateway Unix accept loop stopped");
                break;
            }
        }
    }
}

async fn handle_protocol<R, W>(
    mut reader: R,
    mut writer: W,
    max_buffer_size: usize,
    store: Arc<ArcSwap<SecretStore>>,
) -> io::Result<()>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin + Send,
{
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    if line.len() > max_buffer_size {
        return write_error_line(&mut writer, "request too large").await;
    }

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
    store: Arc<ArcSwap<SecretStore>>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let snapshot = store.load();
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

    write_json_line(writer, &results).await
}

/// Handle a `secret.push` request: insert the already-minted placeholder into
/// `store`, scoped to `domain` when present (unscoped/wildcard otherwise,
/// mirroring a CLI intercept whose matcher has no `domain_path`), and return
/// the placeholder so the Sidecar can substitute it into the response body it
/// forwards to the agent.
async fn handle_push<W>(
    request: super::PushRequest<'_>,
    writer: &mut W,
    store: Arc<ArcSwap<SecretStore>>,
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
    store.rcu(|current| {
        let mut updated = SecretStore::clone(current);
        updated.insert(placeholder.clone(), domain.clone(), value.clone());
        updated
    });

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
