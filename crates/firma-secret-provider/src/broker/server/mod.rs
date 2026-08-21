//! Broker-side listener: accepts shim connections and dispatches requests.
//!
//! The broker is a trust boundary: its handler applies config matching and
//! authorization to decide what can run, executes the real CLI out of the
//! sandbox, and returns secret material, so the listener restricts who can
//! connect. On Unix
//! the socket file is created owner-only (`0600`), and the connecting shim's
//! credentials are validated to belong to the current user before the request
//! is read. A connection that fails these checks receives an error response
//! and is closed without running the tool.
//!
//! A same-user local process is trusted: it already has the user's secrets.
//! The boundary enforced here is cross-user access.
//!
//! Concurrency: [`BrokerListener::accept_one`] services exactly one
//! connection, so an accept loop that awaits it serially runs tools one at a
//! time — new connections queue in the kernel backlog and their shims can
//! time out while a slow tool holds the broker. Callers that want tools to
//! run concurrently should spawn a task per `accept_one` (each call takes
//! `&self`, so concurrent accepts are safe). Note that
//! [`config::BrokerListenerConfig::operation_timeout`] cancels the handler
//! mid-run when it fires: a handler that spawns a child process must ensure
//! the child is killed on cancellation, or the tool keeps running out of the
//! sandbox after the shim has already failed closed.

use std::io;

#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{net::TcpListener, time::timeout};

use crate::{
    broker::{
        BrokerRequest, BrokerResponse, drain_remaining, read_bounded_line, stream::BrokerStream,
        write_all,
    },
    endpoint::{EndpointInner, server::ServerEndpoint},
};

pub mod config;

enum BrokerListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener, PathBuf),
}

/// Broker-side listener: accepts shim connections and dispatches requests.
pub struct BrokerListener {
    inner: BrokerListenerInner,
    config: config::BrokerListenerConfig,
}

impl BrokerListener {
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
    pub async fn bind(
        endpoint: &ServerEndpoint,
        config: config::BrokerListenerConfig,
    ) -> io::Result<Self> {
        match endpoint.as_inner() {
            EndpointInner::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await?;
                Ok(Self {
                    inner: BrokerListenerInner::Tcp(listener),
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
                set_socket_permissions(path).await?;
                Ok(Self {
                    inner: BrokerListenerInner::Unix(listener, path.clone()),
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
            BrokerListenerInner::Tcp(l) => Ok(EndpointInner::Tcp(l.local_addr()?)),
            #[cfg(unix)]
            BrokerListenerInner::Unix(_, path) => Ok(EndpointInner::Unix(path.clone())),
        }
    }

    /// Accept one shim connection, invoke `handler(request)`, and write the
    /// response back.
    ///
    /// The whole read-then-run-then-write exchange is bounded by
    /// [`config::BrokerListenerConfig::operation_timeout`], and on Unix the connecting
    /// shim's credentials are validated before the request is read. A rejected
    /// connection receives an error response.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if accepting, reading, or writing fails, or if the
    /// peer fails credential validation. Handler rejections are serialized as
    /// `{"type":"rejected","error":"..."}` responses rather than returned
    /// here. A returned error only affects the current connection; a robust
    /// accept loop must keep accepting.
    pub async fn accept_one<F>(&self, handler: F) -> io::Result<()>
    where
        F: for<'a> AsyncFnOnce(BrokerRequest<'a>) -> BrokerResponse<'a>,
    {
        let mut stream: BrokerStream = match &self.inner {
            BrokerListenerInner::Tcp(listener) => BrokerStream::Tcp {
                stream: listener.accept().await?.0,
            },
            #[cfg(unix)]
            BrokerListenerInner::Unix(listener, _) => {
                let (stream, _) = listener.accept().await?;
                if let Err(error) = reject_mismatched_peer(&stream) {
                    let response = BrokerResponse::rejected(format!(
                        "peer credential validation failed: {error}"
                    ));
                    let mut stream = BrokerStream::Unix { stream };
                    let _ = timeout(
                        self.config.operation_timeout,
                        write_response(&mut stream, &response, self.config.max_response_size()),
                    )
                    .await;
                    return Err(error);
                }
                BrokerStream::Unix { stream }
            }
        };
        // The whole read-then-run-then-write exchange is bounded by
        // `operation_timeout`, so a shim that stalls mid-exchange cannot hold
        // the connection indefinitely.
        timeout(
            self.config.operation_timeout,
            handle_connection(
                &mut stream,
                self.config.max_request_size(),
                self.config.max_response_size(),
                handler,
            ),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "broker connection exceeded operation timeout",
            )
        })?
    }
}

impl Drop for BrokerListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let BrokerListenerInner::Unix(_, path) = &self.inner {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Validate that the accepted connection's peer belongs to the current user.
///
/// The caller writes an error response and fails the connection when this
/// returns an error. TCP loopback carries no peer credentials to check.
#[cfg(unix)]
fn reject_mismatched_peer(stream: &tokio::net::UnixStream) -> io::Result<()> {
    let actual_uid = super::peer_uid(stream)?;
    let expected_uid = super::current_uid();
    if actual_uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("broker peer uid mismatch: expected uid={expected_uid} got uid={actual_uid}"),
        ));
    }
    Ok(())
}

async fn handle_connection<F>(
    stream: &mut BrokerStream,
    max_request_size: usize,
    max_response_size: usize,
    handler: F,
) -> io::Result<()>
where
    F: for<'a> AsyncFnOnce(BrokerRequest<'a>) -> BrokerResponse<'a>,
{
    // The read is capped at max_request_size + 1 (see [`read_bounded_line`]),
    // and any request whose newline-stripped line exceeds the limit is
    // rejected. Padding an over-limit request with boundary whitespace must
    // not let it pass, so the check measures the raw line, not the trimmed
    // content. The size check runs on the raw bytes before UTF-8 decoding so
    // an over-limit line that truncates mid-character still receives the
    // "request too large" response instead of a silent close.
    let line = read_bounded_line(stream, max_request_size as u64).await?;
    if line.len() > max_request_size {
        write_response(
            stream,
            &BrokerResponse::rejected("request too large"),
            max_response_size,
        )
        .await?;
        // The request line was capped, so the rest of an over-limit request is
        // still in flight. Drain it before closing so the TCP close delivers a
        // FIN, not an RST that can discard the error response the client has
        // not read yet (see [`drain_remaining`]).
        return drain_remaining(stream).await;
    }
    let line = String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "broker request is not UTF-8"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return write_response(
            stream,
            &BrokerResponse::rejected("empty broker request"),
            max_response_size,
        )
        .await;
    }
    let response = match serde_json::from_str::<BrokerRequest>(trimmed) {
        Ok(request) => handler(request).await,
        Err(e) => BrokerResponse::rejected(format!("malformed broker request: {e}")),
    };
    write_response(stream, &response, max_response_size).await
}

/// Serialize `response` into a newline-terminated wire line, or return `None`
/// when the serialized line exceeds `max_response_bytes`.
///
/// The response must be capped before it reaches the shim: the shim reads
/// only up to its own buffer limit, so an over-limit line would be truncated
/// or rejected without a meaningful reason. Enforcing the cap here replaces
/// it with a short, clean error response instead.
fn serialize_response(
    response: &BrokerResponse<'_>,
    max_response_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("failed to serialize broker response: {e}")))?;
    if payload.len() > max_response_bytes {
        return Ok(None);
    }
    payload.push(b'\n');
    Ok(Some(payload))
}

async fn write_response(
    stream: &mut BrokerStream,
    response: &BrokerResponse<'_>,
    max_response_bytes: usize,
) -> io::Result<()> {
    let Some(payload) = serialize_response(response, max_response_bytes)? else {
        // The handler's response (or its error reason) exceeded the cap.
        // Answer with a fixed-size error instead so the shim fails closed
        // with a meaningful reason.
        let Some(payload) = serialize_response(
            &BrokerResponse::rejected("response too large"),
            max_response_bytes,
        )?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured max_response_bytes is smaller than the smallest error response",
            ));
        };
        return write_all(stream, &payload).await;
    };
    write_all(stream, &payload).await
}

/// Make a freshly-bound Unix socket owner-only.
#[cfg(unix)]
async fn set_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}
