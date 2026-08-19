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

use std::io;

#[cfg(unix)]
use std::path::PathBuf;

use bytesize::ByteSize;
use firma_http::Str;
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
    /// [`validate_endpoint`]): on Unix hosts only a Unix socket is accepted,
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
    /// [`BrokerListenerConfig::operation_timeout`], and on Unix the connecting
    /// shim's credentials are validated before the request is read. A rejected
    /// connection receives an error response.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if accepting, reading, or writing fails, or if the
    /// peer fails credential validation. Handler errors are serialized and
    /// written as `{"error":"..."}` responses rather than returned here. A
    /// returned error only affects the current connection; a robust accept
    /// loop must keep accepting.
    pub async fn accept_one<F>(&self, handler: F) -> io::Result<()>
    where
        F: for<'a> AsyncFnOnce(BrokerRequest<'a, Vec<Str<'a>>>) -> BrokerResponse<'a>,
    {
        let mut stream: BrokerStream = match &self.inner {
            BrokerListenerInner::Tcp(listener) => BrokerStream::Tcp {
                stream: listener.accept().await?.0,
            },
            #[cfg(unix)]
            BrokerListenerInner::Unix(listener, _) => {
                let (stream, _) = listener.accept().await?;
                if let Err(error) = reject_mismatched_peer(&stream) {
                    let response =
                        BrokerResponse::err(format!("peer credential validation failed: {error}"));
                    let mut stream = BrokerStream::Unix { stream };
                    let _ = timeout(
                        self.config.operation_timeout,
                        write_response(&mut stream, &response),
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
                max_request_bytes(self.config.max_request_bytes),
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
    max_request_bytes: usize,
    handler: F,
) -> io::Result<()>
where
    F: for<'a> AsyncFnOnce(BrokerRequest<'a, Vec<Str<'a>>>) -> BrokerResponse<'a>,
{
    // The read is capped at max_request_bytes + 1 (see [`read_bounded_line`]),
    // and any request whose newline-stripped line exceeds the limit is
    // rejected. Padding an over-limit request with boundary whitespace must
    // not let it pass, so the check measures the raw line, not the trimmed
    // content.
    let line = read_bounded_line(stream, max_request_bytes as u64).await?;
    let line = String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "broker request is not UTF-8"))?;
    if line.len() > max_request_bytes {
        write_response(stream, &BrokerResponse::err("request too large")).await?;
        // The request line was capped, so the rest of an over-limit request is
        // still in flight. Drain it before closing so the TCP close delivers a
        // FIN, not an RST that can discard the error response the client has
        // not read yet (see [`drain_remaining`]).
        return drain_remaining(stream).await;
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return write_response(stream, &BrokerResponse::err("empty broker request")).await;
    }
    let response = match serde_json::from_str::<BrokerRequest<Vec<Str>>>(trimmed) {
        Ok(request) => handler(request).await,
        Err(e) => BrokerResponse::err(format!("malformed broker request: {e}")),
    };
    write_response(stream, &response).await
}

async fn write_response(
    stream: &mut BrokerStream,
    response: &BrokerResponse<'_>,
) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("failed to serialize broker response: {e}")))?;
    payload.push(b'\n');
    write_all(stream, &payload).await
}

/// Byte size of the request-line cap, as a `usize` the reader can bound with.
fn max_request_bytes(size: ByteSize) -> usize {
    // The only way this conversion can fail is on a 32-bit system with a
    // configured max_request_bytes larger than usize::MAX.
    usize::try_from(size.as_u64()).unwrap_or(usize::MAX)
}

/// Make a freshly-bound Unix socket owner-only.
#[cfg(unix)]
async fn set_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}
