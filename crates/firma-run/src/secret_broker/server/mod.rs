//! Broker-side listener: accepts shim connections and dispatches requests.
//!
//! The broker is a trust boundary: it runs the real CLI out of the sandbox and
//! returns secret material, so the listener restricts who can connect. On Unix
//! the socket file is created owner-only (`0600`), and on Linux the connecting
//! shim's credentials are validated to belong to the current user before the
//! request is read. A connection that fails these checks receives an error
//! response and is closed without running the tool.
//!
//! A same-user local process is trusted: it already has the user's secrets.
//! The boundary enforced here is cross-user access.

use std::{io, net::TcpListener, time::Instant};

#[cfg(unix)]
use std::{os::unix::net::UnixListener, path::PathBuf};

use bytesize::ByteSize;

use crate::{
    config::CommandMediatorEndpoint,
    secret_broker::{
        BrokerRequest, BrokerResponse, BrokerStream, current_uid, peer_uid, read_bounded_line,
        validate_endpoint, write_all_bounded,
    },
};

pub mod config;

enum BrokerListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener, PathBuf),
}

/// Broker-side listener: accepts shim connections and dispatches requests.
pub(crate) struct BrokerListener {
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
    pub(crate) fn bind(
        endpoint: &CommandMediatorEndpoint,
        config: config::BrokerListenerConfig,
    ) -> io::Result<Self> {
        validate_endpoint(endpoint)
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
        match endpoint {
            CommandMediatorEndpoint::Tcp { addr } => {
                let listener = TcpListener::bind(addr)?;
                Ok(Self {
                    inner: BrokerListenerInner::Tcp(listener),
                    config,
                })
            }
            #[cfg(unix)]
            CommandMediatorEndpoint::Unix { path } => {
                if let Err(e) = std::fs::remove_file(path)
                    && e.kind() != io::ErrorKind::NotFound
                {
                    return Err(e);
                }
                let listener = UnixListener::bind(path)?;
                set_socket_permissions(path)?;
                Ok(Self {
                    inner: BrokerListenerInner::Unix(listener, path.clone()),
                    config,
                })
            }
            #[cfg(not(unix))]
            CommandMediatorEndpoint::Unix { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix domain sockets are not supported on this platform",
            )),
        }
    }

    /// Return the address this listener is actually bound to.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot report the local address.
    pub(crate) fn bound_endpoint(&self) -> io::Result<CommandMediatorEndpoint> {
        match &self.inner {
            BrokerListenerInner::Tcp(l) => Ok(CommandMediatorEndpoint::Tcp {
                addr: l.local_addr()?,
            }),
            #[cfg(unix)]
            BrokerListenerInner::Unix(_, path) => {
                Ok(CommandMediatorEndpoint::Unix { path: path.clone() })
            }
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
    pub(crate) fn accept_one<F>(&self, handler: F) -> io::Result<()>
    where
        F: FnOnce(BrokerRequest) -> BrokerResponse,
    {
        let mut stream = match &self.inner {
            BrokerListenerInner::Tcp(listener) => BrokerStream::Tcp(listener.accept()?.0),
            #[cfg(unix)]
            BrokerListenerInner::Unix(listener, _) => BrokerStream::Unix(listener.accept()?.0),
        };
        let deadline = Instant::now() + self.config.operation_timeout;
        if let Err(error) = reject_mismatched_peer(&stream) {
            let response =
                BrokerResponse::err(format!("peer credential validation failed: {error}"));
            let _ = write_response(&mut stream, deadline, &response);
            return Err(error);
        }
        handle_connection(
            &mut stream,
            deadline,
            max_request_bytes(self.config.max_request_bytes),
            handler,
        )
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
fn reject_mismatched_peer(stream: &BrokerStream) -> io::Result<()> {
    let BrokerStream::Unix(stream) = stream else {
        return Ok(());
    };
    let actual_uid = peer_uid(stream)?;
    let expected_uid = current_uid();
    if actual_uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("broker peer uid mismatch: expected uid={expected_uid} got uid={actual_uid}"),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "mirror of the Unix signature")]
fn reject_mismatched_peer(_stream: &BrokerStream) -> io::Result<()> {
    Ok(())
}

fn handle_connection(
    stream: &mut BrokerStream,
    deadline: Instant,
    max_request_bytes: usize,
    handler: impl FnOnce(BrokerRequest) -> BrokerResponse,
) -> io::Result<()> {
    // The read is capped at max_request_bytes + 1 (see [`read_bounded_line`]),
    // and any request whose newline-stripped line exceeds the limit is
    // rejected. Padding an over-limit request with boundary whitespace must
    // not let it pass, so the check measures the raw line, not the trimmed
    // content.
    let line = read_bounded_line(stream, max_request_bytes as u64, deadline)?;
    let line = String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "broker request is not UTF-8"))?;
    if line.len() > max_request_bytes {
        return write_response(stream, deadline, &BrokerResponse::err("request too large"));
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return write_response(
            stream,
            deadline,
            &BrokerResponse::err("empty broker request"),
        );
    }
    let response = match serde_json::from_str::<BrokerRequest>(trimmed) {
        Ok(request) => handler(request),
        Err(e) => BrokerResponse::err(format!("malformed broker request: {e}")),
    };
    write_response(stream, deadline, &response)
}

fn write_response(
    stream: &mut BrokerStream,
    deadline: Instant,
    response: &BrokerResponse,
) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("failed to serialize broker response: {e}")))?;
    payload.push(b'\n');
    write_all_bounded(stream, &payload, deadline)
}

/// Byte size of the request-line cap, as a `usize` the reader can bound with.
fn max_request_bytes(size: ByteSize) -> usize {
    // The only way this conversion can fail is on a 32-bit system with a
    // configured max_request_bytes larger than usize::MAX.
    usize::try_from(size.as_u64()).unwrap_or(usize::MAX)
}

/// Make a freshly-bound Unix socket owner-only.
#[cfg(unix)]
fn set_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    use std::thread;

    use firma_http::Str;

    use crate::secret_broker::server::config::BrokerListenerConfig;

    use super::*;

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    struct BoundBroker {
        listener: BrokerListener,
        #[cfg(unix)]
        _dir: tempfile::TempDir,
        #[cfg(not(unix))]
        _dir: (),
        endpoint: CommandMediatorEndpoint,
    }

    /// Bind a listener on a fresh Unix socket in a temp dir.
    #[cfg(unix)]
    fn bind_with_config(config: BrokerListenerConfig) -> BoundBroker {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let endpoint = CommandMediatorEndpoint::Unix { path };
        let listener = BrokerListener::bind(&endpoint, config).expect("bind");
        BoundBroker {
            listener,
            _dir: dir,
            endpoint,
        }
    }

    /// Bind a listener on a fresh loopback TCP port (the Windows transport).
    #[cfg(not(unix))]
    fn bind_with_config(config: BrokerListenerConfig) -> BoundBroker {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid loopback addr"),
        };
        let listener = BrokerListener::bind(&endpoint, config).expect("bind");
        let CommandMediatorEndpoint::Tcp { addr } =
            listener.bound_endpoint().expect("bound_endpoint")
        else {
            panic!("TCP listener must return TCP endpoint");
        };
        BoundBroker {
            listener,
            _dir: (),
            endpoint: CommandMediatorEndpoint::Tcp { addr },
        }
    }

    fn connect_and_send(
        endpoint: &CommandMediatorEndpoint,
        request: &BrokerRequest<'_>,
        check: impl FnOnce(BrokerResponse<'_>),
    ) {
        let mut stream: Box<dyn ReadWrite> = match endpoint {
            CommandMediatorEndpoint::Tcp { addr } => {
                Box::new(TcpStream::connect(addr).expect("connect"))
            }
            #[cfg(unix)]
            CommandMediatorEndpoint::Unix { path } => {
                Box::new(UnixStream::connect(path).expect("connect"))
            }
        };
        let payload = serde_json::to_string(request).expect("serialize");
        stream
            .write_all(format!("{payload}\n").as_bytes())
            .expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        check(serde_json::from_str(line.trim()).expect("deserialize response"));
    }

    fn connect_and_send_raw(
        endpoint: &CommandMediatorEndpoint,
        raw: &[u8],
        check: impl FnOnce(BrokerResponse<'_>),
    ) {
        let mut stream: Box<dyn ReadWrite> = match endpoint {
            CommandMediatorEndpoint::Tcp { addr } => {
                Box::new(TcpStream::connect(addr).expect("connect"))
            }
            #[cfg(unix)]
            CommandMediatorEndpoint::Unix { path } => {
                Box::new(UnixStream::connect(path).expect("connect"))
            }
        };
        stream.write_all(raw).expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        check(serde_json::from_str(line.trim()).expect("deserialize response"));
    }

    #[test]
    fn roundtrip_ok_response() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_with_config(BrokerListenerConfig::default());
        let request = BrokerRequest {
            bin: Str::from("bws"),
            args: Str::from("secret get abc"),
        };
        let request_clone = request.clone();
        let server = thread::spawn(move || {
            listener
                .accept_one(|req| {
                    assert_eq!(req, request_clone);
                    BrokerResponse::ok(b"secret-value")
                })
                .expect("accept_one");
        });
        connect_and_send(&endpoint, &request, |response| {
            server.join().expect("server thread");
            assert_eq!(
                response.into_stdout().expect("ok response"),
                b"secret-value"
            );
        });
    }

    #[test]
    fn handler_error_written_as_error_response() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_with_config(BrokerListenerConfig::default());
        let request = BrokerRequest {
            bin: Str::from("bws"),
            args: Str::from("secret get x"),
        };
        let server = thread::spawn(move || {
            listener
                .accept_one(|_req| BrokerResponse::err("tool not found"))
                .expect("accept_one");
        });
        connect_and_send(&endpoint, &request, |response| {
            server.join().expect("server thread");
            assert!(response.into_stdout().is_err());
        });
    }

    #[cfg(windows)]
    #[test]
    fn bound_endpoint_returns_assigned_tcp_port() {
        let BoundBroker { endpoint, _dir } = bind_with_config(BrokerListenerConfig::default());
        let CommandMediatorEndpoint::Tcp { addr } = endpoint else {
            panic!("TCP listener must return TCP endpoint");
        };
        assert_ne!(addr.port(), 0, "OS must assign a non-zero port");
    }

    #[test]
    fn bind_rejects_non_local_tcp_endpoint() {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "0.0.0.0:9999".parse().expect("valid addr"),
        };
        let error = BrokerListener::bind(&endpoint, BrokerListenerConfig::default());
        assert!(error.is_err(), "non-loopback TCP must be rejected");
    }

    #[test]
    fn oversize_request_is_rejected() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_with_config(BrokerListenerConfig {
            max_request_bytes: bytesize::ByteSize::b(32),
            ..BrokerListenerConfig::default()
        });
        let server = thread::spawn(move || {
            listener
                .accept_one(|_req| panic!("oversize request must not reach the handler"))
                .expect("accept_one");
        });
        let big = "x".repeat(4096);
        connect_and_send_raw(
            &endpoint,
            format!("{{\"bin\":\"{big}\"}}\n").as_bytes(),
            |response| {
                server.join().expect("server thread");
                assert!(response.into_stdout().is_err());
            },
        );
    }

    #[test]
    fn request_padded_with_whitespace_over_limit_is_rejected() {
        let limit = 64u64;
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_with_config(BrokerListenerConfig {
            max_request_bytes: bytesize::ByteSize::b(limit),
            ..BrokerListenerConfig::default()
        });
        let server = thread::spawn(move || {
            listener
                .accept_one(|_req| panic!("oversize request must not reach the handler"))
                .expect("accept_one");
        });
        // A valid request is shorter than the limit; pad it with leading
        // whitespace so the raw line is `limit + 1` bytes even though the
        // trimmed content is not. The size check must measure the line, not
        // the trimmed content.
        let request = BrokerRequest {
            bin: Str::from("bws"),
            args: Str::from("secret get abc"),
        };
        let json = serde_json::to_string(&request).expect("serialize");
        let mut padded = " ".repeat(usize::try_from(limit + 1).expect("usize") - json.len());
        padded.push_str(&json);
        padded.push('\n');
        connect_and_send_raw(&endpoint, padded.as_bytes(), |response| {
            server.join().expect("server thread");
            assert!(response.into_stdout().is_err());
        });
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let endpoint = CommandMediatorEndpoint::Unix { path: path.clone() };
        let listener =
            BrokerListener::bind(&endpoint, BrokerListenerConfig::default()).expect("bind");
        let metadata = std::fs::metadata(&path).expect("metadata");
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "broker socket must be owner-only"
        );
        drop(listener);
        assert!(!path.exists(), "drop must remove the socket file");
    }
}
