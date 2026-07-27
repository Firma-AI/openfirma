//! Client for the out-of-sandbox secret broker.
//!
//! The shim binary runs inside the sandbox and uses [`BrokerClient`] to ask
//! the broker (running out of the sandbox, inside firma-run) to launch the
//! real CLI tool and return its stdout. [`BrokerClient`] opens a fresh
//! connection per call rather than pooling, since broker calls are
//! infrequent relative to tool launches, and applies the timeouts and buffer
//! limits from [`BrokerClientConfig`] to every operation.
//!
//! All operations are fail-closed: any connect, timeout, protocol, or
//! rejected error means the wrapped tool produced no usable output, and the
//! caller must treat the tool launch as failed rather than substituting a
//! partial or synthetic result.

use std::{io, net::TcpStream, time::Instant};

use base64::Engine as _;
use firma_http::Str;

use crate::{
    config::CommandMediatorEndpoint,
    secret_broker::{
        BrokerRequest, BrokerResponse, BrokerStream, read_bounded_line, validate_endpoint,
        write_all_bounded,
    },
};

pub mod config;
pub mod error;

use config::BrokerClientConfig;
use error::{BrokerClientError, ProtocolViolation, TransportError};

/// Client for the out-of-sandbox secret broker, bound to one
/// [`CommandMediatorEndpoint`].
///
/// Construction validates address-level invariants; transport-level checks
/// (Unix socket presence, peer credentials) run at connect time.
#[derive(Debug)]
pub struct BrokerClient {
    endpoint: CommandMediatorEndpoint,
    config: BrokerClientConfig,
}

impl BrokerClient {
    /// Build a client for `endpoint`, validating address-level invariants.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerClientError::InvalidEndpoint`] if the endpoint is not
    /// local: a TCP endpoint on any host (TCP is Windows-only for this
    /// transport) or a non-loopback TCP address on Windows, or a non-absolute
    /// Unix path.
    pub fn try_new(
        endpoint: CommandMediatorEndpoint,
        config: BrokerClientConfig,
    ) -> Result<Self, BrokerClientError> {
        validate_endpoint(&endpoint).map_err(BrokerClientError::InvalidEndpoint)?;
        Ok(Self { endpoint, config })
    }

    /// Launch one wrapped tool via the broker and return its raw stdout
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerClientError::Rejected`] when the broker reports the
    /// tool failed, [`BrokerClientError::Transport`] when the round-trip did
    /// not complete, and [`BrokerClientError::ProtocolViolation`] when the
    /// response broke the wire contract. All errors are fail-closed: the tool
    /// produced no usable output.
    pub fn run(&self, bin: &str, args: &str) -> Result<Vec<u8>, BrokerClientError> {
        let request = BrokerRequest {
            bin: Str::from(bin),
            args: Str::from(args),
        };
        self.request(&request, |response| match response {
            BrokerResponse::Ok { stdout } => base64::engine::general_purpose::STANDARD
                .decode(&*stdout)
                .map_err(|error| {
                    BrokerClientError::ProtocolViolation(ProtocolViolation::Base64(error))
                }),
            BrokerResponse::Err { error } => Err(BrokerClientError::Rejected(error.to_string())),
        })
    }

    /// Send one request and read the broker's response.
    ///
    /// # Errors
    ///
    /// See [`Self::run`].
    pub fn request<T>(
        &self,
        request: &BrokerRequest,
        exec: impl Fn(BrokerResponse) -> Result<T, BrokerClientError>,
    ) -> Result<T, BrokerClientError> {
        let payload = serde_json::to_string(request).map_err(BrokerClientError::Bug)?;
        if payload.len() > self.max_buffer_size() {
            return Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::MaxBufferSizeExceeded,
            ));
        }
        let stream = self.connect()?;
        self.send_and_receive(stream, &payload, exec)
    }

    fn connect(&self) -> Result<BrokerStream, BrokerClientError> {
        let timeout = self.config.connection_timeout;
        let stream = match &self.endpoint {
            CommandMediatorEndpoint::Tcp { addr } => {
                let stream = TcpStream::connect_timeout(addr, timeout).map_err(|error| {
                    let source = if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) {
                        TransportError::ConnectionTimeout
                    } else {
                        TransportError::Connect(error)
                    };
                    self.transport_error(source)
                })?;
                BrokerStream::Tcp(stream)
            }
            #[cfg(unix)]
            CommandMediatorEndpoint::Unix { path } => {
                let stream = connect_unix_with_timeout(path, timeout).map_err(|error| {
                    let source = if error.kind() == io::ErrorKind::TimedOut {
                        TransportError::ConnectionTimeout
                    } else {
                        TransportError::Connect(error)
                    };
                    self.transport_error(source)
                })?;
                validate_broker_peer_credentials(&stream, &self.endpoint)?;
                BrokerStream::Unix(stream)
            }
            #[cfg(not(unix))]
            CommandMediatorEndpoint::Unix { .. } => {
                return Err(BrokerClientError::InvalidEndpoint(
                    "unix broker endpoint is not supported on this platform".to_string(),
                ));
            }
        };
        Ok(stream)
    }

    fn send_and_receive<T>(
        &self,
        mut stream: BrokerStream,
        payload: &str,
        exec: impl Fn(BrokerResponse) -> Result<T, BrokerClientError>,
    ) -> Result<T, BrokerClientError> {
        let deadline = Instant::now() + self.config.operation_timeout;
        write_all_bounded(&mut stream, payload.as_bytes(), deadline)
            .map_err(|error| self.transport_error(map_io_error(error, TransportError::Write)))?;
        write_all_bounded(&mut stream, b"\n", deadline)
            .map_err(|error| self.transport_error(map_io_error(error, TransportError::Write)))?;

        // Cap the underlying reads at max_buffer_size + 1 (see
        // [`read_bounded_line`]) and reject any response whose newline-stripped
        // line exceeds the limit. Padding an over-limit response with boundary
        // whitespace must not let it pass, so the check measures the raw line,
        // not the trimmed content.
        let line = read_bounded_line(&mut stream, self.max_buffer_size() as u64, deadline)
            .map_err(|error| self.transport_error(map_io_error(error, TransportError::Read)))?;
        let line = String::from_utf8(line).map_err(|error| {
            BrokerClientError::ProtocolViolation(ProtocolViolation::InvalidUtf8(error))
        })?;
        if line.len() > self.max_buffer_size() {
            return Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::MaxBufferSizeExceeded,
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(self.transport_error(TransportError::Empty));
        }
        exec(serde_json::from_str(trimmed).map_err(|error| {
            BrokerClientError::ProtocolViolation(ProtocolViolation::Deserialize(error))
        })?)
    }

    /// Wrap a [`TransportError`] with this client's endpoint.
    fn transport_error(&self, source: TransportError) -> BrokerClientError {
        BrokerClientError::Transport {
            endpoint: self.endpoint.clone(),
            source,
        }
    }

    #[inline]
    fn max_buffer_size(&self) -> usize {
        // The only way this conversion can fail is on a 32-bit system with a
        // configured max_buffer_size larger than usize::MAX.
        usize::try_from(self.config.max_buffer_size.as_u64()).unwrap_or(usize::MAX)
    }
}

/// Classify an I/O failure from a deadline-bounded read or write as the
/// operation timeout, or wrap it in the operation-specific variant.
fn map_io_error(error: io::Error, wrap: fn(io::Error) -> TransportError) -> TransportError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        TransportError::OperationTimeout
    } else {
        wrap(error)
    }
}

/// Connect to a Unix broker socket with a deadline.
///
/// `UnixStream::connect` has no built-in timeout, so the connect runs on a
/// detached thread and this function waits on it for up to `timeout`. On
/// timeout the connect thread is left to finish and drop its result; the
/// caller only ever sees a [`io::ErrorKind::TimedOut`] error.
#[cfg(unix)]
fn connect_unix_with_timeout(
    path: &std::path::Path,
    timeout: std::time::Duration,
) -> io::Result<std::os::unix::net::UnixStream> {
    let path = path.to_owned();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(std::os::unix::net::UnixStream::connect(&path));
    });
    receiver.recv_timeout(timeout).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "secret broker unix connect timed out",
        )
    })?
}

/// Confirm the broker socket's peer belongs to the current user.
///
/// The broker returns secret material, so the client must not talk to a
/// socket planted by a different user. Matches the same-uid check the local
/// exec mediator applies on its side of the same boundary.
#[cfg(unix)]
fn validate_broker_peer_credentials(
    stream: &std::os::unix::net::UnixStream,
    endpoint: &CommandMediatorEndpoint,
) -> Result<(), BrokerClientError> {
    let actual_uid = super::peer_uid(stream).map_err(|error| BrokerClientError::Transport {
        endpoint: endpoint.clone(),
        source: TransportError::Connect(error),
    })?;
    let expected_uid = super::current_uid();
    if actual_uid != expected_uid {
        return Err(BrokerClientError::Transport {
            endpoint: endpoint.clone(),
            source: TransportError::PeerUidMismatch {
                expected_uid,
                actual_uid,
            },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::BufRead;
    use std::thread;

    use super::*;

    struct BoundBroker {
        listener: crate::secret_broker::server::BrokerListener,
        #[cfg(unix)]
        _dir: tempfile::TempDir,
        #[cfg(not(unix))]
        _dir: (),
        endpoint: CommandMediatorEndpoint,
    }

    /// Bind a listener on a fresh Unix socket in a temp dir.
    #[cfg(unix)]
    fn bind_broker() -> BoundBroker {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let endpoint = CommandMediatorEndpoint::Unix { path };
        let listener = crate::secret_broker::server::BrokerListener::bind(
            &endpoint,
            crate::secret_broker::server::config::BrokerListenerConfig::default(),
        )
        .expect("bind");
        BoundBroker {
            listener,
            _dir: dir,
            endpoint,
        }
    }

    /// Bind a listener on a fresh loopback TCP port (the Windows transport).
    #[cfg(not(unix))]
    fn bind_broker() -> BoundBroker {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid loopback addr"),
        };
        let listener = crate::secret_broker::server::BrokerListener::bind(
            &endpoint,
            crate::secret_broker::server::config::BrokerListenerConfig::default(),
        )
        .expect("bind");
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

    fn serve_ok(listener: crate::secret_broker::server::BrokerListener, stdout: Vec<u8>) {
        thread::spawn(move || {
            listener
                .accept_one(|_req| crate::secret_broker::BrokerResponse::ok(&stdout))
                .expect("accept_one");
        });
    }

    #[test]
    fn run_returns_decoded_stdout() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_broker();
        serve_ok(listener, b"secret-value".to_vec());
        let client =
            BrokerClient::try_new(endpoint, BrokerClientConfig::default()).expect("client");
        assert_eq!(
            client.run("bws", "secret get abc").expect("run"),
            b"secret-value"
        );
    }

    #[test]
    fn run_propagates_broker_rejection() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_broker();
        thread::spawn(move || {
            listener
                .accept_one(|_req| crate::secret_broker::BrokerResponse::err("tool not found"))
                .expect("accept_one");
        });
        let client =
            BrokerClient::try_new(endpoint, BrokerClientConfig::default()).expect("client");
        let error = client.run("bws", "secret get x").expect_err("rejected");
        assert!(matches!(error, BrokerClientError::Rejected(_)));
    }

    #[test]
    fn request_fails_closed_when_response_exceeds_buffer() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_broker();
        serve_ok(listener, vec![b'x'; 256]);
        let config = BrokerClientConfig {
            max_buffer_size: bytesize::ByteSize::b(64),
            ..BrokerClientConfig::default()
        };
        let client = BrokerClient::try_new(endpoint, config).expect("client");
        let error = client.request(
            &BrokerRequest {
                bin: Str::from("bws"),
                args: Str::from("secret get abc"),
            },
            |_| Ok(()),
        );
        assert!(matches!(
            error,
            Err(BrokerClientError::ProtocolViolation(
                ProtocolViolation::MaxBufferSizeExceeded
            ))
        ));
    }

    #[test]
    fn request_accepts_response_exactly_at_buffer_limit() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_broker();
        // A response whose encoded JSON line is exactly `max_buffer_size`
        // bytes must be accepted (the trailing newline must not count against
        // the limit). Sizing the limit from the real serialized payload keeps
        // the boundary exact.
        let stdout = vec![b'x'; 42];
        let response_payload =
            serde_json::to_vec(&crate::secret_broker::BrokerResponse::ok(&stdout))
                .expect("serialize");
        let config = BrokerClientConfig {
            max_buffer_size: bytesize::ByteSize::b(response_payload.len() as u64),
            ..BrokerClientConfig::default()
        };
        serve_ok(listener, stdout.clone());
        let client = BrokerClient::try_new(endpoint, config).expect("client");
        let response = client.request(
            &BrokerRequest {
                bin: Str::from("bws"),
                args: Str::from("secret get abc"),
            },
            |response| response.into_stdout().map_err(BrokerClientError::Rejected),
        );
        assert_eq!(response.expect("response"), stdout);
    }

    /// Bind a bare listener that answers the first connection with `padded`
    /// raw bytes, bypassing [`BrokerListener`] so the test can send a response
    /// line that no serializer would produce (e.g. whitespace-padded).
    #[cfg(unix)]
    fn bind_raw_responder(padded: Vec<u8>) -> (CommandMediatorEndpoint, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut reader = std::io::BufReader::new(&mut conn);
            let mut request = Vec::new();
            let _ = reader.read_until(b'\n', &mut request);
            drop(reader);
            std::io::Write::write_all(&mut conn, &padded).expect("write");
        });
        (CommandMediatorEndpoint::Unix { path }, dir)
    }

    /// Windows twin of [`bind_raw_responder`], using the TCP transport.
    #[cfg(not(unix))]
    fn bind_raw_responder(padded: Vec<u8>) -> (CommandMediatorEndpoint, ()) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut reader = std::io::BufReader::new(&mut conn);
            let mut request = Vec::new();
            let _ = reader.read_until(b'\n', &mut request);
            drop(reader);
            std::io::Write::write_all(&mut conn, &padded).expect("write");
        });
        (CommandMediatorEndpoint::Tcp { addr }, ())
    }

    #[test]
    fn request_rejects_over_limit_line_padded_with_whitespace() {
        let stdout = b"secret-value".to_vec();
        let response_payload =
            serde_json::to_vec(&crate::secret_broker::BrokerResponse::ok(&stdout))
                .expect("serialize");
        // The broker pads the response line with a trailing space, so the raw
        // line is one byte over `max_buffer_size` even though the trimmed
        // content is not. The size check must measure the line, not the
        // trimmed content.
        let mut padded = response_payload.clone();
        padded.push(b' ');
        padded.push(b'\n');
        let (endpoint, _guard) = bind_raw_responder(padded);
        let config = BrokerClientConfig {
            max_buffer_size: bytesize::ByteSize::b(response_payload.len() as u64),
            ..BrokerClientConfig::default()
        };
        let client = BrokerClient::try_new(endpoint, config).expect("client");
        let error = client.request(
            &BrokerRequest {
                bin: Str::from("bws"),
                args: Str::from("secret get abc"),
            },
            |_| Ok(()),
        );
        assert!(
            matches!(
                error,
                Err(BrokerClientError::ProtocolViolation(
                    ProtocolViolation::MaxBufferSizeExceeded
                ))
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn request_fails_closed_when_operation_times_out() {
        let BoundBroker {
            listener,
            endpoint,
            _dir,
        } = bind_broker();
        let server = thread::spawn(move || {
            let result = listener.accept_one(|_req| {
                // Stall longer than the client's operation_timeout so the
                // response never arrives within the deadline.
                std::thread::sleep(std::time::Duration::from_millis(500));
                crate::secret_broker::BrokerResponse::err("too late")
            });
            // The client is gone by the time the response is written, so the
            // write fails with a broken pipe; that is the expected outcome.
            let _ = result;
        });
        let config = BrokerClientConfig {
            operation_timeout: std::time::Duration::from_millis(100),
            ..BrokerClientConfig::default()
        };
        let client = BrokerClient::try_new(endpoint, config).expect("client");
        let error = client.request(
            &BrokerRequest {
                bin: Str::from("bws"),
                args: Str::from("secret get abc"),
            },
            |_| Ok(()),
        );
        assert!(matches!(
            error,
            Err(BrokerClientError::Transport {
                source: TransportError::OperationTimeout,
                ..
            })
        ));
        server.join().expect("server thread");
    }

    #[test]
    fn try_new_rejects_invalid_tcp_endpoint() {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "8.8.8.8:53".parse().expect("valid addr"),
        };
        let error = BrokerClient::try_new(endpoint, BrokerClientConfig::default());
        assert!(matches!(error, Err(BrokerClientError::InvalidEndpoint(_))));
    }

    #[cfg(unix)]
    #[test]
    fn try_new_rejects_tcp_on_unix() {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:9000".parse().expect("valid addr"),
        };
        let error = BrokerClient::try_new(endpoint, BrokerClientConfig::default());
        assert!(matches!(error, Err(BrokerClientError::InvalidEndpoint(_))));
    }

    #[test]
    fn try_new_rejects_relative_unix_path() {
        let endpoint = CommandMediatorEndpoint::Unix {
            path: std::path::PathBuf::from("relative/broker.sock"),
        };
        let error = BrokerClient::try_new(endpoint, BrokerClientConfig::default());
        assert!(matches!(error, Err(BrokerClientError::InvalidEndpoint(_))));
    }

    #[cfg(unix)]
    #[test]
    fn request_fails_fast_when_broker_is_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = CommandMediatorEndpoint::Unix {
            path: dir.path().join("missing-broker.sock"),
        };
        let client =
            BrokerClient::try_new(endpoint, BrokerClientConfig::default()).expect("client");
        let error = client.request(
            &BrokerRequest {
                bin: Str::from("bws"),
                args: Str::from("secret get abc"),
            },
            |_| Ok(()),
        );
        assert!(matches!(error, Err(BrokerClientError::Transport { .. })));
    }

    #[cfg(not(unix))]
    #[test]
    fn request_fails_fast_when_broker_is_unreachable() {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:1".parse().expect("valid addr"),
        };
        let client =
            BrokerClient::try_new(endpoint, BrokerClientConfig::default()).expect("client");
        let error = client.request(
            &BrokerRequest {
                bin: Str::from("bws"),
                args: Str::from("secret get abc"),
            },
            |_| Ok(()),
        );
        assert!(matches!(error, Err(BrokerClientError::Transport { .. })));
    }
}
