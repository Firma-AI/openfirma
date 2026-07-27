//! Out-of-sandbox broker transport for the secret shim.
//!
//! The shim binary connects to the broker over a Unix domain socket (Unix) or
//! TCP loopback (Windows) and sends a newline-terminated JSON request. The
//! broker runs the real CLI out of the sandbox, intercepts the output, and
//! writes back a newline-terminated JSON response containing the base64-encoded
//! stdout.
//!
//! Protocol (one round-trip per connection):
//!
//! ```text
//! shim  →  {"bin":"bws","args":"secret get abc"}\n
//! broker → {"stdout":"<base64>"}\n        (on success)
//! broker → {"error":"<reason>"}\n         (on failure — shim exits non-zero)
//! ```

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;

#[cfg(unix)]
use std::{os::unix::net::UnixListener, path::PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::config::CommandMediatorEndpoint;

/// Maximum request line length from the shim, in bytes.
const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Shim → broker request: describes one tool launch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BrokerRequest {
    /// Executable basename of the wrapped tool (e.g. `"bws"`).
    pub bin: String,
    /// Space-joined arguments (everything after the binary name).
    pub args: String,
}

/// Broker → shim response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BrokerResponse {
    Ok {
        /// Base64-encoded stdout bytes from the real tool.
        stdout: String,
    },
    Err {
        error: String,
    },
}

impl BrokerResponse {
    /// Build a success response from raw stdout bytes.
    #[must_use]
    pub fn ok(stdout: &[u8]) -> Self {
        Self::Ok {
            stdout: base64::engine::general_purpose::STANDARD.encode(stdout),
        }
    }

    /// Build an error response.
    #[must_use]
    pub fn err(reason: impl Into<String>) -> Self {
        Self::Err {
            error: reason.into(),
        }
    }

    /// Decode the stdout bytes from a success response.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is an error response or the base64 is
    /// malformed.
    pub fn into_stdout(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Ok { stdout } => base64::engine::general_purpose::STANDARD
                .decode(stdout)
                .map_err(|e| format!("broker response base64 decode failed: {e}")),
            Self::Err { error } => Err(error),
        }
    }
}

enum BrokerListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener, PathBuf),
}

/// Broker-side listener: accepts shim connections and dispatches requests.
pub struct BrokerListener {
    inner: BrokerListenerInner,
}

impl BrokerListener {
    /// Bind a listener at `endpoint`.
    ///
    /// For Unix endpoints, any stale socket file is removed before binding.
    /// For TCP endpoints with port `0`, the OS assigns a free port; retrieve
    /// it with [`bound_endpoint`][Self::bound_endpoint].
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if binding fails.
    pub fn bind(endpoint: &CommandMediatorEndpoint) -> io::Result<Self> {
        match endpoint {
            CommandMediatorEndpoint::Tcp { addr } => {
                let listener = TcpListener::bind(addr)?;
                Ok(Self {
                    inner: BrokerListenerInner::Tcp(listener),
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
                Ok(Self {
                    inner: BrokerListenerInner::Unix(listener, path.clone()),
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
    pub fn bound_endpoint(&self) -> io::Result<CommandMediatorEndpoint> {
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
    /// # Errors
    ///
    /// Returns an I/O error if accepting, reading, or writing fails. Handler
    /// errors are serialized and written as `{"error":"..."}` responses rather
    /// than returned here.
    pub fn accept_one<F>(&self, handler: F) -> io::Result<()>
    where
        F: FnOnce(BrokerRequest) -> BrokerResponse,
    {
        match &self.inner {
            BrokerListenerInner::Tcp(listener) => {
                let (stream, _) = listener.accept()?;
                handle_connection(BufReader::new(stream.try_clone()?), stream, handler)
            }
            #[cfg(unix)]
            BrokerListenerInner::Unix(listener, _) => {
                let (stream, _) = listener.accept()?;
                handle_connection(BufReader::new(stream.try_clone()?), stream, handler)
            }
        }
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

fn handle_connection<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    handler: impl FnOnce(BrokerRequest) -> BrokerResponse,
) -> io::Result<()> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.len() > MAX_REQUEST_BYTES {
        let response = BrokerResponse::err("request too large");
        return write_response(&mut writer, &response);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(io::Error::other("empty broker request"));
    }
    let response = match serde_json::from_str::<BrokerRequest>(trimmed) {
        Ok(request) => handler(request),
        Err(e) => BrokerResponse::err(format!("malformed broker request: {e}")),
    };
    write_response(&mut writer, &response)
}

fn write_response(writer: &mut impl Write, response: &BrokerResponse) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("failed to serialize broker response: {e}")))?;
    payload.push(b'\n');
    writer.write_all(&payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::thread;

    use super::*;

    fn bind_tcp() -> (BrokerListener, SocketAddr) {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid loopback addr"),
        };
        let listener = BrokerListener::bind(&endpoint).expect("bind");
        let CommandMediatorEndpoint::Tcp { addr } =
            listener.bound_endpoint().expect("bound_endpoint")
        else {
            panic!("TCP listener must return TCP endpoint");
        };
        (listener, addr)
    }

    fn connect_and_send(addr: SocketAddr, request: &BrokerRequest) -> BrokerResponse {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let payload = serde_json::to_string(request).expect("serialize");
        stream
            .write_all(format!("{payload}\n").as_bytes())
            .expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        serde_json::from_str(line.trim()).expect("deserialize response")
    }

    #[test]
    fn roundtrip_ok_response() {
        let (listener, addr) = bind_tcp();
        let request = BrokerRequest {
            bin: "bws".to_string(),
            args: "secret get abc".to_string(),
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
        let response = connect_and_send(addr, &request);
        server.join().expect("server thread");
        assert_eq!(
            response.into_stdout().expect("ok response"),
            b"secret-value"
        );
    }

    #[test]
    fn handler_error_written_as_error_response() {
        let (listener, addr) = bind_tcp();
        let request = BrokerRequest {
            bin: "bws".to_string(),
            args: "secret get x".to_string(),
        };
        let server = thread::spawn(move || {
            listener
                .accept_one(|_req| BrokerResponse::err("tool not found"))
                .expect("accept_one");
        });
        let response = connect_and_send(addr, &request);
        server.join().expect("server thread");
        assert!(response.into_stdout().is_err());
    }

    #[test]
    fn bound_endpoint_returns_assigned_tcp_port() {
        let (_listener, addr) = bind_tcp();
        assert_ne!(addr.port(), 0, "OS must assign a non-zero port");
    }
}
