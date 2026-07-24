//! In-sandbox shim: send a tool-launch request to the out-of-sandbox broker.
//!
//! The shim shadows a configured executable inside the sandbox. When invoked, it
//! sends a JSON request to the broker over the transport named by
//! `FIRMA_BROKER_ADDR`, receives the broker's base64-encoded stdout, and writes
//! that output to its own stdout. The shim holds no plaintext: all vault I/O
//! happens out of the sandbox in the broker.
//!
//! Protocol (one round-trip per connection):
//!
//! ```text
//! shim  →  {"bin":"bws","args":"secret get abc"}\n
//! broker → {"stdout":"<base64>"}\n
//! ```

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;

use super::broker::{BrokerRequest, BrokerResponse};

/// Env var carrying the broker's transport address into the sandbox.
///
/// Supported schemes:
/// - `tcp:<addr>` — TCP loopback socket (all platforms)
/// - `unix:<path>` — Unix domain socket (Unix only)
pub const FIRMA_BROKER_ADDR: &str = "FIRMA_BROKER_ADDR";

/// Connect to `addr`, send `request`, and return the decoded response.
///
/// # Errors
///
/// Returns an error if the address scheme is unsupported, the connection fails,
/// or the response cannot be decoded.
pub fn call_broker(addr: &str, request: &BrokerRequest) -> io::Result<BrokerResponse> {
    let payload = serde_json::to_string(request)
        .map_err(|e| io::Error::other(format!("failed to serialize broker request: {e}")))?;

    if let Some(rest) = addr.strip_prefix("tcp:") {
        return call_tcp(rest, &payload);
    }

    #[cfg(unix)]
    if let Some(path) = addr.strip_prefix("unix:") {
        return call_unix(std::path::Path::new(path), &payload);
    }

    Err(io::Error::other(format!(
        "unsupported broker address scheme: {addr}"
    )))
}

fn call_tcp(addr: &str, payload: &str) -> io::Result<BrokerResponse> {
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| io::Error::other(format!("broker unavailable (tcp:{addr}): {e}")))?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    read_response(BufReader::new(stream))
}

#[cfg(unix)]
fn call_unix(path: &std::path::Path, payload: &str) -> io::Result<BrokerResponse> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path).map_err(|e| {
        io::Error::other(format!("broker unavailable (unix:{}): {e}", path.display()))
    })?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    read_response(BufReader::new(stream))
}

fn read_response(mut reader: impl BufRead) -> io::Result<BrokerResponse> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(io::Error::other("broker returned empty response"));
    }
    serde_json::from_str(trimmed)
        .map_err(|e| io::Error::other(format!("failed to decode broker response: {e}")))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;

    use super::*;

    fn serve_once_tcp(response: BrokerResponse) -> (thread::JoinHandle<()>, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let payload = serde_json::to_string(&response).expect("serialize");
                let _ = stream.write_all(payload.as_bytes());
                let _ = stream.write_all(b"\n");
            }
        });
        (handle, addr)
    }

    #[test]
    fn call_broker_tcp_returns_decoded_stdout() {
        let (server, addr) = serve_once_tcp(BrokerResponse::ok(b"secret-value"));
        let request = BrokerRequest {
            bin: "bws".to_string(),
            args: "secret get abc".to_string(),
        };
        let response = call_broker(&format!("tcp:{addr}"), &request).expect("call_broker");
        server.join().expect("server thread");
        assert_eq!(response.into_stdout().expect("ok"), b"secret-value");
    }

    #[test]
    fn unsupported_scheme_returns_error() {
        let request = BrokerRequest {
            bin: String::from("bws"),
            args: String::new(),
        };
        let err = call_broker("vsock://3:1234", &request).expect_err("unsupported");
        assert!(
            err.to_string()
                .contains("unsupported broker address scheme")
        );
    }

    #[test]
    fn unreachable_tcp_returns_error() {
        let request = BrokerRequest {
            bin: String::from("bws"),
            args: String::new(),
        };
        let err = call_broker("tcp:127.0.0.1:1", &request).expect_err("unreachable");
        assert!(err.to_string().contains("broker unavailable"));
    }
}
