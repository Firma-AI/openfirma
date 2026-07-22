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
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::broker::{BrokerRequest, BrokerResponse};

/// Env var carrying the broker's transport address into the sandbox.
///
/// Supported schemes:
/// - `unix:<path>` — Unix domain socket (Linux bwrap)
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

    if let Some(path) = addr.strip_prefix("unix:") {
        return call_unix(Path::new(path), &payload);
    }

    Err(io::Error::other(format!(
        "unsupported broker address scheme: {addr}"
    )))
}

fn call_unix(path: &Path, payload: &str) -> io::Result<BrokerResponse> {
    let mut stream = UnixStream::connect(path).map_err(|e| {
        io::Error::other(format!("broker unavailable (unix:{}): {e}", path.display()))
    })?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
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
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;

    fn serve_once(path: &Path, response: BrokerResponse) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).expect("bind");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let payload = serde_json::to_string(&response).expect("serialize");
                let _ = stream.write_all(payload.as_bytes());
                let _ = stream.write_all(b"\n");
            }
        })
    }

    #[test]
    fn call_broker_returns_decoded_stdout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let server = serve_once(&path, BrokerResponse::ok(b"secret-value"));

        let addr = format!("unix:{}", path.display());
        let request = BrokerRequest {
            bin: "bws".to_string(),
            args: "secret get abc".to_string(),
        };
        let response = call_broker(&addr, &request).expect("call_broker");
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
    fn unreachable_socket_returns_error() {
        let request = BrokerRequest {
            bin: String::from("bws"),
            args: String::new(),
        };
        let err = call_broker("unix:/nonexistent/broker.sock", &request).expect_err("unreachable");
        assert!(err.to_string().contains("broker unavailable"));
    }
}
